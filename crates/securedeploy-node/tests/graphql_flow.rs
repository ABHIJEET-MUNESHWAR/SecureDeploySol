//! End-to-end GraphQL flow tests over the assembled schema.

use std::sync::Arc;

use async_graphql::{Request, Variables};
use securedeploy_api::{build_schema, ServiceState};
use securedeploy_core::domain::GovernanceConfig;
use securedeploy_core::engine::{AuditEngine, SystemUnixClock};
use securedeploy_infra::{BroadcastEventSink, InMemoryFindingStore, InMemoryProposalStore};
use securedeploy_resilience::RateLimiter;
use securedeploy_types::BuildHash;

fn schema() -> async_graphql::Schema<
    securedeploy_api::schema::QueryRoot,
    securedeploy_api::schema::MutationRoot,
    securedeploy_api::schema::SubscriptionRoot,
> {
    let events = Arc::new(BroadcastEventSink::new(64));
    let config = GovernanceConfig::new(
        "authority".into(),
        vec!["g1".into(), "g2".into(), "g3".into()],
        2,
        0,
    );
    let engine = Arc::new(
        AuditEngine::new(
            Arc::new(InMemoryProposalStore::default()),
            Arc::new(InMemoryFindingStore::default()),
            events.clone(),
            Arc::new(SystemUnixClock),
            config,
        )
        .unwrap(),
    );
    let state = ServiceState::new(engine, events, Arc::new(RateLimiter::per_second(1000)));
    build_schema(state)
}

#[tokio::test]
async fn propose_approve_execute_flow() {
    let schema = schema();
    let hash = BuildHash::of(b"artifact").to_hex();

    let propose = format!(
        r#"mutation {{ proposeUpgrade(input: {{ programId: "P1", buildHash: "{hash}", proposer: "g1" }}) {{ id status }} }}"#
    );
    let res = schema.execute(Request::new(propose)).await;
    assert!(res.errors.is_empty(), "{:?}", res.errors);

    // First approval — below threshold.
    let r1 = schema
        .execute(Request::new(
            r#"mutation { approveUpgrade(id: 0, guardian: "g1") { approvals status } }"#,
        ))
        .await;
    assert!(r1.errors.is_empty(), "{:?}", r1.errors);

    // Second approval — reaches threshold.
    let r2 = schema
        .execute(Request::new(
            r#"mutation { approveUpgrade(id: 0, guardian: "g2") { approvals status } }"#,
        ))
        .await;
    assert!(r2.errors.is_empty(), "{:?}", r2.errors);

    // Execute (timelock is zero).
    let exec = schema
        .execute(Request::new(
            r#"mutation { executeUpgrade(id: 0) { status } }"#,
        ))
        .await;
    assert!(exec.errors.is_empty(), "{:?}", exec.errors);
}

#[tokio::test]
async fn duplicate_guardian_approval_rejected() {
    let schema = schema();
    let hash = BuildHash::of(b"artifact").to_hex();
    let propose = format!(
        r#"mutation {{ proposeUpgrade(input: {{ programId: "P1", buildHash: "{hash}", proposer: "authority" }}) {{ id }} }}"#
    );
    schema.execute(Request::new(propose)).await;
    schema
        .execute(Request::new(
            r#"mutation { approveUpgrade(id: 0, guardian: "g1") { approvals } }"#,
        ))
        .await;
    let dup = schema
        .execute(Request::new(
            r#"mutation { approveUpgrade(id: 0, guardian: "g1") { approvals } }"#,
        ))
        .await;
    assert!(!dup.errors.is_empty());
}

#[tokio::test]
async fn finding_and_config_queries() {
    let schema = schema();
    let raise = r#"mutation { raiseFinding(input: { id: "F1", programId: "P1", threat: MISSING_SIGNER_CHECK, severity: HIGH, title: "no signer" }) { threatCode severity } }"#;
    let r = schema.execute(Request::new(raise)).await;
    assert!(r.errors.is_empty(), "{:?}", r.errors);

    let cfg = schema
        .execute(Request::new(
            r#"query { config { threshold paused proposalCount } stats { findings openFindings } }"#,
        ))
        .await;
    assert!(cfg.errors.is_empty(), "{:?}", cfg.errors);
}

#[tokio::test]
async fn variables_parse() {
    // Ensure the schema accepts a variables document (smoke test).
    let schema = schema();
    let res = schema
        .execute(Request::new("query { health }").variables(Variables::default()))
        .await;
    assert!(res.errors.is_empty());
}
