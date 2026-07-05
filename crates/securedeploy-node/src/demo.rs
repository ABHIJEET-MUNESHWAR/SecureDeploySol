//! Self-contained demo of the audit / governance flow (no network required).

use std::sync::Arc;

use securedeploy_core::domain::GovernanceConfig;
use securedeploy_core::engine::{AuditEngine, SystemUnixClock};
use securedeploy_infra::{BroadcastEventSink, InMemoryFindingStore, InMemoryProposalStore};
use securedeploy_types::{BuildHash, ProgramId, Severity, ThreatClass};
use tracing::info;

use crate::config::GovernanceArgs;

/// Runs a propose → approve → (finding) demo and prints the resulting state.
///
/// # Errors
/// Fails if the guardian configuration is invalid.
pub async fn run(gov: &GovernanceArgs) -> anyhow::Result<()> {
    // Use a zero timelock for the demo so execution is immediate.
    let config = GovernanceConfig::new(
        gov.authority.clone(),
        gov.guardians.clone(),
        gov.threshold,
        0,
    );
    let engine = AuditEngine::new(
        Arc::new(InMemoryProposalStore::default()),
        Arc::new(InMemoryFindingStore::default()),
        Arc::new(BroadcastEventSink::new(64)),
        Arc::new(SystemUnixClock),
        config,
    )?;

    let hash = BuildHash::of(b"program-v2.so").to_hex();
    let proposal = engine
        .propose(
            ProgramId("Prog1111111111111111111111111111111111111".into()),
            &hash,
            gov.authority.clone(),
        )
        .await?;
    info!(id = proposal.id.0, build_hash = %proposal.build_hash, "proposed upgrade");

    for g in gov.guardians.iter().take(gov.threshold as usize) {
        let r = engine.approve(proposal.id.0, g.clone()).await?;
        info!(approvals = r.approvals, "guardian approved");
    }

    let executed = engine.execute(proposal.id.0).await?;
    info!(status = ?executed.status, "proposal executed");

    engine
        .raise_finding(
            "F-DEMO-1".into(),
            ProgramId("Prog1111111111111111111111111111111111111".into()),
            ThreatClass::IntegerOverflow,
            Severity::Medium,
            "unchecked add in reward calc".into(),
        )
        .await?;

    let stats = engine.stats().await?;
    println!(
        "demo complete: proposals={} executed={} findings={} open_findings={}",
        stats.proposals, stats.executed, stats.findings, stats.open_findings
    );
    Ok(())
}
