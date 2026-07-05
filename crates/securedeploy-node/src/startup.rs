//! Startup wiring: construct the engine, its adapters, and the HTTP router.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use metrics_exporter_prometheus::PrometheusHandle;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use securedeploy_api::{build_schema, router as graphql_router, ConcreteEngine, ServiceState};
use securedeploy_core::domain::GovernanceConfig;
use securedeploy_core::engine::{AuditEngine, SystemUnixClock};
use securedeploy_infra::{BroadcastEventSink, InMemoryFindingStore, InMemoryProposalStore};
use securedeploy_resilience::RateLimiter;

use crate::config::{GovernanceArgs, ServeArgs};

/// Assembles the shared [`ServiceState`] from configuration.
///
/// # Errors
/// Fails if the guardian configuration is invalid.
pub fn build_state(gov: &GovernanceArgs, rate_limit_rps: u32) -> anyhow::Result<ServiceState> {
    let proposals = Arc::new(InMemoryProposalStore::default());
    let findings = Arc::new(InMemoryFindingStore::default());
    let events = Arc::new(BroadcastEventSink::new(1024));
    let config = GovernanceConfig::new(
        gov.authority.clone(),
        gov.guardians.clone(),
        gov.threshold,
        gov.timelock_seconds,
    );

    let engine: Arc<ConcreteEngine> = Arc::new(
        AuditEngine::new(
            proposals,
            findings,
            events.clone(),
            Arc::new(SystemUnixClock),
            config,
        )
        .context("building audit engine")?,
    );

    let rate_limiter = Arc::new(RateLimiter::per_second(rate_limit_rps.max(1)));
    Ok(ServiceState::new(engine, events, rate_limiter))
}

/// Builds the full HTTP router: GraphQL, playground, subscriptions, `/metrics`,
/// `/health`, plus timeout and tracing middleware.
pub fn build_router(state: ServiceState, metrics: PrometheusHandle) -> Router {
    let schema = build_schema(state);
    graphql_router(schema)
        .route("/health", get(|| async { "ok" }))
        .route("/metrics", get(move || async move { metrics.render() }))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(TraceLayer::new_for_http())
}

/// Runs the GraphQL server until shutdown.
///
/// # Errors
/// Fails if the recorder cannot be installed or the socket cannot be bound.
pub async fn serve(gov: &GovernanceArgs, args: &ServeArgs) -> anyhow::Result<()> {
    let metrics = crate::telemetry::init_metrics()?;
    let state = build_state(gov, args.rate_limit_rps)?;
    let app = build_router(state, metrics);

    let listener = tokio::net::TcpListener::bind(&args.bind_addr)
        .await
        .with_context(|| format!("binding {}", args.bind_addr))?;
    info!(addr = %args.bind_addr, "securedeploy-node listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutdown signal received");
}
