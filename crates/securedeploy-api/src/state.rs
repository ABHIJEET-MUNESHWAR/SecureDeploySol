//! Shared application state wiring the concrete audit engine, event bus, and a
//! request rate limiter for the GraphQL API.

use std::sync::Arc;

use securedeploy_core::engine::{AuditEngine, SystemUnixClock};
use securedeploy_infra::{BroadcastEventSink, InMemoryFindingStore, InMemoryProposalStore};
use securedeploy_resilience::RateLimiter;

/// The concrete engine used by the GraphQL API.
pub type ConcreteEngine =
    AuditEngine<InMemoryProposalStore, InMemoryFindingStore, BroadcastEventSink, SystemUnixClock>;

/// Immutable, cloneable application state shared across GraphQL resolvers.
#[derive(Clone)]
pub struct ServiceState {
    /// The audit engine.
    pub engine: Arc<ConcreteEngine>,
    /// Event bus for subscriptions.
    pub events: Arc<BroadcastEventSink>,
    /// Per-request rate limiter guarding mutations.
    pub rate_limiter: Arc<RateLimiter>,
}

impl ServiceState {
    /// Assembles the shared state from its already-constructed components.
    #[must_use]
    pub fn new(
        engine: Arc<ConcreteEngine>,
        events: Arc<BroadcastEventSink>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            engine,
            events,
            rate_limiter,
        }
    }
}
