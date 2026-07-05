use async_trait::async_trait;

use crate::domain::{DomainEvent, FindingRecord, ProposalRecord};
use crate::error::Result;

/// Persistence port for upgrade proposals.
#[async_trait]
pub trait ProposalStore: Send + Sync {
    async fn upsert(&self, record: ProposalRecord) -> Result<()>;
    async fn get(&self, id: u64) -> Result<Option<ProposalRecord>>;
    async fn list(&self) -> Result<Vec<ProposalRecord>>;
    async fn count(&self) -> Result<u64>;
}

/// Persistence port for security findings.
#[async_trait]
pub trait FindingStore: Send + Sync {
    async fn insert(&self, record: FindingRecord) -> Result<()>;
    async fn get(&self, id: &str) -> Result<Option<FindingRecord>>;
    async fn list(&self) -> Result<Vec<FindingRecord>>;
}

/// Fan-out port for domain events.
#[async_trait]
pub trait EventSink: Send + Sync {
    async fn publish(&self, event: DomainEvent) -> Result<()>;
}
