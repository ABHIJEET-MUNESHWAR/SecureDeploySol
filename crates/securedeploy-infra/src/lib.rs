//! Infrastructure adapters for the deployment-security service.
#![forbid(unsafe_code)]

pub mod events;
pub mod memory;

pub use events::BroadcastEventSink;
pub use memory::{InMemoryFindingStore, InMemoryProposalStore};

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "postgres")]
pub use postgres::PgProposalStore;
