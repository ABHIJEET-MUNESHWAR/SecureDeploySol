//! Domain core: records, ports, and the generic `AuditEngine`.
#![forbid(unsafe_code)]

pub mod domain;
pub mod engine;
pub mod error;
pub mod ports;

pub use domain::{DomainEvent, FindingRecord, GovernanceConfig, ProposalRecord};
pub use engine::{AuditEngine, EngineStats, SystemUnixClock, UnixClock};
pub use error::{EngineError, Result};
pub use ports::{EventSink, FindingStore, ProposalStore};
