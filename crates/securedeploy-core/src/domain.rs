use securedeploy_types::{ProgramId, ProposalId, ProposalStatus, Severity, ThreatClass};
use serde::{Deserialize, Serialize};

/// Off-chain mirror of an on-chain upgrade proposal, enriched with indexing
/// metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalRecord {
    pub id: ProposalId,
    pub program_id: ProgramId,
    /// Hex-encoded sha256 build hash pinned on-chain.
    pub build_hash: String,
    pub proposer: String,
    pub eta: i64,
    pub approvals: u8,
    pub threshold: u8,
    pub status: ProposalStatus,
    pub created_at: i64,
}

/// A security finding raised against a program or proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRecord {
    pub id: String,
    pub program_id: ProgramId,
    pub threat: ThreatClass,
    pub severity: Severity,
    pub title: String,
    pub resolved: bool,
    pub created_at: i64,
}

/// The governance configuration this service enforces, mirroring on-chain state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceConfig {
    pub authority: String,
    pub guardians: Vec<String>,
    pub threshold: u8,
    pub timelock_seconds: i64,
    pub paused: bool,
    pub proposal_count: u64,
}

impl GovernanceConfig {
    #[must_use]
    pub fn new(
        authority: String,
        guardians: Vec<String>,
        threshold: u8,
        timelock_seconds: i64,
    ) -> Self {
        Self {
            authority,
            guardians,
            threshold,
            timelock_seconds,
            paused: false,
            proposal_count: 0,
        }
    }

    #[must_use]
    pub fn is_guardian(&self, key: &str) -> bool {
        self.guardians.iter().any(|g| g == key)
    }
}

/// Domain events published as the audit state changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainEvent {
    ProposalCreated { id: u64, program_id: String },
    ProposalApproved { id: u64, approvals: u8 },
    ProposalExecuted { id: u64 },
    ProposalCancelled { id: u64 },
    FindingRaised { id: String, severity: Severity },
    PauseChanged { paused: bool },
}
