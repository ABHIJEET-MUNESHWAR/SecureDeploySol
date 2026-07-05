//! Pure domain types for the deployment-security service.
#![forbid(unsafe_code)]

pub mod build_hash;
pub mod error;
pub mod governance;

pub use build_hash::BuildHash;
pub use error::{Result, SecureError};
pub use governance::{can_execute, compute_eta, validate_guardians, MAX_GUARDIANS};

use serde::{Deserialize, Serialize};

/// Newtype for a Solana program id (base58 string form kept opaque here).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProgramId(pub String);

impl ProgramId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Monotonic proposal id, mirroring the on-chain `proposal_count`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProposalId(pub u64);

impl ProposalId {
    /// Next id, guarding against overflow.
    #[must_use]
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

/// Lifecycle state of an upgrade proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProposalStatus {
    #[default]
    Pending,
    Approved,
    Executed,
    Cancelled,
}

/// Severity of a security finding (ordered).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Taxonomy of the Solana attack classes this service tracks. The on-chain
/// program is hardened against each of these; findings reference them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatClass {
    MissingSignerCheck,
    MissingOwnerCheck,
    AccountConfusion,
    ArbitraryCpi,
    PdaSeedCollision,
    IntegerOverflow,
    Reinitialization,
    TypeCosplay,
    UpgradeAuthorityAbuse,
    UnboundedAccount,
}

impl ThreatClass {
    /// Stable machine-readable code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::MissingSignerCheck => "SVM-01-signer",
            Self::MissingOwnerCheck => "SVM-02-owner",
            Self::AccountConfusion => "SVM-03-confusion",
            Self::ArbitraryCpi => "SVM-04-cpi",
            Self::PdaSeedCollision => "SVM-05-pda",
            Self::IntegerOverflow => "SVM-06-overflow",
            Self::Reinitialization => "SVM-07-reinit",
            Self::TypeCosplay => "SVM-08-cosplay",
            Self::UpgradeAuthorityAbuse => "SVM-09-upgrade",
            Self::UnboundedAccount => "SVM-10-unbounded",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_id_next() {
        assert_eq!(ProposalId(1).next(), Some(ProposalId(2)));
        assert_eq!(ProposalId(u64::MAX).next(), None);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Info < Severity::Low);
    }

    #[test]
    fn threat_codes_unique() {
        let all = [
            ThreatClass::MissingSignerCheck,
            ThreatClass::MissingOwnerCheck,
            ThreatClass::AccountConfusion,
            ThreatClass::ArbitraryCpi,
            ThreatClass::PdaSeedCollision,
            ThreatClass::IntegerOverflow,
            ThreatClass::Reinitialization,
            ThreatClass::TypeCosplay,
            ThreatClass::UpgradeAuthorityAbuse,
            ThreatClass::UnboundedAccount,
        ];
        let mut codes: Vec<_> = all.iter().map(|t| t.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }

    #[test]
    fn status_default_is_pending() {
        assert_eq!(ProposalStatus::default(), ProposalStatus::Pending);
    }
}
