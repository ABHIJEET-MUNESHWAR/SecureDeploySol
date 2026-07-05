use thiserror::Error;

/// Domain error type for the deployment-security service.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum SecureError {
    #[error("governance is paused")]
    Paused,
    #[error("guardian set must not be empty")]
    EmptyGuardianSet,
    #[error("guardian set exceeds maximum of {max}")]
    TooManyGuardians { max: usize },
    #[error("duplicate guardian in set")]
    DuplicateGuardian,
    #[error("threshold {threshold} must be in 1..={len}")]
    InvalidThreshold { threshold: u8, len: usize },
    #[error("timelock has not elapsed: {remaining}s remaining")]
    TimelockActive { remaining: i64 },
    #[error("approval threshold not met: {approvals}/{threshold}")]
    ThresholdNotMet { approvals: u8, threshold: u8 },
    #[error("proposal already finalized")]
    AlreadyFinalized,
    #[error("guardian already approved this proposal")]
    DuplicateApproval,
    #[error("not a registered guardian")]
    NotGuardian,
    #[error("build hash must be non-zero")]
    EmptyBuildHash,
    #[error("invalid hex length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("arithmetic overflow")]
    Overflow,
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, SecureError>;
