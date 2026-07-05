use anchor_lang::prelude::*;

/// Program-level error codes.
///
/// Each variant maps to a specific *hardening* invariant. Returning a typed
/// error (never `panic!`/`unwrap`) keeps failing transactions cheap and
/// auditable.
#[error_code]
pub enum SecureError {
    #[msg("The governance is paused")]
    Paused,
    #[msg("Signer is not the governance authority")]
    Unauthorized,
    #[msg("Signer is not a registered guardian")]
    NotGuardian,
    #[msg("No pending authority to accept")]
    NoPendingAuthority,
    #[msg("Signer is not the pending authority")]
    NotPendingAuthority,
    #[msg("Guardian set must not be empty")]
    EmptyGuardianSet,
    #[msg("Guardian set exceeds the maximum")]
    TooManyGuardians,
    #[msg("Duplicate guardian in the set")]
    DuplicateGuardian,
    #[msg("Threshold must be in 1..=guardians.len()")]
    InvalidThreshold,
    #[msg("Timelock duration is invalid")]
    InvalidTimelock,
    #[msg("Proposal has already been executed")]
    AlreadyExecuted,
    #[msg("Proposal has been cancelled")]
    Cancelled,
    #[msg("Approval threshold not yet reached")]
    ThresholdNotMet,
    #[msg("Timelock has not elapsed")]
    TimelockActive,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Build hash must be non-zero")]
    EmptyBuildHash,
}
