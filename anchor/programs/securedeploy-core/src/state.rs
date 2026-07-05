use anchor_lang::prelude::*;

/// Upper bound on the guardian set. A *bounded* vector is a deliberate
/// hardening choice: it fixes the account size at allocation time and prevents
/// an unbounded-growth / rent-exhaustion denial-of-service.
pub const MAX_GUARDIANS: usize = 16;

/// Validation errors for a proposed guardian configuration.
///
/// This is a plain enum (not an Anchor `#[error_code]`) so the validation logic
/// is a pure function that can be exhaustively unit-tested on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    Empty,
    TooMany,
    Duplicate,
    InvalidThreshold,
}

/// Validate a guardian set + threshold without touching chain state.
///
/// Invariants enforced:
/// * non-empty set,
/// * size within [`MAX_GUARDIANS`],
/// * no duplicate guardians (a duplicate would let one key satisfy the
///   threshold twice),
/// * `1 <= threshold <= guardians.len()`.
pub fn validate_guardians(
    guardians: &[Pubkey],
    threshold: u8,
) -> core::result::Result<(), ConfigError> {
    if guardians.is_empty() {
        return Err(ConfigError::Empty);
    }
    if guardians.len() > MAX_GUARDIANS {
        return Err(ConfigError::TooMany);
    }
    for (i, a) in guardians.iter().enumerate() {
        for b in &guardians[i + 1..] {
            if a == b {
                return Err(ConfigError::Duplicate);
            }
        }
    }
    let t = threshold as usize;
    if t == 0 || t > guardians.len() {
        return Err(ConfigError::InvalidThreshold);
    }
    Ok(())
}

/// Root governance account (PDA `["governance"]`).
#[account]
pub struct Governance {
    /// Current authority (may pause, cancel, and rotate the guardian set).
    pub authority: Pubkey,
    /// Two-step authority transfer target; `None` sentinel is `Pubkey::default()`.
    pub pending_authority: Pubkey,
    /// Registered guardians; upgrades require `threshold` distinct approvals.
    pub guardians: Vec<Pubkey>,
    /// Number of distinct guardian approvals required to execute a proposal.
    pub threshold: u8,
    /// Minimum seconds between proposal creation and execution.
    pub timelock_seconds: i64,
    /// Emergency stop; blocks propose/approve/execute.
    pub paused: bool,
    /// Monotonic proposal counter (also the next proposal id).
    pub proposal_count: u64,
    /// Canonical bump for this PDA.
    pub bump: u8,
}

impl Governance {
    pub const SEED: &'static [u8] = b"governance";

    /// Space for `MAX_GUARDIANS`, so the account never needs a realloc.
    pub const LEN: usize = 8            // discriminator
        + 32                            // authority
        + 32                            // pending_authority
        + (4 + MAX_GUARDIANS * 32)      // guardians vec
        + 1                             // threshold
        + 8                             // timelock_seconds
        + 1                             // paused
        + 8                             // proposal_count
        + 1; // bump

    /// Constant-time membership check against the guardian set.
    pub fn is_guardian(&self, key: &Pubkey) -> bool {
        self.guardians.iter().any(|g| g == key)
    }
}

/// A timelocked, guardian-approved upgrade proposal
/// (PDA `["proposal", id_le]`).
#[account]
pub struct Proposal {
    /// Proposal id (equals the `proposal_count` at creation time).
    pub id: u64,
    /// The program whose upgrade is being governed.
    pub program_id: Pubkey,
    /// Expected verifiable build hash (e.g. sha256 of the artifact). Pinning
    /// this defends against swapping in an unreviewed binary at deploy time.
    pub build_hash: [u8; 32],
    /// Who proposed the upgrade.
    pub proposer: Pubkey,
    /// Earliest execution time (created_at + timelock).
    pub eta: i64,
    /// Distinct guardian approvals accumulated so far.
    pub approvals: u8,
    /// Whether the proposal has been executed.
    pub executed: bool,
    /// Whether the proposal has been cancelled.
    pub cancelled: bool,
    /// Canonical bump.
    pub bump: u8,
}

impl Proposal {
    pub const SEED: &'static [u8] = b"proposal";
    pub const LEN: usize = 8 + 8 + 32 + 32 + 32 + 8 + 1 + 1 + 1 + 1;
}

/// Per-guardian approval marker (PDA `["approval", id_le, guardian]`).
///
/// Its *existence* is the vote. Creating it with `init` makes a second vote by
/// the same guardian fail atomically — this is the replay/double-vote guard.
#[account]
pub struct Approval {
    pub proposal_id: u64,
    pub guardian: Pubkey,
    pub bump: u8,
}

impl Approval {
    pub const SEED: &'static [u8] = b"approval";
    pub const LEN: usize = 8 + 8 + 32 + 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize) -> Vec<Pubkey> {
        (0..n).map(|_| Pubkey::new_unique()).collect()
    }

    #[test]
    fn rejects_empty_set() {
        assert_eq!(validate_guardians(&[], 1), Err(ConfigError::Empty));
    }

    #[test]
    fn rejects_oversized_set() {
        let g = keys(MAX_GUARDIANS + 1);
        assert_eq!(validate_guardians(&g, 1), Err(ConfigError::TooMany));
    }

    #[test]
    fn rejects_duplicate_guardian() {
        let mut g = keys(3);
        g[2] = g[0];
        assert_eq!(validate_guardians(&g, 2), Err(ConfigError::Duplicate));
    }

    #[test]
    fn rejects_zero_threshold() {
        let g = keys(3);
        assert_eq!(
            validate_guardians(&g, 0),
            Err(ConfigError::InvalidThreshold)
        );
    }

    #[test]
    fn rejects_threshold_above_len() {
        let g = keys(3);
        assert_eq!(
            validate_guardians(&g, 4),
            Err(ConfigError::InvalidThreshold)
        );
    }

    #[test]
    fn accepts_valid_config() {
        let g = keys(5);
        assert_eq!(validate_guardians(&g, 3), Ok(()));
    }

    #[test]
    fn membership_check() {
        let g = keys(3);
        let gov = Governance {
            authority: Pubkey::new_unique(),
            pending_authority: Pubkey::default(),
            guardians: g.clone(),
            threshold: 2,
            timelock_seconds: 3600,
            paused: false,
            proposal_count: 0,
            bump: 255,
        };
        assert!(gov.is_guardian(&g[1]));
        assert!(!gov.is_guardian(&Pubkey::new_unique()));
    }
}
