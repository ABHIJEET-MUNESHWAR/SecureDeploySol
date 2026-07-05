//! Guardian-set validation and timelock math — the exact rules the on-chain
//! program enforces, mirrored off-chain so the indexer/API reject invalid
//! configurations before a transaction is ever built.

use crate::error::{Result, SecureError};

/// Upper bound on the guardian set, matching the on-chain `MAX_GUARDIANS`.
pub const MAX_GUARDIANS: usize = 16;

/// Validate a guardian set and threshold.
///
/// Enforces: non-empty, size within [`MAX_GUARDIANS`], no duplicates, and
/// `1 <= threshold <= len`.
pub fn validate_guardians<T: PartialEq>(guardians: &[T], threshold: u8) -> Result<()> {
    if guardians.is_empty() {
        return Err(SecureError::EmptyGuardianSet);
    }
    if guardians.len() > MAX_GUARDIANS {
        return Err(SecureError::TooManyGuardians { max: MAX_GUARDIANS });
    }
    for (i, a) in guardians.iter().enumerate() {
        for b in &guardians[i + 1..] {
            if a == b {
                return Err(SecureError::DuplicateGuardian);
            }
        }
    }
    let t = threshold as usize;
    if t == 0 || t > guardians.len() {
        return Err(SecureError::InvalidThreshold {
            threshold,
            len: guardians.len(),
        });
    }
    Ok(())
}

/// Earliest execution time for a proposal created at `created_at` under a
/// `timelock` (seconds). Checked to avoid overflow.
pub fn compute_eta(created_at: i64, timelock: i64) -> Result<i64> {
    created_at
        .checked_add(timelock)
        .ok_or(SecureError::Overflow)
}

/// Whether a proposal may execute at `now` given `eta`, `approvals`, and the
/// required `threshold`. Returns the specific gate that failed.
pub fn can_execute(now: i64, eta: i64, approvals: u8, threshold: u8) -> Result<()> {
    if approvals < threshold {
        return Err(SecureError::ThresholdNotMet {
            approvals,
            threshold,
        });
    }
    if now < eta {
        return Err(SecureError::TimelockActive {
            remaining: eta - now,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_config_passes() {
        assert!(validate_guardians(&[1, 2, 3], 2).is_ok());
    }

    #[test]
    fn empty_rejected() {
        let empty: [u8; 0] = [];
        assert_eq!(
            validate_guardians(&empty, 1),
            Err(SecureError::EmptyGuardianSet)
        );
    }

    #[test]
    fn duplicate_rejected() {
        assert_eq!(
            validate_guardians(&[1, 2, 2], 2),
            Err(SecureError::DuplicateGuardian)
        );
    }

    #[test]
    fn threshold_bounds() {
        assert!(matches!(
            validate_guardians(&[1, 2, 3], 0),
            Err(SecureError::InvalidThreshold { .. })
        ));
        assert!(matches!(
            validate_guardians(&[1, 2, 3], 4),
            Err(SecureError::InvalidThreshold { .. })
        ));
    }

    #[test]
    fn eta_overflow_is_caught() {
        assert_eq!(compute_eta(i64::MAX, 1), Err(SecureError::Overflow));
        assert_eq!(compute_eta(100, 50), Ok(150));
    }

    #[test]
    fn execution_gates() {
        // threshold not met
        assert!(matches!(
            can_execute(200, 150, 1, 2),
            Err(SecureError::ThresholdNotMet { .. })
        ));
        // timelock active
        assert!(matches!(
            can_execute(100, 150, 2, 2),
            Err(SecureError::TimelockActive { .. })
        ));
        // ok
        assert_eq!(can_execute(200, 150, 2, 2), Ok(()));
    }
}
