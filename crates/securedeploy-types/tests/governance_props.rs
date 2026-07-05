use proptest::prelude::*;
use securedeploy_types::governance::{can_execute, validate_guardians, MAX_GUARDIANS};

proptest! {
    // A valid, unique guardian set with a threshold in range always validates.
    #[test]
    fn valid_sets_pass(len in 1usize..=MAX_GUARDIANS, t in 1u8..=MAX_GUARDIANS as u8) {
        let guardians: Vec<u32> = (0..len as u32).collect();
        let threshold = t.min(len as u8);
        prop_assert!(validate_guardians(&guardians, threshold).is_ok());
    }

    // Oversized sets are always rejected.
    #[test]
    fn oversized_rejected(extra in 1usize..8) {
        let guardians: Vec<u32> = (0..(MAX_GUARDIANS + extra) as u32).collect();
        prop_assert!(validate_guardians(&guardians, 1).is_err());
    }

    // Execution is permitted iff both gates pass.
    #[test]
    fn execution_monotonic(now in 0i64..1_000_000, eta in 0i64..1_000_000, a in 0u8..10, t in 1u8..10) {
        let res = can_execute(now, eta, a, t);
        prop_assert_eq!(res.is_ok(), a >= t && now >= eta);
    }
}
