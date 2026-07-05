//! Host-side logic tests for the hardened governance core.

use securedeploy_core::state::{
    validate_guardians, ConfigError, Governance, Proposal, MAX_GUARDIANS,
};

use anchor_lang::prelude::Pubkey;

fn keys(n: usize) -> Vec<Pubkey> {
    (0..n).map(|_| Pubkey::new_unique()).collect()
}

#[test]
fn guardian_validation_boundaries() {
    let g = keys(MAX_GUARDIANS);
    assert_eq!(validate_guardians(&g, MAX_GUARDIANS as u8), Ok(()));
    assert_eq!(
        validate_guardians(&keys(MAX_GUARDIANS + 1), 1),
        Err(ConfigError::TooMany)
    );
    assert_eq!(validate_guardians(&[], 1), Err(ConfigError::Empty));
}

#[test]
fn threshold_must_be_within_range() {
    let g = keys(4);
    assert_eq!(
        validate_guardians(&g, 0),
        Err(ConfigError::InvalidThreshold)
    );
    assert_eq!(
        validate_guardians(&g, 5),
        Err(ConfigError::InvalidThreshold)
    );
    assert_eq!(validate_guardians(&g, 1), Ok(()));
    assert_eq!(validate_guardians(&g, 4), Ok(()));
}

#[test]
fn duplicate_guardians_rejected() {
    let mut g = keys(4);
    g[3] = g[1];
    assert_eq!(validate_guardians(&g, 2), Err(ConfigError::Duplicate));
}

#[test]
fn account_sizes_are_bounded() {
    // Governance must have room for the maximum guardian set.
    let min = 8 + 32 + 32 + 4 + MAX_GUARDIANS * 32 + 1 + 8 + 1 + 8 + 1;
    assert_eq!(Governance::LEN, min);
    assert_eq!(Proposal::LEN, 8 + 8 + 32 + 32 + 32 + 8 + 1 + 1 + 1 + 1);
}
