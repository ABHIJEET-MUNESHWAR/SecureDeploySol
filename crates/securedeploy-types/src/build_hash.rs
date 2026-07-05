//! Verifiable build-hash utilities.
//!
//! A deployment is pinned to the sha256 of its artifact. Off-chain we can
//! recompute the hash of a downloaded artifact and compare it byte-for-byte to
//! the hash recorded in the on-chain proposal — this is the core defence
//! against deploying an unreviewed binary.

use crate::error::{Result, SecureError};
use sha2::{Digest, Sha256};

/// A 32-byte build hash (sha256 of a program artifact).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BuildHash([u8; 32]);

impl BuildHash {
    /// Compute the sha256 of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        Self(arr)
    }

    /// Wrap raw bytes, rejecting the all-zero sentinel.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0u8; 32] {
            return Err(SecureError::EmptyBuildHash);
        }
        Ok(Self(bytes))
    }

    /// Parse a 64-char hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let raw = hex::decode(s).map_err(|_| SecureError::InvalidLength {
            expected: 64,
            got: s.len(),
        })?;
        if raw.len() != 32 {
            return Err(SecureError::InvalidLength {
                expected: 32,
                got: raw.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        Self::from_bytes(arr)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Constant-work equality (both are fixed 32-byte arrays).
    #[must_use]
    pub fn matches(&self, other: &BuildHash) -> bool {
        self.0 == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(BuildHash::of(b"artifact"), BuildHash::of(b"artifact"));
        assert_ne!(BuildHash::of(b"artifact"), BuildHash::of(b"artifact2"));
    }

    #[test]
    fn hex_roundtrip() {
        let h = BuildHash::of(b"program.so");
        let restored = BuildHash::from_hex(&h.to_hex()).unwrap();
        assert!(h.matches(&restored));
    }

    #[test]
    fn zero_hash_rejected() {
        assert_eq!(
            BuildHash::from_bytes([0u8; 32]),
            Err(SecureError::EmptyBuildHash)
        );
    }

    #[test]
    fn bad_hex_rejected() {
        assert!(BuildHash::from_hex("zz").is_err());
    }
}
