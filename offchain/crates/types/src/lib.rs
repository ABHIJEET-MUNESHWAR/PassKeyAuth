//! # passkeyauth-types — off-chain domain model for the identity service
//!
//! Pure, dependency-light types mirroring the on-chain PassKeyAuth program
//! (identities, passkey credentials, issuers, attestations) plus the Merkle
//! membership-proof types the off-chain service builds. Digests use keccak-256
//! (see `passkeyauth-core::merkle`), matching the on-chain hash exactly so
//! roots and proofs reconcile bit-for-bit.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced when constructing or validating domain values.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// A hex string could not be parsed to the expected width.
    #[error("invalid hex (expected {expected} bytes)")]
    InvalidHex {
        /// Expected byte width.
        expected: usize,
    },
    /// A referenced entity was not found.
    #[error("not found")]
    NotFound,
}

/// Decode a fixed-width hex string into `N` bytes.
fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], DomainError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != N * 2 {
        return Err(DomainError::InvalidHex { expected: N });
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or(DomainError::InvalidHex { expected: N })?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or(DomainError::InvalidHex { expected: N })?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Ok(out)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A 32-byte Solana-style public key / address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    /// Build from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Lowercase hex (64 chars).
    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
    /// Parse from hex.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidHex`] on malformed input.
    pub fn from_hex(s: &str) -> Result<Self, DomainError> {
        Ok(Self(decode_hex::<32>(s)?))
    }
}

/// A 32-byte keccak digest (a Merkle leaf, node, or root).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// Build from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// The zero digest.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }
    /// Lowercase hex (64 chars).
    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
    /// Parse from hex.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidHex`] on malformed input.
    pub fn from_hex(s: &str) -> Result<Self, DomainError> {
        Ok(Self(decode_hex::<32>(s)?))
    }
}

/// A registered passkey (secp256r1) credential (off-chain view).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassKeyView {
    /// Compressed P-256 public key, hex (66 chars).
    pub pubkey_hex: String,
    /// Human-readable label.
    pub label: String,
    /// Unix timestamp when registered.
    pub added_ts: i64,
}

/// A claimed attestation (off-chain view).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationView {
    /// The issuer PDA.
    pub issuer: Pubkey,
    /// The issuer's schema id.
    pub schema_id: Digest,
    /// Unix timestamp when claimed.
    pub claimed_ts: i64,
}

/// An off-chain mirror of an on-chain identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityView {
    /// The identity PDA address.
    pub address: Pubkey,
    /// The owner wallet.
    pub owner: Pubkey,
    /// Registered passkeys.
    pub passkeys: Vec<PassKeyView>,
    /// Claimed attestations.
    pub attestations: Vec<AttestationView>,
}

/// An off-chain mirror of an on-chain attestation issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerView {
    /// The issuer PDA address.
    pub address: Pubkey,
    /// The issuer authority.
    pub authority: Pubkey,
    /// The schema this issuer attests.
    pub schema_id: Digest,
    /// The current Merkle root over eligible commitments.
    pub merkle_root: Digest,
    /// Number of attestations claimed.
    pub attestation_count: u64,
}

/// A Merkle membership proof for a leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf being proven.
    pub leaf: Digest,
    /// The sibling digests from leaf to root.
    pub siblings: Vec<Digest>,
    /// Direction bits (bit set → current node is the right child).
    pub index_bits: u64,
}

/// Aggregate identity-service statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityStats {
    /// Number of mirrored identities.
    pub identities: u64,
    /// Number of mirrored issuers.
    pub issuers: u64,
    /// Total registered passkeys.
    pub passkeys: u64,
    /// Total claimed attestations.
    pub attestations: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips() {
        let k = Pubkey::new([0x2a; 32]);
        assert_eq!(Pubkey::from_hex(&k.to_hex()).unwrap(), k);
        let d = Digest::new([0xff; 32]);
        assert_eq!(Digest::from_hex(&d.to_hex()).unwrap(), d);
        assert!(Digest::from_hex("00").is_err());
        assert_eq!(Digest::zero(), Digest::new([0; 32]));
    }
}
