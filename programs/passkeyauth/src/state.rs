//! On-chain account layouts for PassKeyAuth.
use anchor_lang::prelude::*;

use crate::constants::{LABEL_LEN, MAX_ATTESTATIONS, MAX_PASSKEYS, P256_PUBKEY_LEN};

/// A registered passkey (secp256r1 / P-256) credential.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, InitSpace, Debug)]
pub struct PassKey {
    /// Compressed P-256 public key.
    pub pubkey: [u8; P256_PUBKEY_LEN],
    /// Human-readable label (null-padded).
    pub label: [u8; LABEL_LEN],
    /// Unix timestamp when the credential was registered.
    pub added_ts: i64,
    /// Whether this slot holds a live credential.
    pub is_active: bool,
}

impl Default for PassKey {
    fn default() -> Self {
        Self {
            pubkey: [0u8; P256_PUBKEY_LEN],
            label: [0u8; LABEL_LEN],
            added_ts: 0,
            is_active: false,
        }
    }
}

/// An attestation claimed by an identity from an issuer's Merkle set.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, InitSpace, Debug)]
pub struct Attestation {
    /// The issuer that anchored the eligible set.
    pub issuer: Pubkey,
    /// The issuer's schema identifier (what the attestation asserts).
    pub schema_id: [u8; 32],
    /// Unix timestamp when the attestation was claimed.
    pub claimed_ts: i64,
    /// Whether this slot holds a live attestation.
    pub is_active: bool,
}

/// A user's identity: a set of passkey credentials + claimed attestations.
///
/// PDA seed: [`crate::constants::IDENTITY_SEED`] ++ `owner`.
#[account]
#[derive(InitSpace)]
pub struct Identity {
    /// The wallet that owns and controls this identity.
    pub owner: Pubkey,
    /// Number of live entries in `passkeys`.
    pub passkey_count: u8,
    /// Fixed-capacity passkey table.
    pub passkeys: [PassKey; MAX_PASSKEYS],
    /// Number of live entries in `attestations`.
    pub attestation_count: u8,
    /// Fixed-capacity attestation table.
    pub attestations: [Attestation; MAX_ATTESTATIONS],
    /// PDA bump.
    pub bump: u8,
}

impl Identity {
    /// First free passkey slot, if any.
    pub fn free_passkey_slot(&self) -> Option<usize> {
        self.passkeys.iter().position(|p| !p.is_active)
    }

    /// First free attestation slot, if any.
    pub fn free_attestation_slot(&self) -> Option<usize> {
        self.attestations.iter().position(|a| !a.is_active)
    }
}

/// An attestation issuer: publishes a Merkle root over eligible commitments.
///
/// PDA seed: [`crate::constants::ISSUER_SEED`] ++ `authority`.
#[account]
#[derive(InitSpace)]
pub struct Issuer {
    /// The authority allowed to update the root.
    pub authority: Pubkey,
    /// The schema this issuer attests (e.g. "kyc-tier-1", "age-over-18").
    pub schema_id: [u8; 32],
    /// Current Merkle root of eligible identity commitments.
    pub merkle_root: [u8; 32],
    /// Number of attestations claimed against this issuer.
    pub attestation_count: u64,
    /// PDA bump.
    pub bump: u8,
}

/// A burned nullifier — its existence marks a proof as spent (replay guard).
///
/// PDA seed: [`crate::constants::NULLIFIER_SEED`] ++ `issuer` ++ `hash`.
#[account]
#[derive(InitSpace)]
pub struct Nullifier {
    /// The issuer the nullifier was spent against.
    pub issuer: Pubkey,
    /// The 32-byte nullifier hash.
    pub hash: [u8; 32],
    /// PDA bump.
    pub bump: u8,
}
