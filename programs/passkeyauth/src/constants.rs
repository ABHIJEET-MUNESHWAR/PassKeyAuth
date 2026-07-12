//! Compile-time capacities, PDA seeds, and fixed program ids for PassKeyAuth.
use anchor_lang::prelude::*;

/// PDA seed for an [`crate::state::Identity`]: `["identity", owner]`.
pub const IDENTITY_SEED: &[u8] = b"identity";
/// PDA seed for an [`crate::state::Issuer`]: `["issuer", authority]`.
pub const ISSUER_SEED: &[u8] = b"issuer";
/// PDA seed for a [`crate::state::Nullifier`]: `["nullifier", issuer, hash]`.
pub const NULLIFIER_SEED: &[u8] = b"nullifier";

/// Maximum passkey credentials attached to one identity.
pub const MAX_PASSKEYS: usize = 4;
/// Maximum attestations recorded on one identity.
pub const MAX_ATTESTATIONS: usize = 4;
/// Maximum supported Merkle proof depth (bounds the verification loop).
pub const MAX_MERKLE_DEPTH: usize = 20;
/// Length of a compressed P-256 (secp256r1) public key.
pub const P256_PUBKEY_LEN: usize = 33;
/// Length of a human-readable credential label.
pub const LABEL_LEN: usize = 16;

/// The Solana secp256r1 signature-verification precompile program id.
pub const SECP256R1_PROGRAM_ID: Pubkey = pubkey!("Secp256r1SigVerify1111111111111111111111111");
