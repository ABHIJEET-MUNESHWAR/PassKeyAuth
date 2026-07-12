//! Program error codes for PassKeyAuth.
use anchor_lang::prelude::*;

#[error_code]
pub enum PassKeyError {
    #[msg("Arithmetic overflow or underflow")]
    MathOverflow,
    #[msg("The passkey table for this identity is full")]
    PassKeyTableFull,
    #[msg("The attestation table for this identity is full")]
    AttestationTableFull,
    #[msg("No passkey exists at the supplied index")]
    PassKeyNotFound,
    #[msg("Signer is not the owner of this identity")]
    NotOwner,
    #[msg("No secp256r1 precompile verification was found in this transaction")]
    MissingPasskeyVerification,
    #[msg("The verified passkey does not match the registered credential")]
    PasskeyMismatch,
    #[msg("The secp256r1 precompile instruction data is malformed")]
    MalformedPrecompile,
    #[msg("The Merkle membership proof is invalid for the issuer root")]
    InvalidMerkleProof,
    #[msg("The Merkle proof exceeds the maximum supported depth")]
    ProofTooDeep,
    #[msg("This nullifier has already been used (replay)")]
    NullifierAlreadyUsed,
    #[msg("Signer is not the authority for this issuer")]
    NotIssuerAuthority,
}
