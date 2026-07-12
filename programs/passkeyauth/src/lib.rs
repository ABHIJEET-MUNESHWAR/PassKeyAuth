//! # PassKeyAuth — on-chain passkeys + zero-knowledge attestations
//!
//! An Anchor program with two capabilities that together give a wallet a
//! flexible, privacy-preserving identity layer:
//!
//! 1. **Passkey (secp256r1 / WebAuthn) authorities** — register P-256
//!    credentials to an [`Identity`] and prove possession on-chain by having the
//!    Solana secp256r1 precompile verify a challenge, then confirming it via the
//!    instructions sysvar (see [`passkey`]).
//! 2. **Zero-knowledge set-membership attestations** — an [`Issuer`] publishes a
//!    Merkle root over eligible identity commitments; a user proves membership
//!    (see [`merkle`]) to claim an attestation **without revealing which leaf**,
//!    burning a [`Nullifier`] so the proof cannot be replayed.
#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::load_instruction_at_checked;
use solana_keccak_hasher as keccak;

pub mod constants;
pub mod errors;
pub mod merkle;
pub mod passkey;
pub mod state;

use constants::*;
use errors::PassKeyError;
use state::{Attestation, Identity, Issuer, Nullifier, PassKey};

declare_id!("8tKno5VNAXXoS6pXAebh1Fhoj2C4QrRQrqFAy8nfAz7m");

/// Upper bound on instructions scanned when locating the precompile (bounds CU).
const MAX_TX_INSTRUCTIONS: usize = 16;

#[program]
pub mod passkeyauth {
    use super::*;

    /// Create the signer's identity account.
    pub fn create_identity(ctx: Context<CreateIdentity>) -> Result<()> {
        let id = &mut ctx.accounts.identity;
        id.owner = ctx.accounts.owner.key();
        id.passkey_count = 0;
        id.passkeys = [PassKey::default(); MAX_PASSKEYS];
        id.attestation_count = 0;
        id.attestations = [Attestation::default(); MAX_ATTESTATIONS];
        id.bump = ctx.bumps.identity;
        emit!(IdentityCreated {
            identity: id.key(),
            owner: id.owner,
        });
        Ok(())
    }

    /// Register a passkey (secp256r1) credential on the identity.
    pub fn add_passkey(
        ctx: Context<ManageIdentity>,
        pubkey: [u8; P256_PUBKEY_LEN],
        label: [u8; LABEL_LEN],
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let id = &mut ctx.accounts.identity;
        let slot = id
            .free_passkey_slot()
            .ok_or(PassKeyError::PassKeyTableFull)?;
        id.passkeys[slot] = PassKey {
            pubkey,
            label,
            added_ts: now,
            is_active: true,
        };
        id.passkey_count = id
            .passkey_count
            .checked_add(1)
            .ok_or(PassKeyError::MathOverflow)?;
        emit!(PassKeyAdded {
            identity: id.key(),
            index: slot as u8,
        });
        Ok(())
    }

    /// Prove possession of a registered passkey.
    ///
    /// The transaction must also contain a `Secp256r1SigVerify` precompile
    /// instruction that verified a challenge under credential `index`'s public
    /// key; this handler confirms it via the instructions sysvar.
    pub fn verify_passkey(ctx: Context<VerifyPassKey>, index: u8) -> Result<()> {
        let id = &ctx.accounts.identity;
        let cred = id
            .passkeys
            .get(index as usize)
            .filter(|p| p.is_active)
            .ok_or(PassKeyError::PassKeyNotFound)?;

        let ixs = &ctx.accounts.instructions.to_account_info();
        let mut verified_message: Option<[u8; 32]> = None;
        for i in 0..MAX_TX_INSTRUCTIONS {
            let Ok(ix) = load_instruction_at_checked(i, ixs) else {
                break;
            };
            if ix.program_id != SECP256R1_PROGRAM_ID {
                continue;
            }
            let vc =
                passkey::extract_embedded(&ix.data).ok_or(PassKeyError::MalformedPrecompile)?;
            require!(vc.pubkey == cred.pubkey, PassKeyError::PasskeyMismatch);
            verified_message = Some(keccak::hash(vc.message).0);
            break;
        }
        let message_hash = verified_message.ok_or(PassKeyError::MissingPasskeyVerification)?;
        emit!(PassKeyVerified {
            identity: id.key(),
            index,
            message_hash,
        });
        Ok(())
    }

    /// Register an attestation issuer with an initial Merkle root.
    pub fn register_issuer(
        ctx: Context<RegisterIssuer>,
        schema_id: [u8; 32],
        merkle_root: [u8; 32],
    ) -> Result<()> {
        let issuer = &mut ctx.accounts.issuer;
        issuer.authority = ctx.accounts.authority.key();
        issuer.schema_id = schema_id;
        issuer.merkle_root = merkle_root;
        issuer.attestation_count = 0;
        issuer.bump = ctx.bumps.issuer;
        emit!(IssuerRegistered {
            issuer: issuer.key(),
            authority: issuer.authority,
        });
        Ok(())
    }

    /// Update the issuer's Merkle root (issuer authority only).
    pub fn update_root(ctx: Context<AdminIssuer>, merkle_root: [u8; 32]) -> Result<()> {
        ctx.accounts.issuer.merkle_root = merkle_root;
        emit!(RootUpdated {
            issuer: ctx.accounts.issuer.key(),
            merkle_root,
        });
        Ok(())
    }

    /// Claim an attestation by proving Merkle membership of `leaf` in the
    /// issuer's set, without revealing which leaf. Burns `nullifier`.
    pub fn claim_attestation(
        ctx: Context<ClaimAttestation>,
        leaf: [u8; 32],
        proof: Vec<[u8; 32]>,
        index_bits: u64,
        nullifier: [u8; 32],
    ) -> Result<()> {
        require!(proof.len() <= MAX_MERKLE_DEPTH, PassKeyError::ProofTooDeep);
        let issuer = &mut ctx.accounts.issuer;
        require!(
            merkle::verify(leaf, &proof, index_bits, issuer.merkle_root),
            PassKeyError::InvalidMerkleProof
        );

        // Burn the nullifier (the `init` on the Nullifier PDA fails if it
        // already exists → replay protection).
        let nul = &mut ctx.accounts.nullifier_record;
        nul.issuer = issuer.key();
        nul.hash = nullifier;
        nul.bump = ctx.bumps.nullifier_record;

        // Record the attestation on the claimer's identity.
        let now = Clock::get()?.unix_timestamp;
        let id = &mut ctx.accounts.identity;
        let slot = id
            .free_attestation_slot()
            .ok_or(PassKeyError::AttestationTableFull)?;
        id.attestations[slot] = Attestation {
            issuer: issuer.key(),
            schema_id: issuer.schema_id,
            claimed_ts: now,
            is_active: true,
        };
        id.attestation_count = id
            .attestation_count
            .checked_add(1)
            .ok_or(PassKeyError::MathOverflow)?;
        issuer.attestation_count = issuer
            .attestation_count
            .checked_add(1)
            .ok_or(PassKeyError::MathOverflow)?;

        emit!(AttestationClaimed {
            identity: id.key(),
            issuer: issuer.key(),
            schema_id: issuer.schema_id,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Account contexts
// ---------------------------------------------------------------------------

/// Accounts for [`passkeyauth::create_identity`].
#[derive(Accounts)]
pub struct CreateIdentity<'info> {
    /// The identity PDA (seeded by the owner).
    #[account(
        init,
        payer = owner,
        space = 8 + Identity::INIT_SPACE,
        seeds = [IDENTITY_SEED, owner.key().as_ref()],
        bump,
    )]
    pub identity: Account<'info, Identity>,
    /// The owner + rent payer.
    #[account(mut)]
    pub owner: Signer<'info>,
    /// System program.
    pub system_program: Program<'info, System>,
}

/// Accounts for identity-management instructions.
#[derive(Accounts)]
pub struct ManageIdentity<'info> {
    /// The identity being modified.
    #[account(
        mut,
        seeds = [IDENTITY_SEED, owner.key().as_ref()],
        bump = identity.bump,
        has_one = owner @ PassKeyError::NotOwner,
    )]
    pub identity: Account<'info, Identity>,
    /// The identity owner.
    pub owner: Signer<'info>,
}

/// Accounts for [`passkeyauth::verify_passkey`].
#[derive(Accounts)]
pub struct VerifyPassKey<'info> {
    /// The identity whose credential is being proven.
    #[account(
        seeds = [IDENTITY_SEED, owner.key().as_ref()],
        bump = identity.bump,
        has_one = owner @ PassKeyError::NotOwner,
    )]
    pub identity: Account<'info, Identity>,
    /// The identity owner.
    pub owner: Signer<'info>,
    /// CHECK: constrained to be the instructions sysvar; read-only.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
}

/// Accounts for [`passkeyauth::register_issuer`].
#[derive(Accounts)]
pub struct RegisterIssuer<'info> {
    /// The issuer PDA (seeded by the authority).
    #[account(
        init,
        payer = authority,
        space = 8 + Issuer::INIT_SPACE,
        seeds = [ISSUER_SEED, authority.key().as_ref()],
        bump,
    )]
    pub issuer: Account<'info, Issuer>,
    /// The issuer authority + rent payer.
    #[account(mut)]
    pub authority: Signer<'info>,
    /// System program.
    pub system_program: Program<'info, System>,
}

/// Accounts for issuer administration.
#[derive(Accounts)]
pub struct AdminIssuer<'info> {
    /// The issuer being modified.
    #[account(
        mut,
        seeds = [ISSUER_SEED, authority.key().as_ref()],
        bump = issuer.bump,
        has_one = authority @ PassKeyError::NotIssuerAuthority,
    )]
    pub issuer: Account<'info, Issuer>,
    /// The issuer authority.
    pub authority: Signer<'info>,
}

/// Accounts for [`passkeyauth::claim_attestation`].
#[derive(Accounts)]
#[instruction(leaf: [u8; 32], proof: Vec<[u8; 32]>, index_bits: u64, nullifier: [u8; 32])]
pub struct ClaimAttestation<'info> {
    /// The claimer's identity (receives the attestation).
    #[account(
        mut,
        seeds = [IDENTITY_SEED, owner.key().as_ref()],
        bump = identity.bump,
        has_one = owner @ PassKeyError::NotOwner,
    )]
    pub identity: Account<'info, Identity>,
    /// The issuer whose set membership is being proven.
    #[account(mut)]
    pub issuer: Account<'info, Issuer>,
    /// The nullifier PDA — `init` fails if already spent (replay guard).
    #[account(
        init,
        payer = owner,
        space = 8 + Nullifier::INIT_SPACE,
        seeds = [NULLIFIER_SEED, issuer.key().as_ref(), nullifier.as_ref()],
        bump,
    )]
    pub nullifier_record: Account<'info, Nullifier>,
    /// The identity owner + rent payer.
    #[account(mut)]
    pub owner: Signer<'info>,
    /// System program.
    pub system_program: Program<'info, System>,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Emitted when an identity is created.
#[event]
pub struct IdentityCreated {
    /// The identity PDA.
    pub identity: Pubkey,
    /// The owner.
    pub owner: Pubkey,
}

/// Emitted when a passkey is registered.
#[event]
pub struct PassKeyAdded {
    /// The identity PDA.
    pub identity: Pubkey,
    /// The credential slot index.
    pub index: u8,
}

/// Emitted when a passkey is proven via the secp256r1 precompile.
#[event]
pub struct PassKeyVerified {
    /// The identity PDA.
    pub identity: Pubkey,
    /// The credential slot index.
    pub index: u8,
    /// Keccak hash of the verified challenge message.
    pub message_hash: [u8; 32],
}

/// Emitted when an issuer is registered.
#[event]
pub struct IssuerRegistered {
    /// The issuer PDA.
    pub issuer: Pubkey,
    /// The issuer authority.
    pub authority: Pubkey,
}

/// Emitted when an issuer's root is updated.
#[event]
pub struct RootUpdated {
    /// The issuer PDA.
    pub issuer: Pubkey,
    /// The new Merkle root.
    pub merkle_root: [u8; 32],
}

/// Emitted when an attestation is claimed.
#[event]
pub struct AttestationClaimed {
    /// The identity PDA.
    pub identity: Pubkey,
    /// The issuer PDA.
    pub issuer: Pubkey,
    /// The issuer's schema id.
    pub schema_id: [u8; 32],
}
