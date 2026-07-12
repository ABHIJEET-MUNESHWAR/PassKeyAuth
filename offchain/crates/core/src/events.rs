//! Domain events emitted by the identity engine and indexer watchers.

use passkeyauth_types::{Digest, Pubkey};
use serde::{Deserialize, Serialize};

/// An identity-relevant event broadcast to subscribers (GraphQL, logs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AttestationEvent {
    /// An identity snapshot was indexed.
    IdentityIndexed {
        /// The identity PDA address.
        identity: Pubkey,
        /// Number of registered passkeys.
        passkeys: u32,
        /// Number of claimed attestations.
        attestations: u32,
    },
    /// An issuer snapshot was indexed.
    IssuerIndexed {
        /// The issuer PDA address.
        issuer: Pubkey,
        /// The current Merkle root.
        root: Digest,
    },
    /// An issuer's eligible-set tree was (re)built off-chain.
    TreeBuilt {
        /// The issuer PDA address.
        issuer: Pubkey,
        /// The computed Merkle root.
        root: Digest,
        /// Number of leaves in the tree.
        leaf_count: u32,
    },
    /// A membership proof was verified against an issuer's root.
    ProofVerified {
        /// The issuer PDA address.
        issuer: Pubkey,
        /// Whether the proof verified.
        valid: bool,
    },
}
