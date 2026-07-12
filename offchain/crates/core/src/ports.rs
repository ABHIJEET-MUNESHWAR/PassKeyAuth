//! Ports (hexagonal boundaries) the engine depends on. Adapters live in `infra`.

use async_trait::async_trait;
use futures::stream::BoxStream;
use passkeyauth_types::{Digest, IdentityView, IssuerView, Pubkey};
use thiserror::Error;

use crate::events::AttestationEvent;

/// Errors crossing a storage or data-source port.
#[derive(Debug, Error)]
pub enum PortError {
    /// The underlying adapter failed.
    #[error("port failure: {0}")]
    Backend(String),
    /// A requested entity was not found.
    #[error("not found")]
    NotFound,
}

/// Read/write access to mirrored identities.
#[async_trait]
pub trait IdentityStore: Send + Sync {
    /// Fetch all mirrored identities.
    async fn all_identities(&self) -> Result<Vec<IdentityView>, PortError>;
    /// Fetch one identity by address.
    async fn identity(&self, address: &Pubkey) -> Result<IdentityView, PortError>;
    /// Insert or update an identity.
    async fn upsert_identity(&self, identity: IdentityView) -> Result<(), PortError>;
}

/// Read/write access to mirrored issuers.
#[async_trait]
pub trait IssuerStore: Send + Sync {
    /// Fetch all mirrored issuers.
    async fn all_issuers(&self) -> Result<Vec<IssuerView>, PortError>;
    /// Fetch one issuer by address.
    async fn issuer(&self, address: &Pubkey) -> Result<IssuerView, PortError>;
    /// Insert or update an issuer.
    async fn upsert_issuer(&self, issuer: IssuerView) -> Result<(), PortError>;
}

/// Storage for an issuer's eligible-set leaves (to (re)build trees + proofs).
#[async_trait]
pub trait TreeStore: Send + Sync {
    /// Store the ordered leaves for an issuer.
    async fn put_leaves(&self, issuer: Pubkey, leaves: Vec<Digest>) -> Result<(), PortError>;
    /// Fetch the ordered leaves for an issuer.
    async fn get_leaves(&self, issuer: &Pubkey) -> Result<Vec<Digest>, PortError>;
}

/// A source of on-chain updates (RPC poller, geyser, or simulator).
#[async_trait]
pub trait DataSource: Send + Sync {
    /// Pull the latest identity snapshots.
    async fn poll_identities(&self) -> Result<Vec<IdentityView>, PortError>;
    /// Pull the latest issuer snapshots.
    async fn poll_issuers(&self) -> Result<Vec<IssuerView>, PortError>;
}

/// Publish side of the event bus.
#[async_trait]
pub trait EventSink: Send + Sync {
    /// Broadcast an event to all subscribers.
    async fn publish(&self, event: AttestationEvent);
}

/// Subscribe side of the event bus.
pub trait EventStream: Send + Sync {
    /// A live stream of subsequent events.
    fn subscribe(&self) -> BoxStream<'static, AttestationEvent>;
}
