//! # passkeyauth-infra — adapters implementing the core ports
//!
//! Concurrent in-memory stores (`dashmap`), a Tokio broadcast event bus serving
//! as BOTH [`EventSink`] and [`EventStream`], and a deterministic
//! [`SimDataSource`] that fabricates an identity + issuer for local runs/tests.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use dashmap::DashMap;
use futures::stream::BoxStream;
use passkeyauth_core::events::AttestationEvent;
use passkeyauth_core::ports::{
    DataSource, EventSink, EventStream, IdentityStore, IssuerStore, PortError, TreeStore,
};
use passkeyauth_types::{AttestationView, Digest, IdentityView, IssuerView, PassKeyView, Pubkey};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

/// Concurrent in-memory identity store keyed by PDA address.
#[derive(Default)]
pub struct InMemoryIdentityStore {
    inner: DashMap<[u8; 32], IdentityView>,
}

impl InMemoryIdentityStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl IdentityStore for InMemoryIdentityStore {
    async fn all_identities(&self) -> Result<Vec<IdentityView>, PortError> {
        Ok(self.inner.iter().map(|e| e.value().clone()).collect())
    }
    async fn identity(&self, address: &Pubkey) -> Result<IdentityView, PortError> {
        self.inner
            .get(&address.0)
            .map(|e| e.value().clone())
            .ok_or(PortError::NotFound)
    }
    async fn upsert_identity(&self, identity: IdentityView) -> Result<(), PortError> {
        self.inner.insert(identity.address.0, identity);
        Ok(())
    }
}

/// Concurrent in-memory issuer store keyed by PDA address.
#[derive(Default)]
pub struct InMemoryIssuerStore {
    inner: DashMap<[u8; 32], IssuerView>,
}

impl InMemoryIssuerStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl IssuerStore for InMemoryIssuerStore {
    async fn all_issuers(&self) -> Result<Vec<IssuerView>, PortError> {
        Ok(self.inner.iter().map(|e| e.value().clone()).collect())
    }
    async fn issuer(&self, address: &Pubkey) -> Result<IssuerView, PortError> {
        self.inner
            .get(&address.0)
            .map(|e| e.value().clone())
            .ok_or(PortError::NotFound)
    }
    async fn upsert_issuer(&self, issuer: IssuerView) -> Result<(), PortError> {
        self.inner.insert(issuer.address.0, issuer);
        Ok(())
    }
}

/// Concurrent in-memory leaf store keyed by issuer address.
#[derive(Default)]
pub struct InMemoryTreeStore {
    inner: DashMap<[u8; 32], Vec<Digest>>,
}

impl InMemoryTreeStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TreeStore for InMemoryTreeStore {
    async fn put_leaves(&self, issuer: Pubkey, leaves: Vec<Digest>) -> Result<(), PortError> {
        self.inner.insert(issuer.0, leaves);
        Ok(())
    }
    async fn get_leaves(&self, issuer: &Pubkey) -> Result<Vec<Digest>, PortError> {
        self.inner
            .get(&issuer.0)
            .map(|e| e.value().clone())
            .ok_or(PortError::NotFound)
    }
}

/// A Tokio broadcast bus used as both event sink and event stream.
#[derive(Clone)]
pub struct BroadcastBus {
    tx: broadcast::Sender<AttestationEvent>,
}

impl BroadcastBus {
    /// Create a bus with the given ring-buffer capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Current number of active subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for BroadcastBus {
    fn default() -> Self {
        Self::new(1_024)
    }
}

#[async_trait]
impl EventSink for BroadcastBus {
    async fn publish(&self, event: AttestationEvent) {
        let _ = self.tx.send(event);
    }
}

impl EventStream for BroadcastBus {
    fn subscribe(&self) -> BoxStream<'static, AttestationEvent> {
        let rx = self.tx.subscribe();
        Box::pin(BroadcastStream::new(rx).filter_map(Result::ok))
    }
}

/// A deterministic simulator that mints one identity and one issuer.
#[derive(Default)]
pub struct SimDataSource;

impl SimDataSource {
    /// Construct the simulator.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// The single identity this simulator mints.
    #[must_use]
    pub fn demo_identity() -> IdentityView {
        IdentityView {
            address: Pubkey::new([0xCD; 32]),
            owner: Pubkey::new([0x11; 32]),
            passkeys: vec![PassKeyView {
                pubkey_hex: "02".to_string() + &"ab".repeat(32),
                label: "yubikey-5c".into(),
                added_ts: 1_700_000_000,
            }],
            attestations: vec![AttestationView {
                issuer: Pubkey::new([0xEE; 32]),
                schema_id: Digest::new([0x07; 32]),
                claimed_ts: 1_700_000_100,
            }],
        }
    }

    /// The single issuer this simulator mints.
    #[must_use]
    pub fn demo_issuer() -> IssuerView {
        IssuerView {
            address: Pubkey::new([0xEE; 32]),
            authority: Pubkey::new([0x22; 32]),
            schema_id: Digest::new([0x07; 32]),
            merkle_root: Digest::zero(),
            attestation_count: 1,
        }
    }
}

#[async_trait]
impl DataSource for SimDataSource {
    async fn poll_identities(&self) -> Result<Vec<IdentityView>, PortError> {
        Ok(vec![Self::demo_identity()])
    }
    async fn poll_issuers(&self) -> Result<Vec<IssuerView>, PortError> {
        Ok(vec![Self::demo_issuer()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn identity_store_roundtrip() {
        let s = InMemoryIdentityStore::new();
        let v = SimDataSource::demo_identity();
        s.upsert_identity(v.clone()).await.unwrap();
        assert_eq!(s.identity(&v.address).await.unwrap(), v);
        assert!(matches!(
            s.identity(&Pubkey::new([0; 32])).await,
            Err(PortError::NotFound)
        ));
    }

    #[tokio::test]
    async fn tree_store_roundtrip() {
        let s = InMemoryTreeStore::new();
        let issuer = Pubkey::new([1; 32]);
        s.put_leaves(issuer, vec![Digest::new([2; 32])])
            .await
            .unwrap();
        assert_eq!(s.get_leaves(&issuer).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn bus_delivers_events() {
        let bus = BroadcastBus::new(8);
        let mut stream = bus.subscribe();
        bus.publish(AttestationEvent::ProofVerified {
            issuer: Pubkey::new([1; 32]),
            valid: true,
        })
        .await;
        assert!(matches!(
            stream.next().await.unwrap(),
            AttestationEvent::ProofVerified { valid: true, .. }
        ));
    }

    #[tokio::test]
    async fn sim_mints_identity_and_issuer() {
        let src = SimDataSource::new();
        assert_eq!(src.poll_identities().await.unwrap().len(), 1);
        assert_eq!(src.poll_issuers().await.unwrap().len(), 1);
    }
}
