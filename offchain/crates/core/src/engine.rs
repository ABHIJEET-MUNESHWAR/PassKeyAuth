//! The identity engine: indexes identities/issuers, builds issuer Merkle trees,
//! and generates + verifies membership proofs (mirroring the on-chain check).

use std::sync::Arc;

use passkeyauth_types::{Digest, IdentityStats, IdentityView, IssuerView, MerkleProof, Pubkey};

use crate::config::EngineConfig;
use crate::events::AttestationEvent;
use crate::merkle::{self, MerkleTree};
use crate::ports::{EventSink, IdentityStore, IssuerStore, PortError, TreeStore};

/// Errors surfaced by the engine.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// A storage/data-source port failed.
    #[error(transparent)]
    Port(#[from] PortError),
    /// A requested leaf index is out of range.
    #[error("leaf index {0} out of range")]
    LeafOutOfRange(usize),
}

/// The composition of ports that drive identity indexing and attestation.
#[derive(Clone)]
pub struct IdentityEngine {
    identities: Arc<dyn IdentityStore>,
    issuers: Arc<dyn IssuerStore>,
    trees: Arc<dyn TreeStore>,
    events: Arc<dyn EventSink>,
    config: EngineConfig,
}

impl IdentityEngine {
    /// Assemble an engine from its ports and configuration.
    #[must_use]
    pub fn new(
        identities: Arc<dyn IdentityStore>,
        issuers: Arc<dyn IssuerStore>,
        trees: Arc<dyn TreeStore>,
        events: Arc<dyn EventSink>,
        config: EngineConfig,
    ) -> Self {
        Self {
            identities,
            issuers,
            trees,
            events,
            config,
        }
    }

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> EngineConfig {
        self.config
    }

    /// Snapshot of all mirrored identities.
    ///
    /// # Errors
    /// Returns [`EngineError`] on port failure.
    pub async fn identities_snapshot(&self) -> Result<Vec<IdentityView>, EngineError> {
        Ok(self.identities.all_identities().await?)
    }

    /// Snapshot of all mirrored issuers.
    ///
    /// # Errors
    /// Returns [`EngineError`] on port failure.
    pub async fn issuers_snapshot(&self) -> Result<Vec<IssuerView>, EngineError> {
        Ok(self.issuers.all_issuers().await?)
    }

    /// Fetch one identity by address.
    ///
    /// # Errors
    /// Returns [`EngineError`] if missing or the port fails.
    pub async fn identity(&self, address: &Pubkey) -> Result<IdentityView, EngineError> {
        Ok(self.identities.identity(address).await?)
    }

    /// Ingest an identity snapshot, persisting it and emitting an event.
    ///
    /// # Errors
    /// Returns [`EngineError`] on port failure.
    pub async fn ingest_identity(&self, identity: IdentityView) -> Result<(), EngineError> {
        let ev = AttestationEvent::IdentityIndexed {
            identity: identity.address,
            passkeys: identity.passkeys.len() as u32,
            attestations: identity.attestations.len() as u32,
        };
        self.identities.upsert_identity(identity).await?;
        self.events.publish(ev).await;
        Ok(())
    }

    /// Ingest an issuer snapshot, persisting it and emitting an event.
    ///
    /// # Errors
    /// Returns [`EngineError`] on port failure.
    pub async fn ingest_issuer(&self, issuer: IssuerView) -> Result<(), EngineError> {
        let ev = AttestationEvent::IssuerIndexed {
            issuer: issuer.address,
            root: issuer.merkle_root,
        };
        self.issuers.upsert_issuer(issuer).await?;
        self.events.publish(ev).await;
        Ok(())
    }

    /// Build (or rebuild) an issuer's eligible-set Merkle tree from `leaves`,
    /// persist the leaves, update the issuer's root, and emit an event.
    /// Returns the computed root.
    ///
    /// # Errors
    /// Returns [`EngineError`] if the issuer is missing or a port fails.
    pub async fn build_tree(
        &self,
        issuer_addr: &Pubkey,
        leaves: Vec<Digest>,
    ) -> Result<Digest, EngineError> {
        let mut issuer = self.issuers.issuer(issuer_addr).await?;
        let tree = MerkleTree::from_leaves(leaves.iter().map(|d| d.0).collect());
        let root = Digest::new(tree.root());
        self.trees.put_leaves(*issuer_addr, leaves.clone()).await?;
        issuer.merkle_root = root;
        self.issuers.upsert_issuer(issuer).await?;
        self.events
            .publish(AttestationEvent::TreeBuilt {
                issuer: *issuer_addr,
                root,
                leaf_count: leaves.len() as u32,
            })
            .await;
        Ok(root)
    }

    /// Generate a membership proof for the leaf at `index` in an issuer's tree.
    ///
    /// # Errors
    /// Returns [`EngineError`] if the issuer/leaf is missing or a port fails.
    pub async fn prove(
        &self,
        issuer_addr: &Pubkey,
        index: usize,
    ) -> Result<MerkleProof, EngineError> {
        let leaves = self.trees.get_leaves(issuer_addr).await?;
        let tree = MerkleTree::from_leaves(leaves.iter().map(|d| d.0).collect());
        let (siblings, index_bits) = tree
            .proof(index)
            .ok_or(EngineError::LeafOutOfRange(index))?;
        Ok(MerkleProof {
            leaf: leaves[index],
            siblings: siblings.into_iter().map(Digest::new).collect(),
            index_bits,
        })
    }

    /// Verify a membership proof against an issuer's current root, emitting an
    /// event with the outcome.
    ///
    /// # Errors
    /// Returns [`EngineError`] if the issuer is missing or a port fails.
    pub async fn verify_proof(
        &self,
        issuer_addr: &Pubkey,
        proof: &MerkleProof,
    ) -> Result<bool, EngineError> {
        let issuer = self.issuers.issuer(issuer_addr).await?;
        let siblings: Vec<[u8; 32]> = proof.siblings.iter().map(|d| d.0).collect();
        let valid = merkle::verify(
            proof.leaf.0,
            &siblings,
            proof.index_bits,
            issuer.merkle_root.0,
        );
        self.events
            .publish(AttestationEvent::ProofVerified {
                issuer: *issuer_addr,
                valid,
            })
            .await;
        Ok(valid)
    }

    /// Aggregate identity-service statistics.
    ///
    /// # Errors
    /// Returns [`EngineError`] on port failure.
    pub async fn stats(&self) -> Result<IdentityStats, EngineError> {
        let identities = self.identities.all_identities().await?;
        let issuers = self.issuers.all_issuers().await?;
        let passkeys = identities.iter().map(|i| i.passkeys.len() as u64).sum();
        let attestations = identities.iter().map(|i| i.attestations.len() as u64).sum();
        Ok(IdentityStats {
            identities: identities.len() as u64,
            issuers: issuers.len() as u64,
            passkeys,
            attestations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::PortError;
    use async_trait::async_trait;
    use passkeyauth_types::AttestationView;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemIdentities(Mutex<Vec<IdentityView>>);
    #[async_trait]
    impl IdentityStore for MemIdentities {
        async fn all_identities(&self) -> Result<Vec<IdentityView>, PortError> {
            Ok(self.0.lock().unwrap().clone())
        }
        async fn identity(&self, address: &Pubkey) -> Result<IdentityView, PortError> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .find(|i| &i.address == address)
                .cloned()
                .ok_or(PortError::NotFound)
        }
        async fn upsert_identity(&self, identity: IdentityView) -> Result<(), PortError> {
            let mut g = self.0.lock().unwrap();
            g.retain(|i| i.address != identity.address);
            g.push(identity);
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemIssuers(Mutex<Vec<IssuerView>>);
    #[async_trait]
    impl IssuerStore for MemIssuers {
        async fn all_issuers(&self) -> Result<Vec<IssuerView>, PortError> {
            Ok(self.0.lock().unwrap().clone())
        }
        async fn issuer(&self, address: &Pubkey) -> Result<IssuerView, PortError> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .find(|i| &i.address == address)
                .cloned()
                .ok_or(PortError::NotFound)
        }
        async fn upsert_issuer(&self, issuer: IssuerView) -> Result<(), PortError> {
            let mut g = self.0.lock().unwrap();
            g.retain(|i| i.address != issuer.address);
            g.push(issuer);
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemTrees(Mutex<Vec<(Pubkey, Vec<Digest>)>>);
    #[async_trait]
    impl TreeStore for MemTrees {
        async fn put_leaves(&self, issuer: Pubkey, leaves: Vec<Digest>) -> Result<(), PortError> {
            let mut g = self.0.lock().unwrap();
            g.retain(|(k, _)| k != &issuer);
            g.push((issuer, leaves));
            Ok(())
        }
        async fn get_leaves(&self, issuer: &Pubkey) -> Result<Vec<Digest>, PortError> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .find(|(k, _)| k == issuer)
                .map(|(_, v)| v.clone())
                .ok_or(PortError::NotFound)
        }
    }

    #[derive(Default)]
    struct NullSink;
    #[async_trait]
    impl EventSink for NullSink {
        async fn publish(&self, _event: AttestationEvent) {}
    }

    fn engine() -> IdentityEngine {
        IdentityEngine::new(
            Arc::new(MemIdentities::default()),
            Arc::new(MemIssuers::default()),
            Arc::new(MemTrees::default()),
            Arc::new(NullSink),
            EngineConfig::default(),
        )
    }

    fn issuer(addr: u8) -> IssuerView {
        IssuerView {
            address: Pubkey::new([addr; 32]),
            authority: Pubkey::new([2; 32]),
            schema_id: Digest::new([3; 32]),
            merkle_root: Digest::zero(),
            attestation_count: 0,
        }
    }

    #[tokio::test]
    async fn build_prove_and_verify() {
        let e = engine();
        let addr = Pubkey::new([5; 32]);
        e.ingest_issuer(issuer(5)).await.unwrap();

        let leaves: Vec<Digest> = (1..=4).map(|b| Digest::new([b; 32])).collect();
        let root = e.build_tree(&addr, leaves.clone()).await.unwrap();
        assert_ne!(root, Digest::zero());

        let proof = e.prove(&addr, 2).await.unwrap();
        assert_eq!(proof.leaf, leaves[2]);
        assert!(e.verify_proof(&addr, &proof).await.unwrap());

        // Tamper with the leaf → verification fails.
        let mut bad = proof.clone();
        bad.leaf = Digest::new([9; 32]);
        assert!(!e.verify_proof(&addr, &bad).await.unwrap());
    }

    #[tokio::test]
    async fn stats_count_passkeys_and_attestations() {
        let e = engine();
        e.ingest_identity(IdentityView {
            address: Pubkey::new([1; 32]),
            owner: Pubkey::new([2; 32]),
            passkeys: vec![],
            attestations: vec![AttestationView {
                issuer: Pubkey::new([5; 32]),
                schema_id: Digest::new([3; 32]),
                claimed_ts: 0,
            }],
        })
        .await
        .unwrap();
        e.ingest_issuer(issuer(5)).await.unwrap();
        let s = e.stats().await.unwrap();
        assert_eq!(s.identities, 1);
        assert_eq!(s.issuers, 1);
        assert_eq!(s.attestations, 1);
    }

    #[tokio::test]
    async fn prove_out_of_range_errors() {
        let e = engine();
        let addr = Pubkey::new([7; 32]);
        e.ingest_issuer(issuer(7)).await.unwrap();
        e.build_tree(&addr, vec![Digest::new([1; 32])])
            .await
            .unwrap();
        assert!(matches!(
            e.prove(&addr, 5).await,
            Err(EngineError::LeafOutOfRange(5))
        ));
    }
}
