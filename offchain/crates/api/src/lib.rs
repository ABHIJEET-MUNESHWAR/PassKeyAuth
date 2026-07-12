//! # passkeyauth-api — GraphQL surface for the identity / attestation service
//!
//! Exposes mirrored identities and issuers, aggregate stats, Merkle
//! tree-building, proof generation, and on-chain-accurate proof verification,
//! plus a live event subscription. Built with `async-graphql` (depth/complexity
//! limited); wired to axum in the node.
#![forbid(unsafe_code)]

use std::sync::Arc;

use async_graphql::{
    Context, Error as GqlError, InputObject, Object, Result as GqlResult, Schema, SimpleObject,
    Subscription,
};
use futures::Stream;
use passkeyauth_core::events::AttestationEvent;
use passkeyauth_core::ports::EventStream;
use passkeyauth_core::IdentityEngine;
use passkeyauth_types::{
    Digest, IdentityStats, IdentityView, IssuerView, MerkleProof, Pubkey,
};
use tokio_stream::StreamExt;

/// Shared GraphQL context: the engine plus the event stream port.
#[derive(Clone)]
pub struct GraphQlContext {
    /// Identity engine used by resolvers.
    pub engine: IdentityEngine,
    /// Event stream used by subscriptions.
    pub events: Arc<dyn EventStream>,
}

fn to_err<E: std::fmt::Display>(e: E) -> GqlError {
    GqlError::new(e.to_string())
}

fn parse_key(s: &str) -> GqlResult<Pubkey> {
    Pubkey::from_hex(s).map_err(to_err)
}

fn parse_digest(s: &str) -> GqlResult<Digest> {
    Digest::from_hex(s).map_err(to_err)
}

/// A passkey credential.
#[derive(SimpleObject)]
struct PassKeyDto {
    pubkey_hex: String,
    label: String,
    added_ts: i64,
}

/// A claimed attestation.
#[derive(SimpleObject)]
struct AttestationDto {
    issuer: String,
    schema_id: String,
    claimed_ts: i64,
}

/// An identity.
#[derive(SimpleObject)]
struct IdentityDto {
    address: String,
    owner: String,
    passkeys: Vec<PassKeyDto>,
    attestations: Vec<AttestationDto>,
}

impl From<IdentityView> for IdentityDto {
    fn from(i: IdentityView) -> Self {
        Self {
            address: i.address.to_hex(),
            owner: i.owner.to_hex(),
            passkeys: i
                .passkeys
                .into_iter()
                .map(|p| PassKeyDto {
                    pubkey_hex: p.pubkey_hex,
                    label: p.label,
                    added_ts: p.added_ts,
                })
                .collect(),
            attestations: i
                .attestations
                .into_iter()
                .map(|a| AttestationDto {
                    issuer: a.issuer.to_hex(),
                    schema_id: a.schema_id.to_hex(),
                    claimed_ts: a.claimed_ts,
                })
                .collect(),
        }
    }
}

/// An attestation issuer.
#[derive(SimpleObject)]
struct IssuerDto {
    address: String,
    authority: String,
    schema_id: String,
    merkle_root: String,
    attestation_count: String,
}

impl From<IssuerView> for IssuerDto {
    fn from(i: IssuerView) -> Self {
        Self {
            address: i.address.to_hex(),
            authority: i.authority.to_hex(),
            schema_id: i.schema_id.to_hex(),
            merkle_root: i.merkle_root.to_hex(),
            attestation_count: i.attestation_count.to_string(),
        }
    }
}

/// Aggregate statistics.
#[derive(SimpleObject)]
struct StatsDto {
    identities: String,
    issuers: String,
    passkeys: String,
    attestations: String,
}

impl From<IdentityStats> for StatsDto {
    fn from(s: IdentityStats) -> Self {
        Self {
            identities: s.identities.to_string(),
            issuers: s.issuers.to_string(),
            passkeys: s.passkeys.to_string(),
            attestations: s.attestations.to_string(),
        }
    }
}

/// A Merkle membership proof.
#[derive(SimpleObject)]
struct ProofDto {
    leaf: String,
    siblings: Vec<String>,
    index_bits: String,
}

impl From<MerkleProof> for ProofDto {
    fn from(p: MerkleProof) -> Self {
        Self {
            leaf: p.leaf.to_hex(),
            siblings: p.siblings.iter().map(Digest::to_hex).collect(),
            index_bits: p.index_bits.to_string(),
        }
    }
}

/// A flattened attestation event for subscription delivery.
#[derive(SimpleObject, Clone)]
struct AttestationEventDto {
    kind: String,
    subject: String,
    root: Option<String>,
    valid: Option<bool>,
    count: Option<u32>,
}

impl From<AttestationEvent> for AttestationEventDto {
    fn from(e: AttestationEvent) -> Self {
        match e {
            AttestationEvent::IdentityIndexed {
                identity,
                passkeys,
                attestations,
            } => Self {
                kind: "identity_indexed".into(),
                subject: identity.to_hex(),
                root: None,
                valid: None,
                count: Some(passkeys + attestations),
            },
            AttestationEvent::IssuerIndexed { issuer, root } => Self {
                kind: "issuer_indexed".into(),
                subject: issuer.to_hex(),
                root: Some(root.to_hex()),
                valid: None,
                count: None,
            },
            AttestationEvent::TreeBuilt {
                issuer,
                root,
                leaf_count,
            } => Self {
                kind: "tree_built".into(),
                subject: issuer.to_hex(),
                root: Some(root.to_hex()),
                valid: None,
                count: Some(leaf_count),
            },
            AttestationEvent::ProofVerified { issuer, valid } => Self {
                kind: "proof_verified".into(),
                subject: issuer.to_hex(),
                root: None,
                valid: Some(valid),
                count: None,
            },
        }
    }
}

/// Root query.
pub struct Query;

#[Object]
impl Query {
    /// All mirrored identities.
    async fn identities(&self, ctx: &Context<'_>) -> GqlResult<Vec<IdentityDto>> {
        let c = ctx.data::<GraphQlContext>()?;
        Ok(c.engine
            .identities_snapshot()
            .await
            .map_err(to_err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// A single identity by address (hex).
    async fn identity(&self, ctx: &Context<'_>, address: String) -> GqlResult<IdentityDto> {
        let c = ctx.data::<GraphQlContext>()?;
        Ok(c.engine
            .identity(&parse_key(&address)?)
            .await
            .map_err(to_err)?
            .into())
    }

    /// All mirrored issuers.
    async fn issuers(&self, ctx: &Context<'_>) -> GqlResult<Vec<IssuerDto>> {
        let c = ctx.data::<GraphQlContext>()?;
        Ok(c.engine
            .issuers_snapshot()
            .await
            .map_err(to_err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Aggregate statistics.
    async fn stats(&self, ctx: &Context<'_>) -> GqlResult<StatsDto> {
        let c = ctx.data::<GraphQlContext>()?;
        Ok(c.engine.stats().await.map_err(to_err)?.into())
    }

    /// Generate a membership proof for the leaf at `index` in an issuer's tree.
    async fn proof(&self, ctx: &Context<'_>, issuer: String, index: u32) -> GqlResult<ProofDto> {
        let c = ctx.data::<GraphQlContext>()?;
        Ok(c.engine
            .prove(&parse_key(&issuer)?, index as usize)
            .await
            .map_err(to_err)?
            .into())
    }
}

/// Input for building an issuer's eligible-set tree.
#[derive(InputObject)]
struct BuildTreeInput {
    /// The issuer PDA address (hex).
    issuer: String,
    /// The ordered leaf commitments (each a 32-byte hex digest).
    leaves: Vec<String>,
}

/// Input for verifying a membership proof.
#[derive(InputObject)]
struct VerifyProofInput {
    /// The issuer PDA address (hex).
    issuer: String,
    /// The leaf digest (hex).
    leaf: String,
    /// The sibling digests (hex), leaf → root.
    siblings: Vec<String>,
    /// The direction bits.
    index_bits: u64,
}

/// Root mutation.
pub struct Mutation;

#[Object]
impl Mutation {
    /// Ingest an issuer snapshot (demo/testing).
    async fn ingest_issuer(
        &self,
        ctx: &Context<'_>,
        address: String,
        authority: String,
        schema_id: String,
    ) -> GqlResult<IssuerDto> {
        let c = ctx.data::<GraphQlContext>()?;
        let issuer = IssuerView {
            address: parse_key(&address)?,
            authority: parse_key(&authority)?,
            schema_id: parse_digest(&schema_id)?,
            merkle_root: Digest::zero(),
            attestation_count: 0,
        };
        c.engine.ingest_issuer(issuer.clone()).await.map_err(to_err)?;
        Ok(issuer.into())
    }

    /// Build (or rebuild) an issuer's Merkle tree; returns the new root.
    async fn build_tree(&self, ctx: &Context<'_>, input: BuildTreeInput) -> GqlResult<String> {
        let c = ctx.data::<GraphQlContext>()?;
        let leaves = input
            .leaves
            .iter()
            .map(|s| parse_digest(s))
            .collect::<GqlResult<Vec<_>>>()?;
        let root = c
            .engine
            .build_tree(&parse_key(&input.issuer)?, leaves)
            .await
            .map_err(to_err)?;
        Ok(root.to_hex())
    }

    /// Verify a membership proof against an issuer's current root.
    async fn verify_proof(&self, ctx: &Context<'_>, input: VerifyProofInput) -> GqlResult<bool> {
        let c = ctx.data::<GraphQlContext>()?;
        let siblings = input
            .siblings
            .iter()
            .map(|s| parse_digest(s))
            .collect::<GqlResult<Vec<_>>>()?;
        let proof = MerkleProof {
            leaf: parse_digest(&input.leaf)?,
            siblings,
            index_bits: input.index_bits,
        };
        c.engine
            .verify_proof(&parse_key(&input.issuer)?, &proof)
            .await
            .map_err(to_err)
    }
}

/// Root subscription.
pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
    /// Live stream of attestation events.
    async fn attestation_events(
        &self,
        ctx: &Context<'_>,
    ) -> impl Stream<Item = AttestationEventDto> + 'static {
        let stream: futures::stream::BoxStream<'static, AttestationEvent> =
            match ctx.data::<GraphQlContext>() {
                Ok(c) => c.events.subscribe(),
                Err(_) => Box::pin(futures::stream::empty()),
            };
        stream.map(AttestationEventDto::from)
    }
}

/// The concrete schema type.
pub type IdentitySchema = Schema<Query, Mutation, SubscriptionRoot>;

/// Build the schema with depth and complexity limits and injected context.
#[must_use]
pub fn build_schema(ctx: GraphQlContext) -> IdentitySchema {
    Schema::build(Query, Mutation, SubscriptionRoot)
        .limit_depth(12)
        .limit_complexity(512)
        .data(ctx)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_graphql::Request as GqlRequest;
    use passkeyauth_core::EngineConfig;
    use passkeyauth_infra::{
        BroadcastBus, InMemoryIdentityStore, InMemoryIssuerStore, InMemoryTreeStore,
    };

    fn schema() -> IdentitySchema {
        let bus = Arc::new(BroadcastBus::new(16));
        let engine = IdentityEngine::new(
            Arc::new(InMemoryIdentityStore::new()),
            Arc::new(InMemoryIssuerStore::new()),
            Arc::new(InMemoryTreeStore::new()),
            bus.clone(),
            EngineConfig::default(),
        );
        build_schema(GraphQlContext { engine, events: bus })
    }

    #[tokio::test]
    async fn stats_query_executes() {
        let res = schema()
            .execute(GqlRequest::new("{ stats { identities issuers } }"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }

    #[tokio::test]
    async fn ingest_build_and_verify() {
        let s = schema();
        let issuer = "ee".repeat(32);
        let key = "11".repeat(32);
        let schema_id = "07".repeat(32);
        let ingest = format!(
            "mutation {{ ingestIssuer(address: \"{issuer}\", authority: \"{key}\", schemaId: \"{schema_id}\") {{ address }} }}"
        );
        assert!(s.execute(GqlRequest::new(ingest)).await.errors.is_empty());

        let l0 = "01".repeat(32);
        let l1 = "02".repeat(32);
        let build = format!(
            "mutation {{ buildTree(input: {{ issuer: \"{issuer}\", leaves: [\"{l0}\", \"{l1}\"] }}) }}"
        );
        let br = s.execute(GqlRequest::new(build)).await;
        assert!(br.errors.is_empty(), "{:?}", br.errors);

        let proof = format!("{{ proof(issuer: \"{issuer}\", index: 0) {{ leaf siblings indexBits }} }}");
        let pr = s.execute(GqlRequest::new(proof)).await;
        assert!(pr.errors.is_empty(), "{:?}", pr.errors);
    }
}
