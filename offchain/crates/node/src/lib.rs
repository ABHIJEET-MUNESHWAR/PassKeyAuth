//! # passkeyauth-node — composition root for the identity service
//!
//! Wires the in-memory adapters, identity engine, indexer keepers, and
//! GraphQL/HTTP surface together and serves them with graceful shutdown and
//! observability.
#![forbid(unsafe_code)]

pub mod config;
pub mod keeper;
pub mod startup;
pub mod telemetry;

use std::sync::Arc;

use passkeyauth_api::{build_schema, GraphQlContext};
use passkeyauth_core::{EngineConfig, IdentityEngine};
use passkeyauth_infra::{
    BroadcastBus, InMemoryIdentityStore, InMemoryIssuerStore, InMemoryTreeStore, SimDataSource,
};
use tracing::info;

pub use config::NodeConfig;

/// Build the fully-wired GraphQL schema and shared bus for a configuration.
#[must_use]
pub fn assemble(
    cfg: &NodeConfig,
) -> (
    passkeyauth_api::IdentitySchema,
    IdentityEngine,
    Arc<BroadcastBus>,
) {
    let bus = Arc::new(BroadcastBus::new(cfg.bus_capacity));
    let engine = IdentityEngine::new(
        Arc::new(InMemoryIdentityStore::new()),
        Arc::new(InMemoryIssuerStore::new()),
        Arc::new(InMemoryTreeStore::new()),
        bus.clone(),
        EngineConfig {
            poll_interval: cfg.poll_interval(),
            scan_interval: cfg.scan_interval(),
        },
    );
    let schema = build_schema(GraphQlContext {
        engine: engine.clone(),
        events: bus.clone(),
    });
    (schema, engine, bus)
}

/// Run the node: serve GraphQL/HTTP and drive keeper watchers until shutdown.
///
/// # Errors
/// Returns an error if the listener cannot bind or the server fails.
pub async fn run(cfg: NodeConfig) -> anyhow::Result<()> {
    let metrics = telemetry::install_metrics();
    let (schema, engine, _bus) = assemble(&cfg);

    let source = Arc::new(SimDataSource::new());
    let keepers = keeper::spawn_keepers(engine, source, cfg.poll_interval(), cfg.scan_interval());

    let app = startup::build_app(schema, metrics, cfg.request_timeout());
    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    info!(addr = %cfg.bind, "PassKeyAuth identity service listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(startup::shutdown_signal())
        .await?;

    for k in keepers {
        k.abort();
    }
    info!("shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_graphql::Request;

    #[tokio::test]
    async fn assemble_serves_queries() {
        let (schema, _engine, _bus) = assemble(&NodeConfig::default());
        let res = schema
            .execute(Request::new("{ stats { identities } }"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }
}
