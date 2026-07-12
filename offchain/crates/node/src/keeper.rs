//! Keeper watchers: background loops that poll the data source to mirror
//! identity/issuer state and periodically publish statistics.

use std::sync::Arc;
use std::time::Duration;

use metrics::{counter, gauge};
use passkeyauth_core::ports::DataSource;
use passkeyauth_core::IdentityEngine;
use tokio::task::JoinHandle;
use tracing::warn;

/// Poll the data source once and mirror identities + issuers into the engine.
///
/// # Errors
/// Propagates engine errors so callers can record failures.
pub async fn poll_once(
    engine: &IdentityEngine,
    source: &dyn DataSource,
) -> Result<usize, passkeyauth_core::EngineError> {
    let identities = source
        .poll_identities()
        .await
        .map_err(passkeyauth_core::EngineError::from)?;
    let issuers = source
        .poll_issuers()
        .await
        .map_err(passkeyauth_core::EngineError::from)?;
    let n = identities.len() + issuers.len();
    for identity in identities {
        engine.ingest_identity(identity).await?;
    }
    for issuer in issuers {
        engine.ingest_issuer(issuer).await?;
    }
    counter!("passkeyauth_poll_total").increment(1);
    Ok(n)
}

/// Publish statistics once (identities, issuers, passkeys, attestations).
///
/// # Errors
/// Propagates engine errors.
pub async fn scan_once(engine: &IdentityEngine) -> Result<(), passkeyauth_core::EngineError> {
    let stats = engine.stats().await?;
    gauge!("passkeyauth_identities").set(stats.identities as f64);
    gauge!("passkeyauth_issuers").set(stats.issuers as f64);
    gauge!("passkeyauth_passkeys").set(stats.passkeys as f64);
    gauge!("passkeyauth_attestations").set(stats.attestations as f64);
    counter!("passkeyauth_scan_total").increment(1);
    Ok(())
}

/// Spawn the poller and scanner loops; they run until the tasks are aborted.
#[must_use]
pub fn spawn_keepers(
    engine: IdentityEngine,
    source: Arc<dyn DataSource>,
    poll_interval: Duration,
    scan_interval: Duration,
) -> Vec<JoinHandle<()>> {
    let poll_engine = engine.clone();
    let poller = tokio::spawn(async move {
        let mut tick = tokio::time::interval(poll_interval);
        loop {
            tick.tick().await;
            if let Err(e) = poll_once(&poll_engine, source.as_ref()).await {
                warn!(error = %e, "poll cycle failed");
                counter!("passkeyauth_poll_errors_total").increment(1);
            }
        }
    });

    let scanner = tokio::spawn(async move {
        let mut tick = tokio::time::interval(scan_interval);
        loop {
            tick.tick().await;
            if let Err(e) = scan_once(&engine).await {
                warn!(error = %e, "scan cycle failed");
                counter!("passkeyauth_scan_errors_total").increment(1);
            }
        }
    });

    vec![poller, scanner]
}

#[cfg(test)]
mod tests {
    use super::*;
    use passkeyauth_core::EngineConfig;
    use passkeyauth_infra::{
        BroadcastBus, InMemoryIdentityStore, InMemoryIssuerStore, InMemoryTreeStore, SimDataSource,
    };

    #[tokio::test]
    async fn poll_then_scan() {
        let bus = Arc::new(BroadcastBus::new(16));
        let engine = IdentityEngine::new(
            Arc::new(InMemoryIdentityStore::new()),
            Arc::new(InMemoryIssuerStore::new()),
            Arc::new(InMemoryTreeStore::new()),
            bus.clone(),
            EngineConfig::default(),
        );
        let source = SimDataSource::new();
        assert_eq!(poll_once(&engine, &source).await.unwrap(), 2);
        scan_once(&engine).await.unwrap();
        assert_eq!(engine.identities_snapshot().await.unwrap().len(), 1);
    }
}
