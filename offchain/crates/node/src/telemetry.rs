//! Telemetry: structured JSON tracing + a Prometheus metrics recorder.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::{prelude::*, EnvFilter};

/// Initialise JSON tracing honoring `RUST_LOG` (idempotent-safe for bins).
pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt = tracing_subscriber::fmt::layer().json().with_target(true);
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        .try_init();
}

/// Install the global Prometheus recorder and return its scrape handle.
///
/// # Panics
/// Panics if a global recorder was already installed in this process.
#[must_use]
pub fn install_metrics() -> PrometheusHandle {
    PrometheusBuilder::new()
        .install_recorder()
        .expect("install prometheus recorder")
}

/// Build a Prometheus handle WITHOUT installing it globally (for tests).
#[must_use]
pub fn build_recorder() -> PrometheusHandle {
    PrometheusBuilder::new().build_recorder().handle()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_renders() {
        let handle = build_recorder();
        // Rendering an empty recorder yields a (possibly empty) string.
        let _ = handle.render();
    }
}
