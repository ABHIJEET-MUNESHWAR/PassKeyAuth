//! Node configuration from CLI flags and environment variables.

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;

/// Runtime configuration for the PassKeyAuth identity node.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "passkeyauth-node",
    about = "PassKeyAuth off-chain identity service"
)]
pub struct NodeConfig {
    /// Address the HTTP/GraphQL server binds to.
    #[arg(long, env = "PASSKEYAUTH_BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,

    /// Data-source poll interval in milliseconds (identity/issuer indexing).
    #[arg(long, env = "PASSKEYAUTH_POLL_MS", default_value_t = 1_000)]
    pub poll_ms: u64,

    /// Statistics scan interval in milliseconds.
    #[arg(long, env = "PASSKEYAUTH_SCAN_MS", default_value_t = 2_000)]
    pub scan_ms: u64,

    /// Request timeout in milliseconds.
    #[arg(long, env = "PASSKEYAUTH_REQUEST_TIMEOUT_MS", default_value_t = 5_000)]
    pub request_timeout_ms: u64,

    /// Broadcast bus capacity.
    #[arg(long, env = "PASSKEYAUTH_BUS_CAPACITY", default_value_t = 1_024)]
    pub bus_capacity: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".parse().expect("valid default addr"),
            poll_ms: 1_000,
            scan_ms: 2_000,
            request_timeout_ms: 5_000,
            bus_capacity: 1_024,
        }
    }
}

impl NodeConfig {
    /// The configured poll interval.
    #[must_use]
    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_ms)
    }

    /// The configured scan interval.
    #[must_use]
    pub fn scan_interval(&self) -> Duration {
        Duration::from_millis(self.scan_ms)
    }

    /// The configured request timeout.
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = NodeConfig::default();
        assert_eq!(c.poll_interval(), Duration::from_millis(1_000));
        assert_eq!(c.scan_interval(), Duration::from_millis(2_000));
    }

    #[test]
    fn parses_from_args() {
        let c = NodeConfig::try_parse_from(["passkeyauth-node", "--poll-ms", "250"]).unwrap();
        assert_eq!(c.poll_ms, 250);
    }
}
