//! Runtime configuration for the identity engine and indexer watchers.

use std::time::Duration;

/// Tunable engine parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineConfig {
    /// Interval between data-source polls (identity/issuer indexing).
    pub poll_interval: Duration,
    /// Interval between statistics scans.
    pub scan_interval: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            scan_interval: Duration::from_secs(2),
        }
    }
}
