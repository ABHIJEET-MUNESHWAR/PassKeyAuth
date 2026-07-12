//! Binary entry point for the PassKeyAuth identity-service node.
#![forbid(unsafe_code)]

use clap::Parser;
use passkeyauth_node::{config::NodeConfig, run, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    telemetry::init_tracing();
    let cfg = NodeConfig::parse();
    run(cfg).await
}
