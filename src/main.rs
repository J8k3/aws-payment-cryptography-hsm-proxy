use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

mod config;
mod error;
mod handlers;
mod key_map;
mod protocol;
mod server;

#[derive(Parser)]
#[command(
    name = "apc-proxy",
    about = "Thales payShield → AWS Payment Cryptography protocol proxy",
    long_about = "Listens for legacy HSM host commands on a TCP port and translates \
                  them to AWS Payment Cryptography API calls, returning vendor-compatible \
                  responses. Supports Thales payShield 10K host command protocol."
)]
struct Cli {
    /// Path to proxy.yaml configuration file
    #[arg(short, long, default_value = "proxy.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("apc_proxy=info")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = config::ProxyConfig::from_yaml(&cli.config)?;

    info!(
        vendor = %cfg.vendor,
        host = %cfg.listen.host,
        port = cfg.listen.port,
        region = %cfg.aws.region,
        "apc-proxy starting"
    );

    server::run(cfg).await
}
