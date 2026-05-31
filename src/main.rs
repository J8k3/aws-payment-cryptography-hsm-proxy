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
#[cfg(test)]
mod tests;
mod verify;

#[derive(Parser)]
#[command(
    name = "apc-proxy",
    about = "Thales payShield 10K and Futurex Excrypt → AWS Payment Cryptography protocol proxy",
    long_about = "Listens for legacy HSM host commands on a TCP port and translates \
                  them to AWS Payment Cryptography API calls, returning vendor-compatible \
                  responses. Supports Thales payShield 10K and Futurex Excrypt Enterprise SSP v.2 \
                  host command protocols."
)]
struct Cli {
    /// Path to proxy.yaml configuration file
    #[arg(short, long, default_value = "proxy.yaml")]
    config: PathBuf,
    /// Validate the config against APC without starting the listener.
    /// Prints a report and exits 0 if every key_mappings entry resolves to
    /// a CREATE_COMPLETE, enabled APC key; non-zero on any failure.
    #[arg(long)]
    verify_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = config::ProxyConfig::from_yaml(&cli.config)?;

    // In verify-only mode keep the log level at warn so the report stays
    // readable; the verify pass prints its own structured output.
    let default_filter = if cli.verify_only {
        "apc_proxy=warn"
    } else {
        "apc_proxy=info"
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter)),
        )
        .init();

    if cli.verify_only {
        let ok = verify::run(&cfg).await?;
        std::process::exit(i32::from(!ok));
    }

    info!(
        vendor = %cfg.vendor,
        host = %cfg.listen.host,
        port = cfg.listen.port,
        region = %cfg.aws.region,
        "apc-proxy starting"
    );

    server::run(cfg).await
}
