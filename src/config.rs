use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct ProxyConfig {
    pub listen: ListenConfig,
    /// Protocol variant: "thales_payshield" or "futurex_excrypt"
    pub vendor: String,
    pub aws: AwsConfig,
    /// Maps legacy key identifiers (label or LMK-encrypted hex) to APC key ARNs.
    #[serde(default)]
    pub key_mappings: HashMap<String, String>,
    /// Optional discovery / passthrough configuration.
    pub discover: Option<DiscoverConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// TLS configuration. Omit for plaintext (development only).
    pub tls: Option<TlsConfig>,
}

/// TLS configuration for the inbound listener.
///
/// Provide cert_file + key_file for server-side TLS.
/// Add ca_file to additionally require client certificates (mTLS).
///
/// For FIPS-compliant TLS, replace the `ring` feature in Cargo.toml with
/// `aws-lc-rs` and recompile.
#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// PEM file containing the server certificate chain (leaf first).
    pub cert_file: PathBuf,
    /// PEM file containing the server private key (PKCS8, RSA, or EC).
    pub key_file: PathBuf,
    /// PEM file containing the CA that signs client certs. Enables mTLS when present.
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    /// Named AWS credential profile. Omit to use the default chain (IAM role, env, instance metadata).
    pub profile: Option<String>,
}

/// Discovery / passthrough mode.
///
/// When enabled, commands with no registered handler are forwarded to the
/// real HSM rather than returning error 68. The command code and safe
/// parameters are logged; sensitive fields (key blocks, PIN blocks) are
/// redacted. Use this to build a map of what commands your application
/// actually uses before writing plugins for them.
#[derive(Debug, Deserialize)]
pub struct DiscoverConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Hostname or IP of the real HSM to forward unhandled commands to.
    pub hsm_host: String,
    pub hsm_port: u16,
    /// Path to write the structured discovery log (NDJSON). Each unique command
    /// code is written once. Safe to feed directly to Claude Code as source context.
    pub log_file: Option<PathBuf>,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}
fn default_port() -> u16 {
    1500
}

impl ProxyConfig {
    pub fn from_yaml(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&content)?)
    }
}
