//! Outbound client for talking to the real HSM — shared by the passthrough
//! forward leg (`server`), the `--verify-only` KCV cross-check (`hsm_probe`),
//! and, eventually, slot discovery (#13). This module owns "open a connection,
//! optionally TLS-wrap it, send one frame, read one complete response";
//! everything protocol- or command-specific stays with the caller.

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::config::{DiscoverConfig, ForwardTlsConfig};
use crate::protocol::Protocol;

/// A configured outbound HSM endpoint. Construction does all the one-time
/// work — reading and parsing the CA / client cert / key files and building
/// the rustls config — so repeated exchanges (e.g. one KCV probe per
/// `key_mappings` entry) don't re-read PEM files from disk on every call.
/// Each `exchange` still opens a fresh TCP connection (see #1 for pooling).
pub struct HsmClient {
    host: String,
    port: u16,
    read_timeout: Duration,
    tls: Option<(
        tokio_rustls::TlsConnector,
        rustls::pki_types::ServerName<'static>,
    )>,
}

impl HsmClient {
    /// Build a client from the operator's `discover` block. Fails if the TLS
    /// files are missing/unparseable or the server name is invalid — surfacing
    /// config problems once, at build time, rather than on every exchange.
    pub fn from_discover(cfg: &DiscoverConfig) -> Result<Self> {
        let tls = match &cfg.tls {
            None => None,
            Some(tls_cfg) => {
                let connector = build_forward_tls_connector(tls_cfg)?;
                let server_name_str = tls_cfg
                    .server_name
                    .as_deref()
                    .unwrap_or(cfg.hsm_host.as_str())
                    .to_string();
                let server_name = rustls::pki_types::ServerName::try_from(server_name_str)
                    .map_err(|e| anyhow::anyhow!("invalid server_name for forward TLS: {e}"))?;
                Some((connector, server_name))
            }
        };
        Ok(Self {
            host: cfg.hsm_host.clone(),
            port: cfg.hsm_port,
            read_timeout: Duration::from_secs(cfg.hsm_read_timeout_secs.unwrap_or(30)),
            tls,
        })
    }

    /// Send one frame and read until `protocol` says the response is complete
    /// (or the connection closes). Opens a fresh TCP connection per call.
    pub async fn exchange(&self, frame: &[u8], protocol: &dyn Protocol) -> Result<Vec<u8>> {
        let tcp = timeout(
            Duration::from_secs(10),
            TcpStream::connect((&*self.host, self.port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout connecting to real HSM {}:{}", self.host, self.port))?
        .map_err(|e| anyhow::anyhow!("connecting to real HSM {}:{}: {e}", self.host, self.port))?;

        match &self.tls {
            None => exchange_with_hsm(tcp, frame, self.read_timeout, protocol).await,
            Some((connector, server_name)) => {
                let tls_stream = timeout(
                    Duration::from_secs(10),
                    connector.connect(server_name.clone(), tcp),
                )
                .await
                .map_err(|_| anyhow::anyhow!("timeout during TLS handshake to real HSM"))?
                .map_err(|e| anyhow::anyhow!("TLS handshake to real HSM failed: {e}"))?;
                exchange_with_hsm(tls_stream, frame, self.read_timeout, protocol).await
            }
        }
    }
}

/// Forward a raw frame to the real HSM and return its response bytes —
/// one-shot convenience for the passthrough leg, which builds per call.
pub(crate) async fn forward_to_hsm(
    frame: &[u8],
    cfg: &DiscoverConfig,
    protocol: &dyn Protocol,
) -> Result<Vec<u8>> {
    HsmClient::from_discover(cfg)?
        .exchange(frame, protocol)
        .await
}

/// Send the frame, read until the protocol says the response is complete or
/// the connection closes. Generic over the stream type so the same logic
/// runs for plain TCP and TLS-wrapped TCP.
async fn exchange_with_hsm<S>(
    mut stream: S,
    frame: &[u8],
    read_timeout: Duration,
    protocol: &dyn Protocol,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(Duration::from_secs(10), stream.write_all(frame))
        .await
        .map_err(|_| anyhow::anyhow!("timeout sending to real HSM"))?
        .map_err(|e| anyhow::anyhow!("sending to real HSM: {e}"))?;

    let mut resp = Vec::with_capacity(4096);
    let mut buf = [0u8; 65536];
    loop {
        let n = timeout(read_timeout, stream.read(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("timeout reading from real HSM"))?
            .map_err(|e| anyhow::anyhow!("reading from real HSM: {e}"))?;
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
        if protocol.is_response_complete(&resp) {
            break;
        }
    }
    Ok(resp)
}

/// The crate's rustls crypto provider, selected by cargo feature. Shared with
/// the inbound listener's TLS setup in `server`.
pub(crate) fn default_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    #[cfg(feature = "ring")]
    return Arc::new(rustls::crypto::ring::default_provider());
    #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
    return Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
    compile_error!("one of features 'ring' or 'aws-lc-rs' must be enabled");
}

/// Build a `TlsConnector` for the outbound forward leg from the operator's
/// `ForwardTlsConfig`. Requires CA file; client cert + key are optional and
/// must be provided together when present (for mTLS).
fn build_forward_tls_connector(cfg: &ForwardTlsConfig) -> Result<tokio_rustls::TlsConnector> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;

    let provider = default_crypto_provider();

    let mut root_store = rustls::RootCertStore::empty();
    for cert in certs(&mut BufReader::new(File::open(&cfg.ca_file).map_err(
        |e| anyhow::anyhow!("opening ca_file {}: {e}", cfg.ca_file.display()),
    )?)) {
        root_store
            .add(cert.map_err(|e| anyhow::anyhow!("reading CA cert: {e}"))?)
            .map_err(|e| anyhow::anyhow!("adding CA cert to root store: {e}"))?;
    }

    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("forward TLS protocol versions: {e}"))?
        .with_root_certificates(root_store);

    let client_cfg = match (&cfg.client_cert_file, &cfg.client_key_file) {
        (Some(cert_path), Some(key_path)) => {
            let cert_chain: Vec<CertificateDer<'static>> =
                certs(&mut BufReader::new(File::open(cert_path).map_err(|e| {
                    anyhow::anyhow!("opening client_cert_file {}: {e}", cert_path.display())
                })?))
                .collect::<Result<_, _>>()
                .map_err(|e| anyhow::anyhow!("parsing client_cert_file: {e}"))?;
            let key_der: PrivateKeyDer<'static> =
                private_key(&mut BufReader::new(File::open(key_path).map_err(|e| {
                    anyhow::anyhow!("opening client_key_file {}: {e}", key_path.display())
                })?))
                .map_err(|e| anyhow::anyhow!("parsing client_key_file: {e}"))?
                .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;
            builder
                .with_client_auth_cert(cert_chain, key_der)
                .map_err(|e| anyhow::anyhow!("building forward mTLS client config: {e}"))?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => anyhow::bail!(
            "discover.tls: client_cert_file and client_key_file must be provided together"
        ),
    };

    Ok(tokio_rustls::TlsConnector::from(Arc::new(client_cfg)))
}
