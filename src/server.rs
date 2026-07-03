use anyhow::Result;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::config::{DiscoverConfig, ProxyConfig, TlsConfig};
use crate::handlers::{AppState, Registry};
use crate::hsm_client::{default_crypto_provider, forward_to_hsm};
use crate::key_map::KeyMap;
use crate::protocol::{futurex::FuturexExcrypt, thales::ThalesPayShield, Protocol};

/// Writes a structured NDJSON discovery log. Each unique command code is written once,
/// so the file stays small and is immediately usable as context in an AI coding session.
struct DiscoveryLog {
    writer: Mutex<BufWriter<File>>,
    seen: Mutex<HashSet<String>>,
    vendor: String,
}

impl DiscoveryLog {
    fn open(path: &std::path::Path, vendor: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| anyhow::anyhow!("opening discovery log {}: {e}", path.display()))?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
            seen: Mutex::new(HashSet::new()),
            vendor: vendor.to_string(),
        })
    }

    fn record_futurex(
        &self,
        command_code: &[u8],
        params: &std::collections::HashMap<[u8; 2], Vec<u8>>,
    ) {
        let cmd = String::from_utf8_lossy(command_code).to_string();
        if !self
            .seen
            .lock()
            .expect("mutex poisoned")
            .insert(cmd.clone())
        {
            return; // already logged this command code
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let param_map = crate::protocol::futurex::params_redacted_map(params);
        let record = serde_json::json!({
            "ts": ts,
            "vendor": self.vendor,
            "cmd": cmd,
            "params": param_map,
        });
        if let Ok(mut w) = self.writer.lock() {
            let _ = writeln!(w, "{record}");
            let _ = w.flush();
        }
    }

    fn record_thales(&self, command_code: &[u8], payload_len: usize) {
        let cmd = String::from_utf8_lossy(command_code).to_string();
        if !self
            .seen
            .lock()
            .expect("mutex poisoned")
            .insert(cmd.clone())
        {
            return;
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let record = serde_json::json!({
            "ts": ts,
            "vendor": self.vendor,
            "cmd": cmd,
            "payload_len": payload_len,
            "note": "Thales fields are positional and command-specific; payload not parsed in discovery mode",
        });
        if let Ok(mut w) = self.writer.lock() {
            let _ = writeln!(w, "{record}");
            let _ = w.flush();
        }
    }
}

pub async fn run(cfg: ProxyConfig) -> Result<()> {
    let mut aws_builder = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(cfg.aws.region.clone()));
    if let Some(ref profile) = cfg.aws.profile {
        aws_builder = aws_builder.profile_name(profile);
    }
    let aws_cfg = aws_builder.load().await;

    if let Some(provider) = aws_cfg.credentials_provider() {
        use aws_credential_types::provider::ProvideCredentials;
        match provider.provide_credentials().await {
            Ok(creds) if creds.expiry().is_none() => {
                warn!(
                    "AWS credentials have no expiry — long-lived IAM user keys detected. \
                     Use an IAM role (instance profile, ECS task role) in production."
                );
            }
            Ok(_) => {}
            Err(e) => {
                warn!(err = %e, "could not pre-resolve AWS credentials at startup; calls will fail if credentials are unavailable");
            }
        }
    }

    let mut key_map = KeyMap::new(cfg.key_mappings.clone());
    let control_client = aws_sdk_paymentcryptography::Client::new(&aws_cfg);
    if let Err(e) = key_map.scan_apc(&control_client).await {
        warn!(err = %e, "APC key inventory scan failed; wrapped key block resolution unavailable");
    }

    let state = Arc::new(AppState {
        key_map,
        data: aws_sdk_paymentcryptographydata::Client::new(&aws_cfg),
    });

    let registry = Arc::new(Registry::build());

    let protocol: Arc<dyn Protocol> = match cfg.vendor.as_str() {
        "thales_payshield" => Arc::new(ThalesPayShield),
        "futurex_excrypt" => Arc::new(FuturexExcrypt),
        other => anyhow::bail!("unknown vendor: {other}"),
    };

    let tls_acceptor: Option<tokio_rustls::TlsAcceptor> = cfg
        .listen
        .tls
        .as_ref()
        .map(build_tls_config)
        .transpose()?
        .map(|sc| tokio_rustls::TlsAcceptor::from(Arc::new(sc)));

    let discovery_log: Option<Arc<DiscoveryLog>> = cfg
        .discover
        .as_ref()
        .and_then(|d| d.log_file.as_deref())
        .and_then(|path| match DiscoveryLog::open(path, &cfg.vendor) {
            Ok(dl) => {
                info!(path = %path.display(), "discovery log opened");
                Some(Arc::new(dl))
            }
            Err(e) => {
                warn!(err = %e, "could not open discovery log; commands will not be persisted to file");
                None
            }
        });

    let discover = cfg.discover.map(Arc::new);

    let addr = format!("{}:{}", cfg.listen.host, cfg.listen.port);
    let listener = TcpListener::bind(&addr).await?;

    let mode = match &cfg.listen.tls {
        Some(t) if t.ca_file.is_some() => "mTLS",
        Some(_) => "TLS",
        None => "plaintext",
    };
    let disc_mode = if discover.as_ref().is_some_and(|d| d.enabled) {
        "discovery+passthrough"
    } else {
        "proxy"
    };
    info!(addr = %addr, vendor = %cfg.vendor, %mode, %disc_mode, "proxy listening");

    loop {
        let (socket, peer) = listener.accept().await?;
        info!(%peer, "connection accepted");

        let state = Arc::clone(&state);
        let registry = Arc::clone(&registry);
        let protocol = Arc::clone(&protocol);
        let tls_acceptor = tls_acceptor.clone();
        let discover = discover.clone();

        let discovery_log = discovery_log.clone();
        tokio::spawn(async move {
            let result = if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(socket).await {
                    Ok(stream) => {
                        handle_connection(
                            stream,
                            state,
                            registry,
                            protocol,
                            discover,
                            discovery_log,
                        )
                        .await
                    }
                    Err(e) => {
                        error!(%peer, err = %e, "TLS handshake failed");
                        return;
                    }
                }
            } else {
                handle_connection(socket, state, registry, protocol, discover, discovery_log).await
            };

            if let Err(e) = result {
                error!(%peer, err = %e, "connection error");
            }
            debug!(%peer, "connection closed");
        });
    }
}

fn build_tls_config(tls: &TlsConfig) -> Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;

    let provider = default_crypto_provider();

    let cert_chain: Vec<CertificateDer<'static>> = certs(&mut BufReader::new(
        File::open(&tls.cert_file)
            .map_err(|e| anyhow::anyhow!("opening cert_file {}: {e}", tls.cert_file.display()))?,
    ))
    .collect::<Result<_, _>>()
    .map_err(|e| anyhow::anyhow!("parsing cert_file: {e}"))?;

    let key_der: PrivateKeyDer<'static> = private_key(&mut BufReader::new(
        File::open(&tls.key_file)
            .map_err(|e| anyhow::anyhow!("opening key_file {}: {e}", tls.key_file.display()))?,
    ))
    .map_err(|e| anyhow::anyhow!("parsing key_file: {e}"))?
    .ok_or_else(|| anyhow::anyhow!("no private key found in {}", tls.key_file.display()))?;

    if let Some(ca_path) = &tls.ca_file {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in certs(&mut BufReader::new(File::open(ca_path).map_err(|e| {
            anyhow::anyhow!("opening ca_file {}: {e}", ca_path.display())
        })?)) {
            root_store
                .add(cert.map_err(|e| anyhow::anyhow!("reading CA cert: {e}"))?)
                .map_err(|e| anyhow::anyhow!("adding CA cert to store: {e}"))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(root_store),
            provider.clone(),
        )
        .build()
        .map_err(|e| anyhow::anyhow!("building mTLS client verifier: {e}"))?;

        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("TLS protocol versions: {e}"))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key_der)
            .map_err(|e| anyhow::anyhow!("building TLS server config: {e}"))
    } else {
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("TLS protocol versions: {e}"))?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .map_err(|e| anyhow::anyhow!("building TLS server config: {e}"))
    }
}

/// Maximum bytes buffered for a single not-yet-parsed inbound frame before the
/// connection is closed. A well-formed Thales frame is at most 2 + u16::MAX =
/// 65_537 bytes; Futurex host-command frames are far smaller. 256 KiB is ~4x
/// the largest possible valid frame — ample headroom for any real command while
/// still bounding the memory one connection can consume (see the OOM path this
/// guards against). Not a config knob on purpose: it is a safety limit, not a
/// tuning parameter.
const MAX_INBOUND_ACCUMULATION: usize = 256 * 1024;

async fn handle_connection<S>(
    mut socket: S,
    state: Arc<AppState>,
    registry: Arc<Registry>,
    protocol: Arc<dyn Protocol>,
    discover: Option<Arc<DiscoverConfig>>,
    discovery_log: Option<Arc<DiscoveryLog>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut read_buf = [0u8; 4096];

    loop {
        let n = socket.read(&mut read_buf).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&read_buf[..n]);

        // Cap unparsed accumulation. Both parsers drain every complete frame
        // each pass, so `buf` only carries a partial (incomplete) trailing
        // frame between reads. If it grows past the cap, either a frame is
        // larger than we will ever serve or the peer is streaming bytes that
        // never complete a frame (a Futurex stream with no closing ']', or a
        // Thales frame whose length prefix never resolves). Close the
        // connection rather than let one socket grow memory without bound.
        if buf.len() > MAX_INBOUND_ACCUMULATION {
            warn!(
                buffered = buf.len(),
                cap = MAX_INBOUND_ACCUMULATION,
                "inbound frame exceeds accumulation cap without completing; closing connection"
            );
            return Ok(());
        }

        loop {
            let Some(cmd) = protocol.parse(&buf) else {
                break;
            };
            let frame_len = cmd.frame_len;
            let header = cmd.header;
            let command_code = cmd.command_code.clone();
            let payload = cmd.payload.clone();

            debug!(
                cmd = %String::from_utf8_lossy(&command_code),
                len = payload.len(),
                "command received"
            );

            let t0 = std::time::Instant::now();
            let response_bytes = match registry.get(&command_code) {
                Some(handler) => {
                    let result = handler.handle(&command_code, &payload, &state).await;
                    info!(
                        cmd = %String::from_utf8_lossy(&command_code),
                        error_code = %String::from_utf8_lossy(&result.error_code),
                        latency_us = t0.elapsed().as_micros(),
                        "command handled"
                    );
                    let rc = protocol.response_code(&command_code);
                    protocol.frame_response(header, &rc, &result.error_code, &result.payload)
                }
                None => {
                    // No handler registered for this command.
                    if let Some(ref dcfg) = discover {
                        if dcfg.enabled {
                            log_discovery_command(
                                &command_code,
                                &payload,
                                discovery_log.as_deref(),
                            );
                            match forward_to_hsm(&buf[..frame_len], dcfg, &*protocol).await {
                                Ok(resp) => resp,
                                Err(e) => {
                                    warn!(err = %e, "discovery forward failed, returning error");
                                    protocol.frame_error(header, &command_code, b"41")
                                }
                            }
                        } else {
                            warn!(cmd = %String::from_utf8_lossy(&command_code), "no handler registered");
                            protocol.frame_error(header, &command_code, b"68")
                        }
                    } else {
                        warn!(cmd = %String::from_utf8_lossy(&command_code), "no handler registered");
                        protocol.frame_error(header, &command_code, b"68")
                    }
                }
            };

            socket.write_all(&response_bytes).await?;
            buf.drain(..frame_len);
        }
    }
}

/// Log a command seen in discovery mode, redacting parameter values.
/// Writes to tracing and, if configured, to the structured NDJSON discovery log.
///
/// For Futurex: parameter codes and value lengths are logged; every value is
/// redacted (discovery fires on unmodeled commands, so no value is known safe).
/// For Thales: only command code and payload length are logged (field layout is positional
/// and command-specific, so field-level parsing is not attempted).
fn log_discovery_command(command_code: &[u8], payload: &[u8], log: Option<&DiscoveryLog>) {
    use crate::protocol::futurex::{parse_params, redact_for_log};

    let cmd = String::from_utf8_lossy(command_code);

    if command_code.len() == 4 {
        let params = parse_params(payload);
        let safe = redact_for_log(&params);
        info!(cmd = %cmd, params = %safe, "DISCOVERY: unhandled Futurex command");
        if let Some(dl) = log {
            dl.record_futurex(command_code, &params);
        }
    } else {
        info!(cmd = %cmd, payload_len = payload.len(), "DISCOVERY: unhandled Thales command");
        if let Some(dl) = log {
            dl.record_thales(command_code, payload.len());
        }
    }
}
