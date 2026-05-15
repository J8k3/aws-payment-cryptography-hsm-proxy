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
            .map_err(|e| anyhow::anyhow!("opening discovery log {:?}: {e}", path))?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
            seen: Mutex::new(HashSet::new()),
            vendor: vendor.to_string(),
        })
    }

    fn record_futurex(&self, command_code: &[u8], params: &std::collections::HashMap<[u8; 2], Vec<u8>>) {
        let cmd = String::from_utf8_lossy(command_code).to_string();
        if !self.seen.lock().unwrap().insert(cmd.clone()) {
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
            let _ = writeln!(w, "{}", record);
            let _ = w.flush();
        }
    }

    fn record_thales(&self, command_code: &[u8], payload_len: usize) {
        let cmd = String::from_utf8_lossy(command_code).to_string();
        if !self.seen.lock().unwrap().insert(cmd.clone()) {
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
            let _ = writeln!(w, "{}", record);
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

    let state = Arc::new(AppState {
        key_map: KeyMap::new(cfg.key_mappings.clone()),
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
    let disc_mode = if discover.as_ref().map(|d| d.enabled).unwrap_or(false) {
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
                    Ok(stream) => handle_connection(stream, state, registry, protocol, discover, discovery_log).await,
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

fn default_crypto_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    #[cfg(feature = "ring")]
    return std::sync::Arc::new(rustls::crypto::ring::default_provider());
    #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
    return std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
    compile_error!("one of features 'ring' or 'aws-lc-rs' must be enabled");
}

fn build_tls_config(tls: &TlsConfig) -> Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;

    let provider = default_crypto_provider();

    let cert_chain: Vec<CertificateDer<'static>> =
        certs(&mut BufReader::new(File::open(&tls.cert_file).map_err(|e| {
            anyhow::anyhow!("opening cert_file {:?}: {e}", tls.cert_file)
        })?))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("parsing cert_file: {e}"))?;

    let key_der: PrivateKeyDer<'static> =
        private_key(&mut BufReader::new(File::open(&tls.key_file).map_err(|e| {
            anyhow::anyhow!("opening key_file {:?}: {e}", tls.key_file)
        })?))
        .map_err(|e| anyhow::anyhow!("parsing key_file: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {:?}", tls.key_file))?;

    if let Some(ca_path) = &tls.ca_file {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in certs(&mut BufReader::new(File::open(ca_path).map_err(|e| {
            anyhow::anyhow!("opening ca_file {:?}: {e}", ca_path)
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

        loop {
            let cmd = match protocol.parse(&buf) {
                Some(c) => c,
                None => break,
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

            let response_bytes = match registry.get(&command_code) {
                Some(handler) => {
                    let result = handler.handle(&command_code, &payload, &state).await;
                    let rc = protocol.response_code(&command_code);
                    protocol.frame_response(header, &rc, &result.error_code, &result.payload)
                }
                None => {
                    // No handler registered for this command.
                    if let Some(ref dcfg) = discover {
                        if dcfg.enabled {
                            log_discovery_command(&command_code, &payload, discovery_log.as_deref());
                            match forward_to_hsm(&buf[..frame_len], dcfg, &*protocol).await {
                                Ok(resp) => resp,
                                Err(e) => {
                                    warn!(err = %e, "discovery forward failed, returning error");
                                    protocol.frame_error(header, &command_code, b"40")
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

/// Log a command seen in discovery mode, redacting known-sensitive fields.
/// Writes to tracing and, if configured, to the structured NDJSON discovery log.
///
/// For Futurex: parameters are parsed; key blocks and PIN blocks are masked.
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

/// Forward a raw frame to the real HSM and return its response bytes.
///
/// Opens a fresh TCP connection per call. In production, consider a connection
/// pool to the real HSM to avoid connection setup overhead on every forwarded command.
async fn forward_to_hsm(frame: &[u8], cfg: &DiscoverConfig, protocol: &dyn Protocol) -> Result<Vec<u8>> {
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    let mut stream = timeout(
        Duration::from_secs(10),
        TcpStream::connect((&*cfg.hsm_host, cfg.hsm_port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timeout connecting to real HSM {}:{}", cfg.hsm_host, cfg.hsm_port))?
    .map_err(|e| anyhow::anyhow!("connecting to real HSM {}:{}: {e}", cfg.hsm_host, cfg.hsm_port))?;

    timeout(Duration::from_secs(10), stream.write_all(frame))
        .await
        .map_err(|_| anyhow::anyhow!("timeout sending to real HSM"))?
        .map_err(|e| anyhow::anyhow!("sending to real HSM: {e}"))?;

    let mut resp = Vec::with_capacity(4096);
    let mut buf = [0u8; 65536];
    loop {
        let n = timeout(Duration::from_secs(30), stream.read(&mut buf))
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
