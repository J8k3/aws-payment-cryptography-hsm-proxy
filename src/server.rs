use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::config::{DiscoverConfig, ProxyConfig, TlsConfig};
use crate::handlers::{AppState, Registry};
use crate::key_map::KeyMap;
use crate::protocol::{futurex::FuturexExcrypt, thales::ThalesPayShield, Protocol};

pub async fn run(cfg: ProxyConfig) -> Result<()> {
    let mut aws_builder = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(cfg.aws.region.clone()));
    if let Some(ref profile) = cfg.aws.profile {
        aws_builder = aws_builder.profile_name(profile);
    }
    let aws_cfg = aws_builder.load().await;

    let state = Arc::new(AppState {
        key_map: KeyMap::new(cfg.key_mappings.clone()),
        control: aws_sdk_paymentcryptography::Client::new(&aws_cfg),
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

        tokio::spawn(async move {
            let result = if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(socket).await {
                    Ok(stream) => handle_connection(stream, state, registry, protocol, discover).await,
                    Err(e) => {
                        error!(%peer, err = %e, "TLS handshake failed");
                        return;
                    }
                }
            } else {
                handle_connection(socket, state, registry, protocol, discover).await
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

    let provider = Arc::new(rustls::crypto::ring::default_provider());

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
                            log_discovery_command(&command_code, &payload);
                            match forward_to_hsm(&buf[..frame_len], dcfg).await {
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
///
/// For Futurex: individual parameters are inspected, key blocks and PIN blocks masked.
/// For Thales: only the command code and payload length are logged (field offsets vary).
fn log_discovery_command(command_code: &[u8], payload: &[u8]) {
    use crate::protocol::futurex::redact_for_log;

    let cmd = String::from_utf8_lossy(command_code);

    // Futurex: 4-byte command codes, parameters are parseable
    if command_code.len() == 4 {
        let params = crate::protocol::futurex::parse_params(payload);
        let safe = redact_for_log(&params);
        info!(cmd = %cmd, params = %safe, "DISCOVERY: unhandled Futurex command");
    } else {
        // Thales: log command code and payload length only — field layout is positional
        // and sensitive offsets are command-specific. Full content analysis not attempted.
        info!(cmd = %cmd, payload_len = payload.len(), "DISCOVERY: unhandled Thales command");
    }
}

/// Forward a raw frame to the real HSM and return its response bytes.
///
/// Opens a fresh TCP connection per call. In production, consider a connection
/// pool to the real HSM to avoid connection setup overhead on every forwarded command.
async fn forward_to_hsm(frame: &[u8], cfg: &DiscoverConfig) -> Result<Vec<u8>> {
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect((&*cfg.hsm_host, cfg.hsm_port)).await
        .map_err(|e| anyhow::anyhow!("connecting to real HSM {}:{}: {e}", cfg.hsm_host, cfg.hsm_port))?;

    stream.write_all(frame).await?;

    // Read one response chunk. For production use, parse the full framed response.
    let mut resp = vec![0u8; 4096];
    let n = stream.read(&mut resp).await?;
    resp.truncate(n);
    Ok(resp)
}
