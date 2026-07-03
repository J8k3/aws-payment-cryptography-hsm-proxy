//! Test-only mock HSM. Binds an ephemeral TCP port and acts like an HSM the
//! proxy can forward to in passthrough/discovery mode. Each connection is
//! handled exactly once: read the inbound frame, write a canned response,
//! record what was received for the test to assert on. Lives entirely in
//! `tests/` — not part of the shipped proxy.
//!
//! Optionally accepts TLS / mTLS for testing the proxy's outbound TLS path
//! (`discover.tls`). Server cert + optional client-cert-CA come from the same
//! `TlsCerts` fixture used by `tests/tls.rs`.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// A running mock HSM. Drop the handle when the test ends; the task will
/// finish naturally after `expected_connections` are served (or whenever the
/// process exits).
///
/// `tests/common/` compiles once per test binary; the TLS test binary
/// doesn't use this struct, so silence the per-binary dead-code lint.
#[allow(dead_code)]
pub struct MockHsm {
    pub addr: std::net::SocketAddr,
    /// Captured frames the proxy forwarded — one entry per accepted connection.
    pub received: Arc<Mutex<Vec<Vec<u8>>>>,
    _task: JoinHandle<()>,
}

/// Computes a mock response from the received frame (`RespondWith`).
pub type ResponseFn = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

#[allow(dead_code)]
#[derive(Clone)]
pub enum MockBehavior {
    /// Read inbound frame, immediately write the canned response, close.
    Respond(Vec<u8>),
    /// Read inbound frame, compute the response from it, write it, close.
    /// For tests where the reply depends on the request (e.g. the KCV probe's
    /// per-key-type candidates).
    RespondWith(ResponseFn),
    /// Accept the connection, read the frame, then hang indefinitely
    /// (no response). Use to exercise proxy's read-timeout path.
    AcceptThenHang,
}

impl std::fmt::Debug for MockBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Respond(r) => f.debug_tuple("Respond").field(r).finish(),
            Self::RespondWith(_) => f.write_str("RespondWith(<fn>)"),
            Self::AcceptThenHang => f.write_str("AcceptThenHang"),
        }
    }
}

/// How the mock should accept connections. `Plaintext` is the default;
/// `Tls` wraps each accepted TCP stream with a rustls server config.
#[allow(dead_code)]
pub enum TransportMode {
    Plaintext,
    /// One-way TLS. `server_config` already pinned with the cert + key.
    Tls(Arc<rustls::ServerConfig>),
}

#[allow(dead_code)]
impl MockHsm {
    /// Spawn a plaintext mock that serves at most `connections` then exits.
    pub async fn spawn(behavior: MockBehavior, connections: usize) -> Self {
        Self::spawn_with_transport(behavior, connections, TransportMode::Plaintext).await
    }

    /// Spawn a mock with a configurable transport (plaintext or TLS).
    pub async fn spawn_with_transport(
        behavior: MockBehavior,
        connections: usize,
        transport: TransportMode,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock HSM listener");
        let addr = listener.local_addr().expect("local_addr");

        let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let received_for_task = Arc::clone(&received);

        let task = tokio::spawn(async move {
            for _ in 0..connections {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let received = Arc::clone(&received_for_task);
                let behavior = behavior.clone();
                match &transport {
                    TransportMode::Plaintext => {
                        handle_one(tcp, &behavior, &received).await;
                    }
                    TransportMode::Tls(server_cfg) => {
                        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(server_cfg));
                        let Ok(tls_stream) = acceptor.accept(tcp).await else {
                            // Handshake failed — record nothing, move on.
                            continue;
                        };
                        handle_one(tls_stream, &behavior, &received).await;
                    }
                }
            }
        });

        Self {
            addr,
            received,
            _task: task,
        }
    }

    /// Convenience: snapshot the captured frames (clones, so the lock is
    /// released immediately).
    pub async fn frames(&self) -> Vec<Vec<u8>> {
        self.received.lock().await.clone()
    }
}

async fn handle_one<S>(mut stream: S, behavior: &MockBehavior, received: &Arc<Mutex<Vec<Vec<u8>>>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 65536];
    let Ok(n) = stream.read(&mut buf).await else {
        return;
    };
    buf.truncate(n);
    received.lock().await.push(buf);

    match behavior {
        MockBehavior::Respond(reply) => {
            let _ = stream.write_all(reply).await;
            let _ = stream.shutdown().await;
        }
        MockBehavior::RespondWith(f) => {
            let reply = f(received.lock().await.last().expect("frame just pushed"));
            let _ = stream.write_all(&reply).await;
            let _ = stream.shutdown().await;
        }
        MockBehavior::AcceptThenHang => {
            // Accept the connection then never respond, exercising the proxy's
            // read timeout. The task is cancelled when the test runtime drops.
            std::future::pending::<()>().await;
        }
    }
}

/// Build a rustls `ServerConfig` for the mock HSM from a TlsCerts fixture.
/// `client_ca` enables mTLS — the mock will require the proxy to present a
/// client cert signed by that CA.
#[allow(dead_code)]
pub fn server_config_from_cert_pem(
    cert_pem: &str,
    key_pem: &str,
    client_ca_pem: Option<&str>,
) -> Arc<rustls::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
            .collect::<Result<_, _>>()
            .expect("parse mock cert");
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem.as_bytes()))
        .expect("parse mock key")
        .expect("mock key present");

    let cfg = if let Some(ca_pem) = client_ca_pem {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(ca_pem.as_bytes())) {
            roots
                .add(cert.expect("parse mock client CA"))
                .expect("add client CA");
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("client verifier");
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key)
            .expect("server config (mTLS)")
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("server config")
    };

    Arc::new(cfg)
}

/// Convenience: re-export `TcpStream` so tests that need to construct
/// transport directly don't have to import from tokio themselves.
#[allow(dead_code)]
pub type RawStream = TcpStream;
