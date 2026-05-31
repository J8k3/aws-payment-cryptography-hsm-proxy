//! Inbound TLS tests for the proxy listener.
//!
//! Each test generates an ephemeral self-signed CA + leaf cert (via `rcgen`),
//! spawns the proxy with `listen.tls` configured to use them, then connects
//! a `tokio-rustls` client that trusts the test CA and sends a Thales B2
//! heartbeat (the lightest possible round-trip — no APC call). The handshake
//! completing and the heartbeat round-trip succeeding is what we're proving.

mod common;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use common::proxy_process::{ProxyConfigInput, ProxyProcess, TlsInput};
use common::tls_certs::TlsCerts;

/// Minimal owned temp dir holder — mirrors the one in `proxy_process.rs`
/// without exposing it. Cleans up on drop.
struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("apc-proxy-tls-test-{pid}-{nanos}"));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn thales_b2_frame() -> Vec<u8> {
    // [2B length][2B header][2B command "B2"]; no payload, body_len = 2+2 = 4.
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00]); // header
    out.extend_from_slice(b"B2");
    out
}

/// One-way TLS: client trusts the proxy's CA, no client cert. B2 heartbeat
/// must round-trip with error code 00.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_tls_b2_heartbeat() {
    let dir = TempDir::new();
    let certs = TlsCerts::generate(&dir.path, "localhost");

    let proxy = ProxyProcess::spawn(&ProxyConfigInput {
        vendor: "thales_payshield",
        hsm_host: "127.0.0.1",
        hsm_port: 1, // unused — B2 is handled locally
        hsm_read_timeout_secs: None,
        tls: Some(TlsInput {
            cert_path: certs.cert_path.clone(),
            key_path: certs.key_path.clone(),
            ca_path: None,
        }),
    });

    let connector = TlsConnector::from(certs.client_config());
    let tcp = TcpStream::connect(proxy.addr)
        .await
        .expect("tcp connect to proxy");
    let server_name =
        rustls::pki_types::ServerName::try_from("localhost").expect("parse server name");
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake against proxy");

    let frame = thales_b2_frame();
    stream.write_all(&frame).await.expect("write B2 frame");

    let mut resp = vec![0u8; 4096];
    let n = stream.read(&mut resp).await.expect("read TLS response");
    resp.truncate(n);

    assert!(
        resp.len() >= 8,
        "expected framed response, got {} bytes",
        resp.len()
    );
    let error_code = &resp[6..8];
    assert_eq!(
        error_code,
        b"00",
        "B2 over TLS should return error code 00; got: {}",
        String::from_utf8_lossy(error_code)
    );
}

/// Plaintext client to a TLS-configured listener: rustls rejects the
/// handshake. The client connection still completes at the TCP layer, but
/// reading the response surfaces a TLS error (server sends Alert and closes,
/// or simply closes). This proves the proxy is not silently accepting
/// plaintext when TLS is configured.
#[tokio::test(flavor = "multi_thread")]
async fn inbound_tls_rejects_plaintext_client() {
    let dir = TempDir::new();
    let certs = TlsCerts::generate(&dir.path, "localhost");

    let proxy = ProxyProcess::spawn(&ProxyConfigInput {
        vendor: "thales_payshield",
        hsm_host: "127.0.0.1",
        hsm_port: 1,
        hsm_read_timeout_secs: None,
        tls: Some(TlsInput {
            cert_path: certs.cert_path.clone(),
            key_path: certs.key_path.clone(),
            ca_path: None,
        }),
    });

    let mut tcp = TcpStream::connect(proxy.addr)
        .await
        .expect("tcp connect to proxy");

    // Send a plaintext Thales B2 frame. The proxy is expecting a TLS
    // ClientHello (handshake byte 0x16); our 0x00 0x04 length prefix is not
    // valid TLS, so rustls aborts the handshake.
    let frame = thales_b2_frame();
    let _ = tcp.write_all(&frame).await;

    // The proxy either RSTs the connection or replies with a TLS Alert and
    // closes. Either way, a subsequent read returns 0 bytes (clean close) or
    // errors out — both are acceptable. What must NOT happen is the proxy
    // processing the plaintext as a real B2 and returning a Thales response.
    let mut resp = vec![0u8; 64];
    let read_result =
        tokio::time::timeout(std::time::Duration::from_secs(2), tcp.read(&mut resp)).await;

    match read_result {
        Ok(Ok(0)) => {
            // Clean close — server rejected and dropped us. Pass.
        }
        Ok(Ok(n)) => {
            // Got bytes back. They must NOT be a successful B2 response
            // (header+"BB"+"00" = "BB00" at offset 4..8). A TLS Alert record
            // starts with 0x15 in byte 0 — that's the expected non-success
            // shape.
            resp.truncate(n);
            assert_ne!(
                resp.get(4..8),
                Some(b"BB00".as_ref()),
                "proxy must not return a Thales success response to a plaintext client \
                 when TLS is configured; got: {resp:?}"
            );
        }
        Ok(Err(_)) | Err(_) => {
            // Read error or timeout — also fine. Server closed without reply.
        }
    }
}
