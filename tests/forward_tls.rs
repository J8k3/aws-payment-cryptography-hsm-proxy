//! End-to-end tests for outbound TLS on the proxy's forward leg
//! (`discover.tls`). The mock HSM serves TLS / mTLS; the proxy is
//! configured to validate the mock's cert against the same CA fixture and
//! optionally present a client cert.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use common::mock_hsm::{self, MockBehavior, MockHsm, TransportMode};
use common::proxy_process::{ForwardTlsInput, ProxyConfigInput, ProxyProcess};
use common::tls_certs::TlsCerts;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("apc-proxy-fwdtls-test-{pid}-{nanos}"));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn thales_frame(cmd: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let body_len = 2 + cmd.len() + payload.len();
    let mut out = Vec::with_capacity(2 + body_len);
    out.extend_from_slice(
        &u16::try_from(body_len)
            .expect("body fits in u16")
            .to_be_bytes(),
    );
    out.extend_from_slice(&[0x00, 0x00]); // header
    out.extend_from_slice(&cmd);
    out.extend_from_slice(payload);
    out
}

fn send_recv(addr: std::net::SocketAddr, frame: &[u8]) -> Vec<u8> {
    let mut conn =
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect to proxy");
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    conn.write_all(frame).expect("write frame");
    let mut resp = vec![0u8; 4096];
    let n = conn.read(&mut resp).expect("read response");
    resp.truncate(n);
    resp
}

fn read_pem(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Forward-TLS happy path: proxy connects to a TLS-only mock HSM, validates
/// the cert chain against the configured CA, forwards an unhandled command,
/// returns the mock's response verbatim.
#[tokio::test(flavor = "multi_thread")]
async fn forward_tls_happy_path() {
    let dir = TempDir::new();
    let certs = TlsCerts::generate(&dir.path, "localhost");

    let server_cfg = mock_hsm::server_config_from_cert_pem(
        &read_pem(&certs.cert_path),
        &read_pem(&certs.key_path),
        None,
    );

    let client_frame = thales_frame(*b"XX", b"forward-tls-test");
    let canned_reply = thales_frame(*b"XY", b"mock TLS reply");

    let mock = MockHsm::spawn_with_transport(
        MockBehavior::Respond(canned_reply.clone()),
        1,
        TransportMode::Tls(server_cfg),
    )
    .await;

    let proxy = ProxyProcess::spawn(&ProxyConfigInput {
        vendor: "thales_payshield",
        hsm_host: "localhost",
        hsm_port: mock.addr.port(),
        hsm_read_timeout_secs: None,
        tls: None,
        forward_tls: Some(ForwardTlsInput {
            ca_file: certs.ca_cert_pem_path.clone(),
            client_cert_file: None,
            client_key_file: None,
            server_name: None,
        }),
    });

    let proxy_addr = proxy.addr;
    let frame_for_send = client_frame.clone();
    let response = tokio::task::spawn_blocking(move || send_recv(proxy_addr, &frame_for_send))
        .await
        .expect("send_recv");

    assert_eq!(
        response, canned_reply,
        "proxy should return mock's reply verbatim over TLS forward leg"
    );

    let received = mock.frames().await;
    assert_eq!(received.len(), 1, "mock should see exactly one frame");
    assert_eq!(
        received[0], client_frame,
        "mock should receive the client frame verbatim through TLS"
    );
}

/// Forward-mTLS happy path: proxy presents a client cert that the mock HSM
/// validates against its own CA. Happy path round-trip.
#[tokio::test(flavor = "multi_thread")]
async fn forward_mtls_happy_path() {
    let dir = TempDir::new();
    let certs = TlsCerts::generate(&dir.path, "localhost");
    let client_cert = certs.issue_client_cert(&dir.path, "proxy-client");

    // Mock requires client auth signed by the same CA.
    let server_cfg = mock_hsm::server_config_from_cert_pem(
        &read_pem(&certs.cert_path),
        &read_pem(&certs.key_path),
        Some(&read_pem(&certs.ca_cert_pem_path)),
    );

    let client_frame = thales_frame(*b"XX", b"forward-mtls-test");
    let canned_reply = thales_frame(*b"XY", b"mock mTLS reply");

    let mock = MockHsm::spawn_with_transport(
        MockBehavior::Respond(canned_reply.clone()),
        1,
        TransportMode::Tls(server_cfg),
    )
    .await;

    let proxy = ProxyProcess::spawn(&ProxyConfigInput {
        vendor: "thales_payshield",
        hsm_host: "localhost",
        hsm_port: mock.addr.port(),
        hsm_read_timeout_secs: None,
        tls: None,
        forward_tls: Some(ForwardTlsInput {
            ca_file: certs.ca_cert_pem_path.clone(),
            client_cert_file: Some(client_cert.cert_path.clone()),
            client_key_file: Some(client_cert.key_path.clone()),
            server_name: None,
        }),
    });

    let proxy_addr = proxy.addr;
    let frame_for_send = client_frame.clone();
    let response = tokio::task::spawn_blocking(move || send_recv(proxy_addr, &frame_for_send))
        .await
        .expect("send_recv");

    assert_eq!(
        response, canned_reply,
        "proxy mTLS forward should round-trip"
    );
}

/// Forward-TLS wrong-CA: proxy's configured CA does NOT match the CA that
/// signed the mock HSM's cert. Handshake must fail; proxy returns framed
/// error 41 instead of silently establishing the connection.
#[tokio::test(flavor = "multi_thread")]
async fn forward_tls_rejects_untrusted_hsm_cert() {
    // Two separate temp dirs — TlsCerts writes server.crt/key/ca.crt with
    // fixed names, so reusing one dir would have the second call overwrite
    // the first and both "fixtures" would resolve to the same files on disk.
    let mock_dir = TempDir::new();
    let proxy_trust_dir = TempDir::new();
    let mock_certs = TlsCerts::generate(&mock_dir.path, "localhost");
    // Different CA entirely — the proxy will be told to trust this one.
    let proxy_trust = TlsCerts::generate(&proxy_trust_dir.path, "localhost");

    let server_cfg = mock_hsm::server_config_from_cert_pem(
        &read_pem(&mock_certs.cert_path),
        &read_pem(&mock_certs.key_path),
        None,
    );

    let mock = MockHsm::spawn_with_transport(
        MockBehavior::Respond(b"unused".to_vec()),
        1,
        TransportMode::Tls(server_cfg),
    )
    .await;

    let proxy = ProxyProcess::spawn(&ProxyConfigInput {
        vendor: "thales_payshield",
        hsm_host: "localhost",
        hsm_port: mock.addr.port(),
        hsm_read_timeout_secs: None,
        tls: None,
        forward_tls: Some(ForwardTlsInput {
            // Wrong CA — proxy will reject the mock's cert.
            ca_file: proxy_trust.ca_cert_pem_path.clone(),
            client_cert_file: None,
            client_key_file: None,
            server_name: None,
        }),
    });

    let proxy_addr = proxy.addr;
    let frame_for_send = thales_frame(*b"XX", b"payload");
    let response = tokio::task::spawn_blocking(move || send_recv(proxy_addr, &frame_for_send))
        .await
        .expect("send_recv");

    assert!(
        response.len() >= 8,
        "expected framed error response; got {} bytes: {:?}",
        response.len(),
        response
    );
    let error_code = &response[6..8];
    assert_eq!(
        error_code,
        b"41",
        "wrong-CA forward TLS should map to error 41; got: {}",
        std::str::from_utf8(error_code).unwrap_or("?")
    );

    // The mock should NOT have received a frame — handshake failed before
    // the proxy could write the payload.
    let received = mock.frames().await;
    assert!(
        received.is_empty(),
        "mock must not see any forwarded bytes when forward-TLS handshake fails"
    );
}
