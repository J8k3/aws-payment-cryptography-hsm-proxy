//! End-to-end tests for discover/passthrough mode.
//!
//! Each test starts a `MockHsm` (in-test tokio task on an ephemeral port),
//! spawns the real `apc-proxy` binary as a subprocess pointing at the mock,
//! sends a client frame, and asserts the proxy forwarded correctly, returned
//! the mock's reply verbatim, and wrote a redacted discovery log entry.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use common::mock_hsm::{MockBehavior, MockHsm};
use common::proxy_process::{ProxyConfigInput, ProxyProcess};

/// Build a Thales frame: `[2B length][2B header][2B command][payload]`.
/// length counts header + command + payload.
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

/// Thales: an unhandled command (`XX`) with `discover.enabled=true` should be
/// forwarded byte-for-byte to the configured HSM and the HSM's response
/// returned to the client unmodified. The discovery log should contain one
/// NDJSON record for the command.
#[tokio::test(flavor = "multi_thread")]
async fn thales_unhandled_command_is_forwarded_and_logged() {
    let client_frame = thales_frame(*b"XX", b"PAYLOAD-NOT-A-REAL-XX-PAYLOAD");
    let canned_reply = thales_frame(*b"XY", b"mock response");

    let mock = MockHsm::spawn(MockBehavior::Respond(canned_reply.clone()), 1).await;

    let proxy = ProxyProcess::spawn(&ProxyConfigInput {
        vendor: "thales_payshield",
        hsm_host: "127.0.0.1",
        hsm_port: mock.addr.port(),
        hsm_read_timeout_secs: None,
        listen_read_timeout_secs: None,
        tls: None,
        forward_tls: None,
    });

    let proxy_addr = proxy.addr;
    let frame_for_send = client_frame.clone();
    let response = tokio::task::spawn_blocking(move || send_recv(proxy_addr, &frame_for_send))
        .await
        .expect("send_recv task");

    assert_eq!(
        response, canned_reply,
        "proxy should return mock HSM's reply byte-for-byte"
    );

    let received = mock.frames().await;
    assert_eq!(
        received.len(),
        1,
        "mock should have seen one forwarded frame"
    );
    assert_eq!(
        received[0], client_frame,
        "mock should have received the client frame verbatim"
    );

    let log = proxy.read_discovery_log();
    assert!(
        log.contains("\"cmd\":\"XX\""),
        "discovery log should record command XX; got: {log}"
    );
    assert!(
        log.contains("\"vendor\":\"thales_payshield\""),
        "discovery log should record vendor; got: {log}"
    );
}

/// HSM unreachable (no listener on the configured port): proxy must not hang;
/// it should return a proxy-framed error response so the client connection
/// closes cleanly.
#[tokio::test(flavor = "multi_thread")]
async fn thales_unhandled_command_returns_error_when_hsm_unreachable() {
    // Bind a listener purely to claim a free port, then drop it so the port
    // becomes unreachable. Some short window exists where the OS could hand
    // the port to another process, but for a test it's good enough.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let unreachable_port = probe.local_addr().expect("local_addr").port();
    drop(probe);

    let proxy = ProxyProcess::spawn(&ProxyConfigInput {
        vendor: "thales_payshield",
        hsm_host: "127.0.0.1",
        hsm_port: unreachable_port,
        hsm_read_timeout_secs: None,
        listen_read_timeout_secs: None,
        tls: None,
        forward_tls: None,
    });

    let client_frame = thales_frame(*b"XX", b"payload");
    let proxy_addr = proxy.addr;
    let frame_for_send = client_frame.clone();
    let response = tokio::task::spawn_blocking(move || send_recv(proxy_addr, &frame_for_send))
        .await
        .expect("send_recv");

    // Proxy frames an error rather than hanging or returning the request bytes.
    // Layout: [2B length][2B header][2B command][2B error code "41"].
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
        "expected error code 41 (forward failed); got {:?}",
        std::str::from_utf8(error_code)
    );
}

/// HSM accepts the connection then never replies. The proxy must give up
/// after `hsm_read_timeout_secs` and return a framed error rather than
/// holding the client connection open indefinitely.
#[tokio::test(flavor = "multi_thread")]
async fn thales_unhandled_command_returns_error_on_hsm_read_timeout() {
    let mock = MockHsm::spawn(MockBehavior::AcceptThenHang, 1).await;

    let proxy = ProxyProcess::spawn(&ProxyConfigInput {
        vendor: "thales_payshield",
        hsm_host: "127.0.0.1",
        hsm_port: mock.addr.port(),
        hsm_read_timeout_secs: Some(1),
        listen_read_timeout_secs: None,
        tls: None,
        forward_tls: None,
    });

    let client_frame = thales_frame(*b"XX", b"payload");
    let proxy_addr = proxy.addr;
    let frame_for_send = client_frame.clone();

    let start = std::time::Instant::now();
    let response = tokio::task::spawn_blocking(move || send_recv(proxy_addr, &frame_for_send))
        .await
        .expect("send_recv");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "proxy should give up within ~1s of the configured timeout, took {elapsed:?}"
    );
    assert!(response.len() >= 8, "expected framed error response");
    let error_code = &response[6..8];
    assert_eq!(
        error_code,
        b"41",
        "expected error code 41 (forward read timeout); got {:?}",
        std::str::from_utf8(error_code)
    );
}
