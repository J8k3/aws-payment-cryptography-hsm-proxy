//! Integration test for the inbound idle read-timeout (slow-loris eviction).
//!
//! Drives the real binary: a connection that opens and then goes silent must be
//! evicted when `listen.read_timeout_secs` is set, and — critically — the
//! *process* must survive to serve other connections.
//!
//! (The unbounded-accumulation cap is exercised by the Futurex bolt-on's tests:
//! only a bracket-delimited, length-less stream can grow without completing a
//! frame; a length-prefixed Thales frame is bounded to 65_537 bytes.)

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use common::proxy_process::{ProxyConfigInput, ProxyProcess};

/// A minimal Thales B2 heartbeat frame: `[len=0x0004][header 0x0000]["B2"]`.
const B2_HEARTBEAT: &[u8] = b"\x00\x04\x00\x00B2";

#[test]
fn idle_connection_is_closed_when_read_timeout_configured() {
    // With listen.read_timeout_secs set, a connection that opens and then goes
    // silent must be evicted (slow-loris defense), not held open forever.
    let proxy = ProxyProcess::spawn(&ProxyConfigInput {
        vendor: "thales_payshield",
        hsm_host: "127.0.0.1",
        hsm_port: 9,
        hsm_read_timeout_secs: None,
        listen_read_timeout_secs: Some(1),
        tls: None,
        forward_tls: None,
    });

    let mut idle = TcpStream::connect(proxy.addr).expect("connect idle conn");
    // Read ceiling well above the 1s idle timeout: the proxy should close the
    // connection (read returns 0) shortly after ~1s of silence.
    idle.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    let start = std::time::Instant::now();
    let mut sink = [0u8; 16];
    let n = idle.read(&mut sink).expect("read on idle conn");
    assert_eq!(n, 0, "proxy should have closed the idle connection (EOF)");
    assert!(
        start.elapsed() < Duration::from_secs(8),
        "idle connection was not closed promptly by the read timeout"
    );

    // Process still healthy: a fresh B2 heartbeat is served.
    let mut hb = TcpStream::connect(proxy.addr).expect("reconnect");
    hb.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    hb.write_all(B2_HEARTBEAT).expect("write B2");
    let mut resp = vec![0u8; 64];
    let n = hb.read(&mut resp).expect("read B2");
    assert!(
        n > 0,
        "no B2 heartbeat response after idle close — the process may have died"
    );
}
