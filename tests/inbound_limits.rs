//! Integration test for the inbound accumulation cap (the Futurex-OOM guard).
//!
//! A connection that streams bytes which never complete a frame must not grow
//! the proxy's memory without bound. The proxy closes such a connection once
//! accumulation exceeds its cap, and — critically — the *process* survives to
//! serve other connections. This test drives the real binary.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use common::proxy_process::{ProxyConfigInput, ProxyProcess};

#[test]
fn oversized_futurex_stream_is_capped_without_killing_process() {
    let proxy = ProxyProcess::spawn(&ProxyConfigInput {
        vendor: "futurex_excrypt",
        // Never dialed: discovery-forward only fires for a *parsed* unhandled
        // command, and the junk below never parses into one.
        hsm_host: "127.0.0.1",
        hsm_port: 9,
        hsm_read_timeout_secs: None,
        tls: None,
        forward_tls: None,
    });

    // Connection 1: stream bytes that never form a Futurex frame (no '['), well
    // past the accumulation cap. Before the fix this grew the proxy buffer
    // without limit; now the proxy closes the connection.
    let mut junk = TcpStream::connect(proxy.addr).expect("connect junk conn");
    junk.set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set write timeout");
    junk.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");

    let chunk = vec![b'A'; 8192];
    let mut sent = 0usize;
    while sent < 2 * 1024 * 1024 {
        // Once the proxy closes its side, writes fail (broken pipe) — expected.
        match junk.write_all(&chunk) {
            Ok(()) => sent += chunk.len(),
            Err(_) => break,
        }
    }

    // The proxy should have closed the connection: a read sees EOF (0) or errors.
    let mut sink = [0u8; 64];
    let closed = matches!(junk.read(&mut sink), Ok(0) | Err(_));
    assert!(
        closed,
        "proxy kept the oversized junk connection open (no accumulation cap?)"
    );

    // Process survived: a fresh connection with a valid ECHO still gets served.
    let mut echo = TcpStream::connect(proxy.addr).expect("reconnect after cap");
    echo.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    echo.write_all(b"[AOECHO;]").expect("write ECHO");
    let mut resp = vec![0u8; 256];
    let n = echo.read(&mut resp).expect("read ECHO response");
    resp.truncate(n);
    assert!(n > 0, "no ECHO response — proxy process may have died");
    assert!(
        resp.ends_with(b"]"),
        "unexpected ECHO response: {:?}",
        String::from_utf8_lossy(&resp)
    );
}
