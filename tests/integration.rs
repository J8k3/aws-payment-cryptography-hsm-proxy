//! Integration tests against real HSM hardware or a simulator.
//!
//! All tests here are `#[ignore]` by default. Run them with:
//!
//!   cargo test --test integration -- --ignored
//!
//! Required environment:
//!
//!   HSM_HOST     — IP or hostname of the HSM (or EFTSim endpoint)
//!   HSM_PORT     — TCP port (Futurex plain: 9000, TLS: 9100; Thales plain: 1500)
//!   PROXY_HOST   — host where this proxy is listening (default: 127.0.0.1)
//!   PROXY_PORT   — port the proxy is listening on (default: 1500)
//!   AWS_REGION   — AWS region for APC calls (default: us-east-1)
//!
//! Optional (for TLS tests):
//!   TLS_CERT     — path to client certificate PEM
//!   TLS_KEY      — path to client private key PEM
//!   TLS_CA       — path to CA certificate PEM for server verification
//!
//! Key mappings must match what is configured in proxy.yaml for the test environment.
//!
//! These tests validate end-to-end behavior: raw wire frames in, APC round-trip,
//! correct response framing out. They cannot be replaced by unit tests because
//! they exercise protocol fidelity, TLS negotiation, APC latency, and key mapping.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn proxy_addr() -> String {
    let host = std::env::var("PROXY_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("PROXY_PORT").unwrap_or_else(|_| "1500".to_string());
    format!("{}:{}", host, port)
}

fn send_recv(frame: &[u8]) -> Vec<u8> {
    let mut conn = TcpStream::connect(proxy_addr()).expect("connect to proxy");
    conn.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    conn.write_all(frame).expect("send frame");
    let mut resp = vec![0u8; 4096];
    let n = conn.read(&mut resp).expect("read response");
    resp[..n].to_vec()
}

// ── Futurex Excrypt ───────────────────────────────────────────────────────────

/// ECHO is the simplest possible probe: send, get response, confirm framing.
#[test]
#[ignore = "requires live proxy and Futurex HSM or simulator (set HSM_HOST, HSM_PORT, PROXY_HOST, PROXY_PORT)"]
fn futurex_echo_returns_success() {
    let frame = b"[AOECHO;]";
    let resp = send_recv(frame);
    let s = String::from_utf8_lossy(&resp);
    assert!(s.starts_with("[AOECHO;"), "unexpected response prefix: {s}");
    assert!(s.contains("BBY;"), "expected success status BBY in: {s}");
}

/// TPIN round-trip: send a synthetic ISO Format 0 PIN block, expect a translated block back.
///
/// Prerequisites: the key identifiers in AX and BT must be in proxy.yaml key_mappings,
/// and the corresponding APC keys must exist in the configured AWS account.
#[test]
#[ignore = "requires live proxy with real APC keys configured (set HSM_HOST, HSM_PORT, PROXY_HOST, PROXY_PORT)"]
fn futurex_tpin_translates_pin_block() {
    // Replace AX/BT values with real key identifiers from your key_mappings
    let frame = b"[AOTPIN;AW0;AXZPK_INBOUND;BTZPK_OUTBOUND;AL0123456789ABCDEF;AK561237487695;]";
    let resp = send_recv(frame);
    let s = String::from_utf8_lossy(&resp);
    assert!(s.starts_with("[AOTPIN;"), "unexpected response prefix: {s}");
    // A translated PIN block will be in the AL parameter
    assert!(s.contains("AL"), "expected AL parameter in response: {s}");
    assert!(s.contains("BBY;"), "expected success status BBY in: {s}");
}

// ── Thales payShield ──────────────────────────────────────────────────────────

fn make_thales_frame(header: [u8; 2], cmd: &[u8], payload: &[u8]) -> Vec<u8> {
    let body_len = 2 + cmd.len() + payload.len();
    let mut out = Vec::new();
    out.extend_from_slice(&(body_len as u16).to_be_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(cmd);
    out.extend_from_slice(payload);
    out
}

fn parse_thales_response(resp: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // [2B length][2B header][2B response_code][2B error_code][payload]
    assert!(resp.len() >= 8, "response too short: {} bytes", resp.len());
    let error_code = resp[6..8].to_vec();
    let payload = resp[8..].to_vec();
    (error_code, payload)
}

/// B2 diagnostics (heartbeat): no APC call, proxy responds locally.
#[test]
#[ignore = "requires live proxy (set PROXY_HOST, PROXY_PORT)"]
fn thales_b2_heartbeat_returns_success() {
    let frame = make_thales_frame([0x00, 0x00], b"B2", b"");
    let resp = send_recv(&frame);
    let (error_code, _payload) = parse_thales_response(&resp);
    assert_eq!(&error_code, b"00", "expected error code 00 (success)");
}

/// CA PIN translate: send an ISO Format 0 PIN block under a ZPK, expect translated block.
///
/// Prerequisites: keys must be provisioned in APC and mapped in proxy.yaml.
/// The PAN field is 12 digits (rightmost digits excluding check digit).
#[test]
#[ignore = "requires live proxy with real APC keys configured (set PROXY_HOST, PROXY_PORT)"]
fn thales_ca_pin_translate_returns_translated_block() {
    // CA payload: [source-key-id][destination-key-id][source-format][dest-format][source-PIN-block][PAN]
    // Replace with real key identifiers and a valid test PIN block
    let payload = b"ZPK_INBOUND ZPK_OUTBOUND0000000000000000561237487695    ";
    let frame = make_thales_frame([0x00, 0x00], b"CA", payload);
    let resp = send_recv(&frame);
    let (error_code, _payload) = parse_thales_response(&resp);
    assert_eq!(&error_code, b"00", "expected error code 00 (success), check key mappings and APC key existence");
}
