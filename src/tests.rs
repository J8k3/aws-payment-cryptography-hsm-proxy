//! In-process integration tests using a mock APC HTTP server.
//!
//! Each test:
//!   1. Spins up a mock APC HTTP server on an ephemeral port.
//!   2. Builds an `AppState` whose APC client points at that server with
//!      hardcoded test credentials (so no real AWS account is needed).
//!   3. Calls the handler under test directly, bypassing the TCP layer.
//!   4. Asserts on the `HandlerResult` error code and payload.
//!
//! Run with: `cargo test` (included automatically).
//! Run with output: `cargo test -- --nocapture`.
//!
//! The mock server is intentionally minimal — it routes by HTTP path and
//! returns pre-configured JSON bodies. It does not validate request bodies
//! or AWS SigV4 signatures.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::handlers::{AppState, Registry};
use crate::key_map::KeyMap;

// ── Mock APC HTTP server ──────────────────────────────────────────────────────

/// Per-route configuration: HTTP status code + JSON body.
type Routes = RwLock<HashMap<String, (u16, String)>>;

/// Lightweight in-process mock for the APC Payment Cryptography data plane.
///
/// Starts listening on a random ephemeral port immediately. Configurable per
/// route — call `set()` to override any default response before a test.
pub struct MockApc {
    /// Base URL of the mock server, e.g. `http://127.0.0.1:52348`.
    pub url: String,
    routes: Arc<Routes>,
}

impl MockApc {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{}", port);

        let routes = Arc::new(RwLock::new(default_routes()));
        let routes_bg = Arc::clone(&routes);

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let r = Arc::clone(&routes_bg);
                tokio::spawn(async move {
                    serve_once(&mut stream, &r).await;
                });
            }
        });

        Self { url, routes }
    }

    /// Override the response for a given APC API path.
    ///
    /// Common paths:
    ///   `/mac/generate`, `/mac/verify`,
    ///   `/pindata/verify`,
    ///   `/cardvalidationdata/generate`, `/cardvalidationdata/verify`
    pub async fn set(&self, path: &str, status: u16, body: &str) {
        self.routes
            .write()
            .await
            .insert(path.to_string(), (status, body.to_string()));
    }

    /// Convenience: configure an APC path to return VerificationFailedException.
    pub async fn set_verification_failure(&self, path: &str) {
        self.set(
            path,
            400,
            r#"{"__type":"VerificationFailedException","message":"mock verification failure"}"#,
        )
        .await;
    }
}

/// Default successful responses for every APC operation the proxy uses.
fn default_routes() -> HashMap<String, (u16, String)> {
    let mut m = HashMap::new();
    m.insert(
        "/mac/generate".into(),
        (
            200,
            r#"{"KeyArn":"arn:aws:payment-cryptography:us-east-1:000000000000:key/mock","KeyCheckValue":"AABBCC","Mac":"AABBCCDDEE112233"}"#.into(),
        ),
    );
    m.insert(
        "/mac/verify".into(),
        (
            200,
            r#"{"KeyArn":"arn:aws:payment-cryptography:us-east-1:000000000000:key/mock","KeyCheckValue":"AABBCC"}"#.into(),
        ),
    );
    m.insert(
        "/pindata/verify".into(),
        (
            200,
            r#"{"EncryptionKeyArn":"arn:mock","EncryptionKeyCheckValue":"AAA","VerificationKeyArn":"arn:mock","VerificationKeyCheckValue":"BBB"}"#.into(),
        ),
    );
    m.insert(
        "/cardvalidationdata/generate".into(),
        (
            200,
            r#"{"KeyArn":"arn:mock","KeyCheckValue":"AAA","ValidationData":"123"}"#.into(),
        ),
    );
    m.insert(
        "/cardvalidationdata/verify".into(),
        (
            200,
            r#"{"KeyArn":"arn:mock","KeyCheckValue":"AAA"}"#.into(),
        ),
    );
    m
}

/// Serve one HTTP request on `stream`, look up the path in `routes`, respond, close.
///
/// Reads the FULL request (headers + body) before sending the response. This
/// prevents the OS from sending a TCP RST when we drop the stream while the SDK
/// is still writing the request body, which would cause a DispatchFailure on the
/// client side.
async fn serve_once(stream: &mut tokio::net::TcpStream, routes: &Routes) {
    // Read until end-of-headers (\r\n\r\n), up to 64 KiB.
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 65536 {
            return;
        }
    }

    // Extract the request path from the first line: "POST /mac/generate HTTP/1.1"
    let path = std::str::from_utf8(&buf)
        .ok()
        .and_then(|s| s.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();

    // Drain the request body so the OS doesn't RST when we close the socket.
    // Parse Content-Length, subtract bytes already buffered past \r\n\r\n.
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(buf.len());
    let content_length: usize = std::str::from_utf8(&buf[..header_end])
        .unwrap_or("")
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-length:") {
                lower.splitn(2, ':').nth(1)?.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let already_buffered = buf.len().saturating_sub(header_end + 4);
    let remaining_body = content_length.saturating_sub(already_buffered);
    if remaining_body > 0 {
        let mut drain = vec![0u8; remaining_body];
        let _ = stream.read_exact(&mut drain).await;
    }

    let (status, body) = {
        let guard = routes.read().await;
        guard
            .get(&path)
            .cloned()
            .unwrap_or_else(|| (404, r#"{"__type":"UnknownOperationException"}"#.to_string()))
    };

    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nx-amzn-RequestId: mock-req-id\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}

// ── Test AppState builder ─────────────────────────────────────────────────────

/// Build an `AppState` whose APC client points at `apc_url` with hardcoded test
/// credentials. No real AWS account or environment credentials are needed.
async fn mock_state(apc_url: &str, key_mappings: HashMap<String, String>) -> Arc<AppState> {
    use aws_credential_types::{provider::SharedCredentialsProvider, Credentials};

    let creds = SharedCredentialsProvider::new(Credentials::new(
        "mock_key_id",
        "mock_secret",
        None,
        None,
        "test",
    ));
    let aws_cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(creds)
        .endpoint_url(apc_url)
        .load()
        .await;

    Arc::new(AppState {
        key_map: KeyMap::new(key_mappings),
        data: aws_sdk_paymentcryptographydata::Client::new(&aws_cfg),
    })
}

/// Single-entry key map: `label` → `"arn:mock"`.
fn one_key(label: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(label.to_string(), "arn:mock".to_string());
    m
}

// ── Helpers to build payShield payloads ──────────────────────────────────────

/// Single-length TAK key label (16 hex chars).
const SINGLE_KEY: &[u8] = b"1234567890ABCDEF";
/// Double-length TAK key label (U + 32 hex chars).
fn double_key() -> Vec<u8> {
    let mut v = vec![b'U'];
    v.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
    v
}
/// 8-char MAC hex value used in verify payloads.
const MAC_8H: &[u8] = b"AABBCCDD";

// ── Heartbeat ─────────────────────────────────────────────────────────────────

/// B2 is handled entirely in the proxy — no APC call — so no mock needed.
#[tokio::test]
async fn thales_b2_heartbeat_returns_success() {
    // We still need a valid AppState to satisfy the handler signature;
    // give it a no-op endpoint since the handler never calls APC.
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();
    let handler = registry.get(b"B2").expect("B2 registered");
    let result = handler.handle(b"B2", b"", &state).await;
    assert_eq!(&result.error_code, b"00");
}

// ── Legacy TAK MAC — MA (generate) ───────────────────────────────────────────

#[tokio::test]
async fn thales_ma_generate_mac_success() {
    let mock = MockApc::start().await;
    let state = mock_state(&mock.url, one_key("1234567890ABCDEF")).await;
    let registry = Registry::build();

    let mut payload = SINGLE_KEY.to_vec(); // TAK key label
    payload.extend_from_slice(b"MESSAGEDATA"); // raw message bytes

    let handler = registry.get(b"MA").expect("MA registered");
    let result = handler.handle(b"MA", &payload, &state).await;

    assert_eq!(&result.error_code, b"00", "expected success");
    // Mock returns Mac = "AABBCCDDEE112233"
    assert_eq!(result.payload.as_slice(), b"AABBCCDDEE112233");
}

#[tokio::test]
async fn thales_ma_key_not_found_returns_10() {
    let mock = MockApc::start().await;
    let state = mock_state(&mock.url, HashMap::new()).await; // empty key map

    let mut payload = SINGLE_KEY.to_vec();
    payload.extend_from_slice(b"DATA");

    let registry = Registry::build();
    let handler = registry.get(b"MA").expect("MA registered");
    let result = handler.handle(b"MA", &payload, &state).await;

    assert_eq!(&result.error_code, b"10", "unknown key → error 10");
}

#[tokio::test]
async fn thales_ma_double_key_success() {
    let mock = MockApc::start().await;
    let dk = double_key();
    let label = String::from_utf8(dk.clone()).unwrap();
    let state = mock_state(&mock.url, one_key(&label)).await;

    let mut payload = dk;
    payload.extend_from_slice(b"DATA");

    let registry = Registry::build();
    let handler = registry.get(b"MA").expect("MA registered");
    let result = handler.handle(b"MA", &payload, &state).await;
    assert_eq!(&result.error_code, b"00");
}

// ── Legacy TAK MAC — MC (verify) ─────────────────────────────────────────────

#[tokio::test]
async fn thales_mc_verify_mac_success() {
    let mock = MockApc::start().await;
    let state = mock_state(&mock.url, one_key("1234567890ABCDEF")).await;

    let mut payload = SINGLE_KEY.to_vec(); // TAK
    payload.extend_from_slice(MAC_8H); // 8H MAC to verify
    payload.extend_from_slice(b"MESSAGEDATA");

    let registry = Registry::build();
    let handler = registry.get(b"MC").expect("MC registered");
    let result = handler.handle(b"MC", &payload, &state).await;

    assert_eq!(&result.error_code, b"00");
    assert!(result.payload.is_empty(), "MC success payload is empty");
}

#[tokio::test]
async fn thales_mc_verify_mac_mismatch_returns_01() {
    let mock = MockApc::start().await;
    mock.set_verification_failure("/mac/verify").await;
    let state = mock_state(&mock.url, one_key("1234567890ABCDEF")).await;

    let mut payload = SINGLE_KEY.to_vec();
    payload.extend_from_slice(MAC_8H);
    payload.extend_from_slice(b"MESSAGEDATA");

    let registry = Registry::build();
    let handler = registry.get(b"MC").expect("MC registered");
    let result = handler.handle(b"MC", &payload, &state).await;

    assert_eq!(&result.error_code, b"01", "MAC mismatch → error 01");
}

#[tokio::test]
async fn thales_mc_payload_too_short_returns_15() {
    let mock = MockApc::start().await;
    let state = mock_state(&mock.url, one_key("1234567890ABCDEF")).await;

    // Key is 16 bytes but no MAC field follows
    let payload = SINGLE_KEY.to_vec();

    let registry = Registry::build();
    let handler = registry.get(b"MC").expect("MC registered");
    let result = handler.handle(b"MC", &payload, &state).await;

    assert_eq!(&result.error_code, b"15", "truncated payload → error 15");
}

// ── Legacy TAK MAC — ME (verify + translate) ──────────────────────────────────

#[tokio::test]
async fn thales_me_verify_and_translate_success() {
    let mock = MockApc::start().await;
    // ME needs two key mappings: src and dst
    let mut keys = HashMap::new();
    keys.insert("1234567890ABCDEF".to_string(), "arn:mock:src".to_string());
    keys.insert("FEDCBA0987654321".to_string(), "arn:mock:dst".to_string());
    let state = mock_state(&mock.url, keys).await;

    let mut payload = SINGLE_KEY.to_vec(); // src TAK: "1234567890ABCDEF"
    payload.extend_from_slice(b"FEDCBA0987654321"); // dst TAK (also single-length)
    payload.extend_from_slice(MAC_8H); // MAC to verify
    payload.extend_from_slice(b"MSGDATA");

    let registry = Registry::build();
    let handler = registry.get(b"ME").expect("ME registered");
    let result = handler.handle(b"ME", &payload, &state).await;

    assert_eq!(&result.error_code, b"00");
    // ME returns the translated MAC from generate_mac
    assert_eq!(result.payload.as_slice(), b"AABBCCDDEE112233");
}

#[tokio::test]
async fn thales_me_verify_step_mismatch_returns_01() {
    let mock = MockApc::start().await;
    mock.set_verification_failure("/mac/verify").await;
    let mut keys = HashMap::new();
    keys.insert("1234567890ABCDEF".to_string(), "arn:mock".to_string());
    keys.insert("FEDCBA0987654321".to_string(), "arn:mock".to_string());
    let state = mock_state(&mock.url, keys).await;

    let mut payload = SINGLE_KEY.to_vec();
    payload.extend_from_slice(b"FEDCBA0987654321");
    payload.extend_from_slice(MAC_8H);
    payload.extend_from_slice(b"DATA");

    let registry = Registry::build();
    let handler = registry.get(b"ME").expect("ME registered");
    let result = handler.handle(b"ME", &payload, &state).await;

    assert_eq!(&result.error_code, b"01");
}

// ── DUKPT PIN verify — CK (IBM 3624) ──────────────────────────────────────────

#[tokio::test]
async fn thales_ck_verify_pin_success() {
    let mock = MockApc::start().await;
    let mut keys = HashMap::new();
    // BDK: 32H key label
    keys.insert(
        "12345678901234561234567890123456".to_string(),
        "arn:mock:bdk".to_string(),
    );
    // PVK: 16H key label
    keys.insert("1234567890ABCDEF".to_string(), "arn:mock:pvk".to_string());
    let state = mock_state(&mock.url, keys).await;

    let registry = Registry::build();
    let handler = registry.get(b"CK").expect("CK registered");

    // CK payload: BDK(32) + PVK(16) + KSN_desc(3) + KSN(20) + PIN_block(16) +
    //             check(2) + account(12) + decim_table(16) + pin_val_data(12) + offset(12)
    let mut payload = b"12345678901234561234567890123456".to_vec(); // BDK 32H
    payload.extend_from_slice(b"1234567890ABCDEF"); // PVK 16H
    payload.extend_from_slice(b"00A"); // KSN descriptor
    payload.extend_from_slice(b"12345678901234567890"); // KSN 20H
    payload.extend_from_slice(b"1234567890ABCDEF"); // PIN block 16H
    payload.extend_from_slice(b"04"); // check length
    payload.extend_from_slice(b"123456789012"); // account 12N
    payload.extend_from_slice(b"1234567890123456"); // decim table 16N
    payload.extend_from_slice(b"NNNNNNNNNNNN"); // pin val data 12A
    payload.extend_from_slice(b"123456789012"); // offset 12H

    let result = handler.handle(b"CK", &payload, &state).await;
    assert_eq!(&result.error_code, b"00");
}

#[tokio::test]
async fn thales_ck_verify_pin_mismatch_returns_01() {
    let mock = MockApc::start().await;
    mock.set_verification_failure("/pindata/verify").await;
    let mut keys = HashMap::new();
    keys.insert(
        "12345678901234561234567890123456".to_string(),
        "arn:mock:bdk".to_string(),
    );
    keys.insert("1234567890ABCDEF".to_string(), "arn:mock:pvk".to_string());
    let state = mock_state(&mock.url, keys).await;

    let registry = Registry::build();
    let handler = registry.get(b"CK").expect("CK registered");

    let mut payload = b"12345678901234561234567890123456".to_vec();
    payload.extend_from_slice(b"1234567890ABCDEF");
    payload.extend_from_slice(b"00A");
    payload.extend_from_slice(b"12345678901234567890");
    payload.extend_from_slice(b"1234567890ABCDEF");
    payload.extend_from_slice(b"04");
    payload.extend_from_slice(b"123456789012");
    payload.extend_from_slice(b"1234567890123456");
    payload.extend_from_slice(b"NNNNNNNNNNNN");
    payload.extend_from_slice(b"123456789012");

    let result = handler.handle(b"CK", &payload, &state).await;
    assert_eq!(&result.error_code, b"01", "PIN mismatch → 01");
}

// ── DUKPT PIN verify — CM (Visa PVV) ─────────────────────────────────────────

#[tokio::test]
async fn thales_cm_verify_pin_success() {
    let mock = MockApc::start().await;
    let mut keys = HashMap::new();
    keys.insert(
        "12345678901234561234567890123456".to_string(),
        "arn:mock:bdk".to_string(),
    );
    keys.insert(
        "12345678901234561234567890123456".to_string(), // reuse same label for simplicity
        "arn:mock:pvk".to_string(),
    );
    // Actually use distinct labels
    keys.insert(
        "ABCDEF1234567890ABCDEF1234567890".to_string(),
        "arn:mock:pvk".to_string(),
    );
    let state = mock_state(&mock.url, keys).await;

    let registry = Registry::build();
    let handler = registry.get(b"CM").expect("CM registered");

    // CM payload: BDK(32) + PVK(32) + KSN_desc(3) + KSN(20) + PIN_block(16) +
    //             PAN(12) + PVKI(1) + PVV(4)
    let mut payload = b"12345678901234561234567890123456".to_vec(); // BDK 32H
    payload.extend_from_slice(b"ABCDEF1234567890ABCDEF1234567890"); // PVK 32H
    payload.extend_from_slice(b"00A"); // KSN descriptor
    payload.extend_from_slice(b"12345678901234567890"); // KSN 20H
    payload.extend_from_slice(b"1234567890ABCDEF"); // PIN block 16H
    payload.extend_from_slice(b"123456789012"); // PAN 12N
    payload.extend_from_slice(b"1"); // PVKI
    payload.extend_from_slice(b"1234"); // PVV 4N

    let result = handler.handle(b"CM", &payload, &state).await;
    assert_eq!(&result.error_code, b"00");
}

// ── Unsupported commands ──────────────────────────────────────────────────────

#[tokio::test]
async fn unsupported_command_returns_68() {
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();

    // CO is explicitly unsupported (no APC equivalent for Diebold method)
    let handler = registry.get(b"CO").expect("CO registered in noop");
    let result = handler.handle(b"CO", b"", &state).await;
    assert_eq!(&result.error_code, b"68");

    // CQ is explicitly unsupported (Encrypted PIN method)
    let handler = registry.get(b"CQ").expect("CQ registered");
    let result = handler.handle(b"CQ", b"", &state).await;
    assert_eq!(&result.error_code, b"68");
}

#[tokio::test]
async fn noop_handler_returns_68_for_all_registered_commands() {
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();

    // Spot-check a few explicitly disabled commands
    for cmd in [b"B0" as &[u8], b"LE", b"EM", b"RA"] {
        let handler = registry.get(cmd).expect("noop handler registered");
        let result = handler.handle(cmd, b"", &state).await;
        assert_eq!(
            &result.error_code,
            b"68",
            "cmd {} should return 68",
            String::from_utf8_lossy(cmd)
        );
    }
}
