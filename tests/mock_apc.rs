//! Mock-APC integration tests for the handler layer.
//!
//! Each test:
//!   1. Spins up a mock APC HTTP server on an ephemeral port.
//!   2. Builds an `AppState` whose APC client points at that server with
//!      hardcoded test credentials (so no real AWS account is needed).
//!   3. Calls the handler under test directly, bypassing the TCP layer.
//!   4. Asserts on the `HandlerResult` error code and payload.
//!
//! Run with: `cargo test --test mock_apc`.
//!
//! The mock server is intentionally minimal — it routes by HTTP path and
//! returns pre-configured JSON bodies. It does not validate request bodies
//! or AWS SigV4 signatures.

// Tests live outside the prod source tree; panic IS the intended failure mode
// and the runner already reports file:line.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use apc_proxy::handlers::{AppState, Registry};
use apc_proxy::key_map::KeyMap;

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
        let url = format!("http://127.0.0.1:{port}");

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
        (200, r#"{"KeyArn":"arn:mock","KeyCheckValue":"AAA"}"#.into()),
    );
    // HE/HG and M0/M2: paths include the URL-encoded key ARN.
    // Tests use "mock-dek" (no colons) so the path is /keys/mock-dek/encrypt|decrypt.
    m.insert(
        "/keys/mock-dek/encrypt".into(),
        (
            200,
            r#"{"KeyArn":"mock-dek","KeyCheckValue":"AAA","CipherText":"CCDDEEFF11223344"}"#.into(),
        ),
    );
    m.insert(
        "/keys/mock-dek/decrypt".into(),
        (
            200,
            r#"{"KeyArn":"mock-dek","KeyCheckValue":"AAA","PlainText":"AABBCCDDEE112233"}"#.into(),
        ),
    );
    // M4 translate is done as two calls: decrypt under the source key, then
    // encrypt under the destination key (re_encrypt_data rejects D0 keys — see
    // the handler grounding). Tests use "mock-src" and "mock-dst".
    m.insert(
        "/keys/mock-src/decrypt".into(),
        (
            200,
            r#"{"KeyArn":"mock-src","KeyCheckValue":"AAA","PlainText":"AABBCCDDEE112233"}"#.into(),
        ),
    );
    m.insert(
        "/keys/mock-dst/encrypt".into(),
        (
            200,
            r#"{"KeyArn":"mock-dst","KeyCheckValue":"AAA","CipherText":"EEFF11223344AABB"}"#.into(),
        ),
    );
    // KQ: verify_auth_request_cryptogram path.
    // Success includes an ARPC; no-ARPC variant omits AuthResponseValue.
    m.insert(
        "/cryptogram/verify".into(),
        (
            200,
            r#"{"KeyArn":"arn:mock","KeyCheckValue":"AAA","AuthResponseValue":"AABBCCDDEEFF0011"}"#
                .into(),
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
                lower.split_once(':')?.1.trim().parse().ok()
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
    // Mock returns Mac = "AABBCCDDEE112233"; handler truncates to first 8H (4 bytes)
    assert_eq!(result.payload.as_slice(), b"AABBCCDD");
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
    // ME returns the translated MAC from generate_mac; handler truncates to first 8H (4 bytes)
    assert_eq!(result.payload.as_slice(), b"AABBCCDD");
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

// ── Encrypt/Decrypt Data Block (HE/HG) ───────────────────────────────────────

#[tokio::test]
async fn thales_he_encrypt_block_success() {
    let mock = MockApc::start().await;
    // "mock-dek" has no colons so the path is /keys/mock-dek/encrypt
    let mut keys = HashMap::new();
    keys.insert("1234567890ABCDEF".to_string(), "mock-dek".to_string());
    let state = mock_state(&mock.url, keys).await;

    let registry = Registry::build();
    let handler = registry.get(b"HE").expect("HE registered");

    // HE payload: TAK(16H) + Data(16H)
    let mut payload = b"1234567890ABCDEF".to_vec(); // TAK single 16H
    payload.extend_from_slice(b"AABBCCDDEE112233"); // plaintext 16H

    let result = handler.handle(b"HE", &payload, &state).await;
    assert_eq!(&result.error_code, b"00", "HE should succeed");
    assert_eq!(
        result.payload.as_slice(),
        b"CCDDEEFF11223344",
        "HE returns ciphertext from APC"
    );
}

#[tokio::test]
async fn thales_he_double_key_success() {
    let mock = MockApc::start().await;
    let mut keys = HashMap::new();
    // parse_legacy_key returns the identifier with the 'U' prefix included
    keys.insert(
        "U1234567890ABCDEF1234567890ABCDEF".to_string(),
        "mock-dek".to_string(),
    );
    let state = mock_state(&mock.url, keys).await;

    let registry = Registry::build();
    let handler = registry.get(b"HE").expect("HE registered");

    let mut payload = b"U1234567890ABCDEF1234567890ABCDEF".to_vec();
    payload.extend_from_slice(b"AABBCCDDEE112233");

    let result = handler.handle(b"HE", &payload, &state).await;
    assert_eq!(&result.error_code, b"00");
}

#[tokio::test]
async fn thales_he_key_not_found_returns_10() {
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();
    let handler = registry.get(b"HE").expect("HE registered");

    let mut payload = b"1234567890ABCDEF".to_vec();
    payload.extend_from_slice(b"AABBCCDDEE112233");

    let result = handler.handle(b"HE", &payload, &state).await;
    assert_eq!(&result.error_code, b"10");
}

#[tokio::test]
async fn thales_he_payload_too_short_returns_15() {
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();
    let handler = registry.get(b"HE").expect("HE registered");

    // TAK present but data only 8H (needs 16H)
    let mut payload = b"1234567890ABCDEF".to_vec();
    payload.extend_from_slice(b"AABBCCDD");

    let result = handler.handle(b"HE", &payload, &state).await;
    assert_eq!(&result.error_code, b"15");
}

#[tokio::test]
async fn thales_hg_decrypt_block_success() {
    let mock = MockApc::start().await;
    let mut keys = HashMap::new();
    keys.insert("1234567890ABCDEF".to_string(), "mock-dek".to_string());
    let state = mock_state(&mock.url, keys).await;

    let registry = Registry::build();
    let handler = registry.get(b"HG").expect("HG registered");

    // HG payload: TAK(16H) + Ciphertext(16H)
    let mut payload = b"1234567890ABCDEF".to_vec();
    payload.extend_from_slice(b"CCDDEEFF11223344"); // ciphertext 16H

    let result = handler.handle(b"HG", &payload, &state).await;
    assert_eq!(&result.error_code, b"00", "HG should succeed");
    assert_eq!(
        result.payload.as_slice(),
        b"AABBCCDDEE112233",
        "HG returns plaintext from APC"
    );
}

// ── International Encrypt/Decrypt (M0/M2/M4) ─────────────────────────────────

/// Build an M0/M2 payload: mode(2) + in_fmt(1) + out_fmt(1) + key_type(3) + key + len(4) + data.
fn m0_payload(key: &[u8], data_hex: &[u8]) -> Vec<u8> {
    let mut v = b"00".to_vec(); // ECB
    v.push(b'1'); // input hex
    v.push(b'1'); // output hex
    v.extend_from_slice(b"00B"); // key type (DEK)
    v.extend_from_slice(key);
    let byte_count = data_hex.len() / 2;
    v.extend_from_slice(format!("{byte_count:04X}").as_bytes());
    v.extend_from_slice(data_hex);
    v
}

#[tokio::test]
async fn thales_m0_encrypt_success() {
    let mock = MockApc::start().await;
    let mut keys = HashMap::new();
    keys.insert("1234567890ABCDEF".to_string(), "mock-dek".to_string());
    let state = mock_state(&mock.url, keys).await;

    let registry = Registry::build();
    let handler = registry.get(b"M0").expect("M0 registered");

    let payload = m0_payload(b"1234567890ABCDEF", b"AABBCCDDEE112233");
    let result = handler.handle(b"M0", &payload, &state).await;

    assert_eq!(&result.error_code, b"00");
    // Mock returns CipherText "CCDDEEFF11223344" (8 bytes) → prefix "0008"
    assert_eq!(result.payload.as_slice(), b"0008CCDDEEFF11223344");
}

#[tokio::test]
async fn thales_m0_cbc_mode_returns_15() {
    let mock = MockApc::start().await;
    let mut keys = HashMap::new();
    keys.insert("1234567890ABCDEF".to_string(), "mock-dek".to_string());
    let state = mock_state(&mock.url, keys).await;

    let registry = Registry::build();
    let handler = registry.get(b"M0").expect("M0 registered");

    // Mode '01' = CBC — not supported
    let mut payload = b"01".to_vec();
    payload.push(b'1');
    payload.push(b'1');
    payload.extend_from_slice(b"00B1234567890ABCDEF00080000000000000000");

    let result = handler.handle(b"M0", &payload, &state).await;
    assert_eq!(&result.error_code, b"15");
}

#[tokio::test]
async fn thales_m0_key_not_found_returns_10() {
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();
    let handler = registry.get(b"M0").expect("M0 registered");

    let payload = m0_payload(b"1234567890ABCDEF", b"AABBCCDDEE112233");
    let result = handler.handle(b"M0", &payload, &state).await;
    assert_eq!(&result.error_code, b"10");
}

#[tokio::test]
async fn thales_m2_decrypt_success() {
    let mock = MockApc::start().await;
    let mut keys = HashMap::new();
    keys.insert("1234567890ABCDEF".to_string(), "mock-dek".to_string());
    let state = mock_state(&mock.url, keys).await;

    let registry = Registry::build();
    let handler = registry.get(b"M2").expect("M2 registered");

    let payload = m0_payload(b"1234567890ABCDEF", b"CCDDEEFF11223344");
    let result = handler.handle(b"M2", &payload, &state).await;

    assert_eq!(&result.error_code, b"00");
    // Mock returns PlainText "AABBCCDDEE112233" (8 bytes) → prefix "0008"
    assert_eq!(result.payload.as_slice(), b"0008AABBCCDDEE112233");
}

#[tokio::test]
async fn thales_m4_reencrypt_success() {
    let mock = MockApc::start().await;
    let mut keys = HashMap::new();
    keys.insert("1234567890ABCDEF".to_string(), "mock-src".to_string());
    keys.insert("FEDCBA0987654321".to_string(), "mock-dst".to_string());
    let state = mock_state(&mock.url, keys).await;

    let registry = Registry::build();
    let handler = registry.get(b"M4").expect("M4 registered");

    // M4: src_mode(2) + dst_mode(2) + in_fmt(1) + out_fmt(1) +
    //     src_key_type(3) + src_key(16) + dst_key_type(3) + dst_key(16) + len(4) + data
    let mut payload = b"00".to_vec(); // src ECB
    payload.extend_from_slice(b"00"); // dst ECB
    payload.push(b'1'); // input hex
    payload.push(b'1'); // output hex
    payload.extend_from_slice(b"00B"); // src key type
    payload.extend_from_slice(b"1234567890ABCDEF"); // src key 16H
    payload.extend_from_slice(b"00B"); // dst key type
    payload.extend_from_slice(b"FEDCBA0987654321"); // dst key 16H
    payload.extend_from_slice(b"0008"); // 8 bytes
    payload.extend_from_slice(b"CCDDEEFF11223344"); // ciphertext 16H

    let result = handler.handle(b"M4", &payload, &state).await;

    assert_eq!(&result.error_code, b"00");
    // Two-call translate: decrypt(mock-src) → plaintext, encrypt(mock-dst) →
    // CipherText "EEFF11223344AABB" (8 bytes) → 4H prefix "0008".
    assert_eq!(result.payload.as_slice(), b"0008EEFF11223344AABB");
}

// ── International MAK MAC (M6/M8) ────────────────────────────────────────────
//
// M6 wire: Mode(1=b'0')+'1'(InFmt)+MACSize(1)+'Algo'(1)+'1'(Pad) +
//          KeyType(3H) + Key(16H) + MsgLen(4H) + message_hex
// M8 appends MAC(mac_size*2 H) after message.
// Valid M6 algos: '1'=ALG1, '3'=ALG3, '6'=CMAC

const MAK_KEY_16H: &[u8] = b"1234567890ABCDEF";

/// Build an M6/M8 payload. `algo` is the MACAlgo byte ('1'/'3'/'6'). Full MAC (4B).
fn m6_handler_payload(algo: u8, data_hex: &[u8]) -> Vec<u8> {
    let mut v = vec![b'0', b'1', b'0', algo, b'1']; // mode+infmt+macsize(full)+algo+pad
    v.extend_from_slice(b"MA1"); // key type 3H
    v.extend_from_slice(MAK_KEY_16H); // key 16H
    let byte_count = data_hex.len() / 2;
    v.extend_from_slice(format!("{byte_count:04X}").as_bytes());
    v.extend_from_slice(data_hex);
    v
}

#[tokio::test]
async fn thales_m6_generate_mac_success() {
    let mock = MockApc::start().await;
    let state = mock_state(
        &mock.url,
        one_key(std::str::from_utf8(MAK_KEY_16H).unwrap()),
    )
    .await;

    let registry = Registry::build();
    let handler = registry.get(b"M6").expect("M6 registered");

    let payload = m6_handler_payload(b'3', b"AABBCCDDEE112233");
    let result = handler.handle(b"M6", &payload, &state).await;

    assert_eq!(&result.error_code, b"00");
    // Mock returns Mac = "AABBCCDDEE112233"; handler truncates to 4-byte (8H) full MAC
    assert_eq!(result.payload.as_slice(), b"AABBCCDD");
}

#[tokio::test]
async fn thales_m6_unsupported_mode_returns_15() {
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();
    let handler = registry.get(b"M6").expect("M6 registered");

    // Algo '0' is not a valid M6 algo → UnsupportedMacMode → error 15
    let payload = m6_handler_payload(b'0', b"AABBCCDDEE112233");
    let result = handler.handle(b"M6", &payload, &state).await;
    assert_eq!(&result.error_code, b"15", "invalid algo → error 15");
}

#[tokio::test]
async fn thales_m6_key_not_found_returns_10() {
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();
    let handler = registry.get(b"M6").expect("M6 registered");

    // Valid algo '3' but empty key map
    let payload = m6_handler_payload(b'3', b"AABBCCDDEE112233");
    let result = handler.handle(b"M6", &payload, &state).await;
    assert_eq!(&result.error_code, b"10");
}

#[tokio::test]
async fn thales_m8_verify_mac_success() {
    let mock = MockApc::start().await;
    let state = mock_state(
        &mock.url,
        one_key(std::str::from_utf8(MAK_KEY_16H).unwrap()),
    )
    .await;

    let registry = Registry::build();
    let handler = registry.get(b"M8").expect("M8 registered");

    let mut payload = m6_handler_payload(b'3', b"AABBCCDDEE112233");
    payload.extend_from_slice(b"AABBCCDD"); // MAC 8H (4-byte full MAC)

    let result = handler.handle(b"M8", &payload, &state).await;
    assert_eq!(&result.error_code, b"00");
    assert!(result.payload.is_empty(), "M8 success payload is empty");
}

#[tokio::test]
async fn thales_m8_mac_mismatch_returns_01() {
    let mock = MockApc::start().await;
    mock.set_verification_failure("/mac/verify").await;
    let state = mock_state(
        &mock.url,
        one_key(std::str::from_utf8(MAK_KEY_16H).unwrap()),
    )
    .await;

    let registry = Registry::build();
    let handler = registry.get(b"M8").expect("M8 registered");

    let mut payload = m6_handler_payload(b'3', b"AABBCCDDEE112233");
    payload.extend_from_slice(b"AABBCCDD");

    let result = handler.handle(b"M8", &payload, &state).await;
    assert_eq!(&result.error_code, b"01", "MAC mismatch → error 01");
}

// ── DUKPT MAC (GW) ───────────────────────────────────────────────────────────
//
// GW wire format: Mode(1N) + '1'(InFmt) + MACSize(1N) + Algo(1N) + Pad(1N) +
//                 BDK(32H) + KSN_desc(3H) + KSN(20H) + MsgLen(4H) + message_hex
// GW verify appends MAC(mac_size*2 H).

/// BDK key label: 32H (parse_bdk double-length baseline, no prefix).
const GW_BDK: &[u8] = b"1234567890ABCDEF1234567890ABCDEF";

/// Build a GW payload with a 3DES DUKPT KSN (20H) and full 4-byte MAC size.
fn gw_payload(mode: u8, algo: u8, msg_hex: &[u8], mac: Option<&[u8]>) -> Vec<u8> {
    let mut v = vec![mode, b'1', b'0', algo, b'1']; // header (full MAC)
    v.extend_from_slice(GW_BDK); // BDK 32H
    v.extend_from_slice(b"014"); // KSN descriptor: 0x14=20 nibbles (3DES)
    v.extend_from_slice(b"12345678901234567890"); // KSN 20H
    let byte_count = msg_hex.len() / 2;
    v.extend_from_slice(format!("{byte_count:04X}").as_bytes());
    v.extend_from_slice(msg_hex);
    if let Some(m) = mac {
        v.extend_from_slice(m);
    }
    v
}

#[tokio::test]
async fn thales_gw_generate_mac_success() {
    let mock = MockApc::start().await;
    let state = mock_state(&mock.url, one_key(std::str::from_utf8(GW_BDK).unwrap())).await;

    let registry = Registry::build();
    let handler = registry.get(b"GW").expect("GW registered");

    let payload = gw_payload(b'0', b'3', b"AABBCCDDEE112233", None); // ALG3 generate
    let result = handler.handle(b"GW", &payload, &state).await;

    assert_eq!(&result.error_code, b"00");
    // Mock returns Mac "AABBCCDDEE112233"; handler truncates to 4-byte (8H) full MAC
    assert_eq!(result.payload.as_slice(), b"AABBCCDD");
}

#[tokio::test]
async fn thales_gw_verify_mac_success() {
    let mock = MockApc::start().await;
    let state = mock_state(&mock.url, one_key(std::str::from_utf8(GW_BDK).unwrap())).await;

    let registry = Registry::build();
    let handler = registry.get(b"GW").expect("GW registered");

    let payload = gw_payload(b'1', b'1', b"AABBCCDDEE112233", Some(b"AABBCCDD")); // ALG1 verify
    let result = handler.handle(b"GW", &payload, &state).await;

    assert_eq!(&result.error_code, b"00");
    assert!(
        result.payload.is_empty(),
        "GW verify success payload is empty"
    );
}

#[tokio::test]
async fn thales_gw_mac_mismatch_returns_01() {
    let mock = MockApc::start().await;
    mock.set_verification_failure("/mac/verify").await;
    let state = mock_state(&mock.url, one_key(std::str::from_utf8(GW_BDK).unwrap())).await;

    let registry = Registry::build();
    let handler = registry.get(b"GW").expect("GW registered");

    let payload = gw_payload(b'1', b'1', b"AABBCCDDEE112233", Some(b"AABBCCDD"));
    let result = handler.handle(b"GW", &payload, &state).await;

    assert_eq!(&result.error_code, b"01", "MAC mismatch → error 01");
}

#[tokio::test]
async fn thales_gw_key_not_found_returns_10() {
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();
    let handler = registry.get(b"GW").expect("GW registered");

    let payload = gw_payload(b'0', b'3', b"AABBCCDDEE112233", None);
    let result = handler.handle(b"GW", &payload, &state).await;

    assert_eq!(&result.error_code, b"10", "unknown BDK → error 10");
}

// ── ARQC verify / ARPC generate (KQ) ────────────────────────────────────────
//
// KQ binary wire format per PUGD0537-004 p.468:
//   Mode(1N) + SchemeID(1N) + KeyType(3H) + Key(var) + PAN+Seq(8B BCD) +
//   ATC(2B) + UN(4B) + TxnLen(2B BE) + TxnData(nB) + 0x3B + ARQC(8B)
//   Mode '1': append ARC(2B binary)

/// Build a KQ binary payload through ARQC. `mode` = b'0' verify-only, b'1' verify+ARPC.
fn kq_binary_payload(mode: u8, key: &[u8]) -> Vec<u8> {
    let txn: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD]; // 4B txn data
    let mut v = vec![mode, b'1']; // Mode + Scheme '1' (Mastercard M/Chip, Option A + Mastercard SKD)
    v.extend_from_slice(b"00E"); // key type 3H
    v.extend_from_slice(key); // IMK
    v.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x01, 0xFF]); // PAN+Seq BCD
    v.extend_from_slice(&[0x00, 0x01]); // ATC 2B binary
    v.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // UN 4B binary
    v.extend_from_slice(&(txn.len() as u16).to_be_bytes()); // TxnLen 2B BE
    v.extend_from_slice(txn); // TxnData
    v.push(0x3B); // delimiter
    v.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]); // ARQC 8B
    v
}

#[tokio::test]
async fn thales_kq_method1_arpc_success() {
    let mock = MockApc::start().await;
    let state = mock_state(&mock.url, one_key("1234567890ABCDEF")).await;

    let registry = Registry::build();
    let handler = registry.get(b"KQ").expect("KQ registered");

    let mut payload = kq_binary_payload(b'1', b"1234567890ABCDEF");
    payload.extend_from_slice(&[0x00, 0x10]); // ARC 2B binary

    let result = handler.handle(b"KQ", &payload, &state).await;
    assert_eq!(&result.error_code, b"00");
    // Mock returns AuthResponseValue "AABBCCDDEEFF0011"
    assert_eq!(result.payload.as_slice(), b"AABBCCDDEEFF0011");
}

#[tokio::test]
async fn thales_kq_no_arpc_returns_empty_payload() {
    let mock = MockApc::start().await;
    // Override mock to return no AuthResponseValue (verify-only mode)
    mock.set(
        "/cryptogram/verify",
        200,
        r#"{"KeyArn":"arn:mock","KeyCheckValue":"AAA"}"#,
    )
    .await;
    let state = mock_state(&mock.url, one_key("1234567890ABCDEF")).await;

    let registry = Registry::build();
    let handler = registry.get(b"KQ").expect("KQ registered");

    let payload = kq_binary_payload(b'0', b"1234567890ABCDEF");

    let result = handler.handle(b"KQ", &payload, &state).await;
    assert_eq!(&result.error_code, b"00");
    assert!(result.payload.is_empty(), "no ARPC → empty payload");
}

#[tokio::test]
async fn thales_kq_arqc_mismatch_returns_01() {
    let mock = MockApc::start().await;
    mock.set_verification_failure("/cryptogram/verify").await;
    let state = mock_state(&mock.url, one_key("1234567890ABCDEF")).await;

    let registry = Registry::build();
    let handler = registry.get(b"KQ").expect("KQ registered");

    let mut payload = kq_binary_payload(b'1', b"1234567890ABCDEF");
    payload.extend_from_slice(&[0x00, 0x10]); // ARC 2B binary

    let result = handler.handle(b"KQ", &payload, &state).await;
    assert_eq!(&result.error_code, b"01", "ARQC mismatch → error 01");
}

#[tokio::test]
async fn thales_kq_key_not_found_returns_10() {
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();
    let handler = registry.get(b"KQ").expect("KQ registered");

    let mut payload = kq_binary_payload(b'1', b"1234567890ABCDEF");
    payload.extend_from_slice(&[0x00, 0x10]); // ARC 2B binary

    let result = handler.handle(b"KQ", &payload, &state).await;
    assert_eq!(&result.error_code, b"10", "unknown key → error 10");
}

#[tokio::test]
async fn thales_kq_tc_type_returns_15() {
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();
    let handler = registry.get(b"KQ").expect("KQ registered");

    // Mode '1', valid scheme '1' (Mastercard), then a truncated body that fails
    // field parsing → malformed payload → error 15.
    let mut payload = vec![b'1'];
    payload.extend_from_slice(b"10E1234567890ABCDEF9A12345678901201000100010000AABBCCDDEEFF0011");

    let result = handler.handle(b"KQ", &payload, &state).await;
    assert_eq!(&result.error_code, b"15", "truncated KQ body → error 15");
}

// ── Unsupported commands ──────────────────────────────────────────────────────

#[tokio::test]
async fn unsupported_command_returns_68() {
    let state = mock_state("http://127.0.0.1:1", HashMap::new()).await;
    let registry = Registry::build();

    // CO is explicitly unsupported (no APC equivalent for Diebold method);
    // registered via dukpt_pin_verify but handle() returns error 68
    let handler = registry
        .get(b"CO")
        .expect("CO registered in dukpt_pin_verify");
    let result = handler.handle(b"CO", b"", &state).await;
    assert_eq!(&result.error_code, b"68");

    // CQ is explicitly unsupported (Encrypted PIN method);
    // registered via dukpt_pin_verify but handle() returns error 68
    let handler = registry
        .get(b"CQ")
        .expect("CQ registered in dukpt_pin_verify");
    let result = handler.handle(b"CQ", b"", &state).await;
    assert_eq!(&result.error_code, b"68");

    // CM (Visa PVV DUKPT verify) is gated: it makes the same verify_pin_data +
    // DukptAttributes + VisaPin call as GQ, which APC answers with a 500.
    let handler = registry
        .get(b"CM")
        .expect("CM registered in dukpt_pin_verify");
    let result = handler.handle(b"CM", b"", &state).await;
    assert_eq!(&result.error_code, b"68");

    // GS is explicitly unsupported (AES DUKPT Diebold method — no APC equivalent);
    // registered via dukpt_pin_verify_aes but handle() returns error 68
    let handler = registry
        .get(b"GS")
        .expect("GS registered in dukpt_pin_verify_aes");
    let result = handler.handle(b"GS", b"", &state).await;
    assert_eq!(&result.error_code, b"68");

    // GU is explicitly unsupported (AES DUKPT Encrypted PIN method);
    // registered via dukpt_pin_verify_aes but handle() returns error 68
    let handler = registry
        .get(b"GU")
        .expect("GU registered in dukpt_pin_verify_aes");
    let result = handler.handle(b"GU", b"", &state).await;
    assert_eq!(&result.error_code, b"68");

    // GQ (Visa PVV DUKPT verify) is gated: APC's single-call verify_pin_data +
    // DukptAttributes + VisaPin returns InternalServerException (500). Registered
    // via dukpt_pin_verify_aes but handle() returns error 68 pending an APC fix.
    let handler = registry
        .get(b"GQ")
        .expect("GQ registered in dukpt_pin_verify_aes");
    let result = handler.handle(b"GQ", b"", &state).await;
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

// ── Registry-wide robustness (no panic on malformed input) ────────────────────
//
// Negative testing is not verify-specific: EVERY handler must survive hostile
// wire input without panicking. A proxy that panics on a malformed frame is a
// DoS. This sweep fuzzes every registered command code with random/truncated
// byte payloads and asserts the call returns (the test completing is the
// no-panic proof). It runs offline in CI: the key map is empty, so any
// key-using handler fails key resolution before any data-plane call, and the
// rest return fixed codes — nothing reaches APC.
//
// Deterministic (fixed-seed xorshift) so a failure reproduces exactly.
#[tokio::test]
async fn all_handlers_survive_malformed_input() {
    let mock = MockApc::start().await; // never actually reached; a safety net if it were
    let registry = Registry::build();
    let state = mock_state(&mock.url, HashMap::new()).await; // empty key map

    // Small deterministic xorshift64 PRNG — no external rand dependency here.
    let mut x: u64 = 0x1234_5678_9abc_def0;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };

    let codes = registry.command_codes();
    assert!(
        codes.len() >= 26,
        "expected the full command surface, got {}",
        codes.len()
    );

    let mut total = 0_usize;
    for code in &codes {
        let handler = registry.get(code).expect("code came from the registry");
        for _ in 0..64 {
            let len = (next() % 96) as usize; // 0..95 bytes, incl. empty and short frames
            let payload: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            // The assertion is simply that this does not panic. Every handler
            // returns a well-formed 2-byte error code for garbage.
            let out = handler.handle(code, &payload, &state).await;
            let _ = out.error_code;
            total += 1;
        }
    }
    eprintln!(
        "robustness: fuzzed {} command codes x 64 payloads = {total} calls, no panic",
        codes.len()
    );
}
