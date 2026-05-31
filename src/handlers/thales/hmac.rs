use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_legacy_key;
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield International Host Commands — HMAC generation and verification.
///
/// LQ (→ LR): Generate an HMAC on a Block of Data
/// LS (→ LT): Verify an HMAC on a Block of Data
///
/// Source: PUGD0537-004 Rev A, p.405 (LQ) and p.407 (LS). AUTHORITATIVE per apc-agent.
/// Wire format inferred from International Host Command patterns (M6/M8 family) — treat
/// field positions as reference-quality until the full International Host Commands PDF is
/// available for cross-check.
///
/// ## Inferred LQ field layout
///   [1N] SHA Variant: '1'=SHA-1, '2'=SHA-256, '3'=SHA-384, '4'=SHA-512
///   [variable] HMAC Key (16H | U+32H | T+48H, encrypted under LMK)
///   [4H] Message Length in bytes (hex-encoded, e.g. "0020" = 32 bytes)
///   [nH] Message Data (hex-encoded, n = 2 × Message Length)
///
/// LR response (after header):
///   [2H] Error Code
///   [nH] HMAC Value (hex; 40H for SHA-1, 64H for SHA-256, 96H for SHA-384, 128H for SHA-512)
///
/// ## Inferred LS field layout
///   [1N] SHA Variant
///   [variable] HMAC Key
///   [4H] Message Length
///   [nH] Message Data
///   [nH] HMAC to Verify (appended, same length formula as LQ output)
///
/// LT response:
///   [2H] Error Code (00=success, 01=mismatch)
///
/// ## APC mapping
///   LQ → generate_mac with TR31_M7_HMAC_KEY:
///     SHA-1  → MacAlgorithm::Hmac
///     SHA-256 → MacAlgorithm::HmacSha256
///     SHA-384 → MacAlgorithm::HmacSha384
///     SHA-512 → MacAlgorithm::HmacSha512
///   LS → verify_mac with TR31_M7_HMAC_KEY
pub struct HmacHandler;

const MSG_LEN_FIELD: usize = 4;

fn sha_variant(byte: u8, cmd: &str) -> Result<MacAlgorithmHmac, ProxyError> {
    match byte {
        b'1' => Ok(MacAlgorithmHmac::Sha1),
        b'2' => Ok(MacAlgorithmHmac::Sha256),
        b'3' => Ok(MacAlgorithmHmac::Sha384),
        b'4' => Ok(MacAlgorithmHmac::Sha512),
        other => Err(ProxyError::UnsupportedMacMode(format!(
            "{cmd}: SHA variant '{}' not supported (expected '1'-'4')",
            other as char
        ))),
    }
}

enum MacAlgorithmHmac {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl MacAlgorithmHmac {
    fn apc_algorithm(&self) -> aws_sdk_paymentcryptographydata::types::MacAlgorithm {
        use aws_sdk_paymentcryptographydata::types::MacAlgorithm;
        match self {
            MacAlgorithmHmac::Sha1 => MacAlgorithm::Hmac,
            MacAlgorithmHmac::Sha256 => MacAlgorithm::HmacSha256,
            MacAlgorithmHmac::Sha384 => MacAlgorithm::HmacSha384,
            MacAlgorithmHmac::Sha512 => MacAlgorithm::HmacSha512,
        }
    }

    /// HMAC output length in hex chars (2 per byte).
    fn output_hex_len(&self) -> usize {
        match self {
            MacAlgorithmHmac::Sha1 => 40,    // 20 bytes
            MacAlgorithmHmac::Sha256 => 64,  // 32 bytes
            MacAlgorithmHmac::Sha384 => 96,  // 48 bytes
            MacAlgorithmHmac::Sha512 => 128, // 64 bytes
        }
    }
}

struct LqFields {
    key_id: KeyDescriptor,
    algorithm: MacAlgorithmHmac,
    message_hex: String,
}

fn parse_lq_fields(payload: &[u8], cmd: &str) -> Result<LqFields, ProxyError> {
    if payload.is_empty() {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: empty payload"
        )));
    }

    let algorithm = sha_variant(payload[0], cmd)?;
    let (key_id, key_consumed) = parse_legacy_key(payload, 1)?;
    let pos = 1 + key_consumed;

    if payload.len() < pos + MSG_LEN_FIELD {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: message length field missing"
        )));
    }
    let len_str = std::str::from_utf8(&payload[pos..pos + MSG_LEN_FIELD])
        .map_err(|_| ProxyError::MalformedPayload(format!("{cmd}: message length not ASCII")))?;
    let byte_count = usize::from_str_radix(len_str, 16).map_err(|_| {
        ProxyError::MalformedPayload(format!("{cmd}: invalid message length '{len_str}'"))
    })?;

    let msg_start = pos + MSG_LEN_FIELD;
    let msg_hex_chars = byte_count * 2;
    if payload.len() < msg_start + msg_hex_chars {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: message truncated (need {msg_hex_chars} hex chars)"
        )));
    }
    let message_hex =
        String::from_utf8_lossy(&payload[msg_start..msg_start + msg_hex_chars]).to_string();

    Ok(LqFields {
        key_id,
        algorithm,
        message_hex,
    })
}

#[async_trait]
impl Handler for HmacHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["LQ", "LS"]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"LQ" => handle_lq(payload, state).await,
            b"LS" => handle_ls(payload, state).await,
            _ => HandlerResult::err(*b"68"),
        }
    }
}

async fn handle_lq(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_lq_fields(payload, "LQ") {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&fields.key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::MacAttributes;
    let alg = fields.algorithm.apc_algorithm();
    debug!(key = %key_arn, ?alg, "LQ: generate_mac HMAC");

    match state
        .data
        .generate_mac()
        .key_identifier(&key_arn)
        .message_data(&fields.message_hex)
        .generation_attributes(MacAttributes::Algorithm(alg))
        .send()
        .await
    {
        Ok(resp) => HandlerResult::success(resp.mac().as_bytes().to_vec()),
        Err(e) => {
            warn!(?e, "LQ: generate_mac failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_ls(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    // Parse the common header (same as LQ: variant + key + msg_len + message)
    if payload.is_empty() {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "LS: empty payload".into(),
        ));
    }
    let algorithm = match sha_variant(payload[0], "LS") {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let hmac_hex_len = algorithm.output_hex_len();

    let (key_id, key_consumed) = match parse_legacy_key(payload, 1) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pos = 1 + key_consumed;

    if payload.len() < pos + MSG_LEN_FIELD {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "LS: message length field missing".into(),
        ));
    }
    let Ok(len_str) = std::str::from_utf8(&payload[pos..pos + MSG_LEN_FIELD]) else {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "LS: message length not ASCII".into(),
        ));
    };
    let Ok(byte_count) = usize::from_str_radix(len_str, 16) else {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "LS: invalid message length '{len_str}'"
        )));
    };

    let msg_start = pos + MSG_LEN_FIELD;
    let msg_hex_chars = byte_count * 2;
    let hmac_start = msg_start + msg_hex_chars;

    if payload.len() < hmac_start + hmac_hex_len {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "LS: payload too short for message ({msg_hex_chars}H) + HMAC ({hmac_hex_len}H)"
        )));
    }

    let message_hex =
        String::from_utf8_lossy(&payload[msg_start..msg_start + msg_hex_chars]).to_string();
    let hmac_val =
        String::from_utf8_lossy(&payload[hmac_start..hmac_start + hmac_hex_len]).to_string();

    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::MacAttributes;
    let alg = algorithm.apc_algorithm();
    debug!(key = %key_arn, ?alg, "LS: verify_mac HMAC");

    match state
        .data
        .verify_mac()
        .key_identifier(&key_arn)
        .message_data(&message_hex)
        .mac(&hmac_val)
        .verification_attributes(MacAttributes::Algorithm(alg))
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error().is_some_and(
                aws_sdk_paymentcryptographydata::operation::verify_mac::VerifyMacError::is_verification_failed_exception,
            ) {
                warn!("LS: HMAC mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "LS: verify_mac failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_lq_payload(sha_char: u8, key: &[u8], message: &[u8]) -> Vec<u8> {
        // message is already hex-encoded
        let mut v = vec![sha_char];
        v.extend_from_slice(key);
        let byte_count = message.len() / 2;
        v.extend_from_slice(format!("{:04X}", byte_count).as_bytes());
        v.extend_from_slice(message);
        v
    }

    fn single_key() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec()
    }

    // ── sha_variant ───────────────────────────────────────────────────────────

    #[test]
    fn sha_variant_maps_1_to_sha1() {
        assert!(matches!(
            sha_variant(b'1', "T").unwrap(),
            MacAlgorithmHmac::Sha1
        ));
    }

    #[test]
    fn sha_variant_maps_2_to_sha256() {
        assert!(matches!(
            sha_variant(b'2', "T").unwrap(),
            MacAlgorithmHmac::Sha256
        ));
    }

    #[test]
    fn sha_variant_maps_3_to_sha384() {
        assert!(matches!(
            sha_variant(b'3', "T").unwrap(),
            MacAlgorithmHmac::Sha384
        ));
    }

    #[test]
    fn sha_variant_maps_4_to_sha512() {
        assert!(matches!(
            sha_variant(b'4', "T").unwrap(),
            MacAlgorithmHmac::Sha512
        ));
    }

    #[test]
    fn sha_variant_rejects_unknown() {
        assert!(sha_variant(b'5', "T").is_err());
        assert!(sha_variant(b'0', "T").is_err());
    }

    // ── output_hex_len ────────────────────────────────────────────────────────

    #[test]
    fn output_hex_len_sha1() {
        assert_eq!(MacAlgorithmHmac::Sha1.output_hex_len(), 40);
    }

    #[test]
    fn output_hex_len_sha256() {
        assert_eq!(MacAlgorithmHmac::Sha256.output_hex_len(), 64);
    }

    #[test]
    fn output_hex_len_sha384() {
        assert_eq!(MacAlgorithmHmac::Sha384.output_hex_len(), 96);
    }

    #[test]
    fn output_hex_len_sha512() {
        assert_eq!(MacAlgorithmHmac::Sha512.output_hex_len(), 128);
    }

    // ── parse_lq_fields ──────────────────────────────────────────────────────

    #[test]
    fn lq_parse_sha256_single_key() {
        // SHA variant '2' + 16H key + 4H len "0004" + 4 bytes = "AABBCCDD"
        let payload = build_lq_payload(b'2', &single_key(), b"AABBCCDD");
        let fields = parse_lq_fields(&payload, "LQ").unwrap();
        assert_eq!(fields.key_id.raw, "1234567890ABCDEF");
        assert!(matches!(fields.algorithm, MacAlgorithmHmac::Sha256));
        assert_eq!(fields.message_hex, "AABBCCDD");
    }

    #[test]
    fn lq_parse_sha1_double_key() {
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = build_lq_payload(b'1', &key, b"DEADBEEF");
        let fields = parse_lq_fields(&payload, "LQ").unwrap();
        assert!(fields.key_id.raw.starts_with('U'));
        assert!(matches!(fields.algorithm, MacAlgorithmHmac::Sha1));
        assert_eq!(fields.message_hex, "DEADBEEF");
    }

    #[test]
    fn lq_rejects_empty() {
        assert!(parse_lq_fields(b"", "LQ").is_err());
    }

    #[test]
    fn lq_rejects_bad_sha_variant() {
        let mut payload = vec![b'9'];
        payload.extend_from_slice(&single_key());
        payload.extend_from_slice(b"00020000");
        assert!(parse_lq_fields(&payload, "LQ").is_err());
    }

    #[test]
    fn lq_rejects_truncated_message() {
        // Manually build payload that claims 8 bytes but only 4 follow
        let mut bad = vec![b'2'];
        bad.extend_from_slice(&single_key());
        bad.extend_from_slice(b"0008"); // claims 8 bytes = 16 hex chars
        bad.extend_from_slice(b"AABB"); // only 4 hex chars
        assert!(parse_lq_fields(&bad, "LQ").is_err());
    }

    // ── LS format checks ──────────────────────────────────────────────────────

    #[test]
    fn ls_parse_variant_and_hmac_offset() {
        // Build LS payload: '2' + key + 4H len + message + 64H HMAC (SHA-256)
        let message = b"AABBCCDD"; // 4 hex chars = 2 bytes
        let hmac: Vec<u8> = vec![b'A'; 64]; // 64 hex chars = 32 bytes

        let mut payload = vec![b'2'];
        payload.extend_from_slice(&single_key());
        let byte_count = message.len() / 2;
        payload.extend_from_slice(format!("{:04X}", byte_count).as_bytes());
        payload.extend_from_slice(message);
        payload.extend_from_slice(&hmac);

        // Verify positions are parseable:
        let alg = sha_variant(payload[0], "LS").unwrap();
        let hmac_hex_len = alg.output_hex_len();
        assert_eq!(hmac_hex_len, 64);
        let (_, key_consumed) = parse_legacy_key(&payload, 1).unwrap();
        assert_eq!(key_consumed, 16); // single key
        let pos = 1 + key_consumed;
        let len_str = std::str::from_utf8(&payload[pos..pos + MSG_LEN_FIELD]).unwrap();
        let bc = usize::from_str_radix(len_str, 16).unwrap();
        let msg_start = pos + MSG_LEN_FIELD;
        let hmac_start = msg_start + bc * 2;
        assert_eq!(
            &payload[hmac_start..hmac_start + hmac_hex_len],
            hmac.as_slice()
        );
    }
}
