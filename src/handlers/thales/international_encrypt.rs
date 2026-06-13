use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_legacy_key;
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield International block encrypt/decrypt/translate commands.
///
/// M0/M1 — Encrypt a Block of Data  → APC encrypt_data
/// M2/M3 — Decrypt a Block of Data  → APC decrypt_data
/// M4/M5 — Translate a Data Block   → APC re_encrypt_data
///
/// FIELD LAYOUT SOURCE: Inferred from the payShield SEED variant commands (AI/A1/AM),
/// which the Legacy Host Commands manual describes as "similar to M0/M2/M4 in input/output
/// and command processing." The official Thales International Host Commands PDF was not
/// available; treat field positions as reference-quality.
///
/// M0 field layout:
///   Mode Flag:          2N  ('00'=ECB; '01'-'03'=CBC/CFB variants — return error 15)
///   Input Format Flag:  1N  ('1'=Hex-Encoded Binary; others → error 15)
///   Output Format Flag: 1N  ('1'=Hex-Encoded accepted; currently only '1' generated)
///   Key Type:           3H  (e.g. '00B'=DEK, '00A'=ZEK; consumed, key_map resolves)
///   Key:               16H | 'U'+32H | 'T'+48H
///   Message Length:     4H  (hex-encoded byte count, e.g. "0010" = 16 bytes)
///   Message:            2× byte-count hex chars of hex-encoded plaintext
///
/// M2: identical layout to M0 (cipher text in, plain text out).
///
/// M4 field layout:
///   Source Mode Flag:   2N  ('00'=ECB; others → error 15)
///   Dest Mode Flag:     2N  ('00'=ECB; others → error 15)
///   Input Format Flag:  1N  ('1'=Hex only)
///   Output Format Flag: 1N  (accepted)
///   Source Key Type:    3H  (consumed)
///   Source Key:        variable
///   Dest Key Type:      3H  (consumed)
///   Dest Key:          variable
///   Message Length:     4H
///   Message:           nH  (hex-encoded ciphertext under source key)
///
/// APC key expectation: TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY.
/// payShield LMK pairs: DEK→LMK 32-33, ZEK→LMK 30-31.
///
/// KNOWN LIMITATION: Only ECB mode ('00') is supported. CBC/CFB modes require
/// returning an output IV that APC does not expose; they return error 15 until
/// the official International Host Commands doc is available to confirm behaviour.
pub struct InternationalEncryptHandler;

const MODE_FLAG_LEN: usize = 2;
const FORMAT_FLAG_LEN: usize = 1;
const KEY_TYPE_LEN: usize = 3;
const MSG_LEN_FIELD: usize = 4; // 4 hex chars encodes byte count

#[async_trait]
impl Handler for InternationalEncryptHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["M0", "M2", "M4"]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"M0" => handle_m0(payload, state).await,
            b"M2" => handle_m2(payload, state).await,
            b"M4" => handle_m4(payload, state).await,
            _ => HandlerResult::err(*b"68"),
        }
    }
}

/// Parse M0/M2 common prefix and data block.
/// Returns (key_id, msg_hex, cursor) or an error.
fn parse_m0_fields(payload: &[u8]) -> Result<(KeyDescriptor, Zeroizing<String>), ProxyError> {
    let mut pos = 0;

    // Mode Flag (2N)
    if payload.len() < pos + MODE_FLAG_LEN {
        return Err(ProxyError::MalformedPayload(
            "M0/M2: mode flag missing".into(),
        ));
    }
    let mode = &payload[pos..pos + MODE_FLAG_LEN];
    pos += MODE_FLAG_LEN;
    if mode != b"00" {
        return Err(ProxyError::MalformedPayload(format!(
            "M0/M2: mode '{}' not supported (ECB '00' only)",
            String::from_utf8_lossy(mode)
        )));
    }

    // Input Format Flag (1N)
    if payload.len() < pos + FORMAT_FLAG_LEN {
        return Err(ProxyError::MalformedPayload(
            "M0/M2: input format flag missing".into(),
        ));
    }
    if payload[pos] != b'1' {
        return Err(ProxyError::MalformedPayload(format!(
            "M0/M2: input format '{}' not supported (hex '1' only)",
            payload[pos] as char
        )));
    }
    pos += FORMAT_FLAG_LEN;

    // Output Format Flag (1N) — accepted but unused (we always return hex)
    if payload.len() < pos + FORMAT_FLAG_LEN {
        return Err(ProxyError::MalformedPayload(
            "M0/M2: output format flag missing".into(),
        ));
    }
    pos += FORMAT_FLAG_LEN;

    // Key Type (3H) — consumed, key_map resolves the actual key
    if payload.len() < pos + KEY_TYPE_LEN {
        return Err(ProxyError::MalformedPayload(
            "M0/M2: key type field missing".into(),
        ));
    }
    pos += KEY_TYPE_LEN;

    // Key (variable)
    let (key_id, key_consumed) = parse_legacy_key(payload, pos)?;
    pos += key_consumed;

    // Message Length (4H hex chars = hex-encoded byte count)
    if payload.len() < pos + MSG_LEN_FIELD {
        return Err(ProxyError::MalformedPayload(
            "M0/M2: message length field missing".into(),
        ));
    }
    let len_hex = std::str::from_utf8(&payload[pos..pos + MSG_LEN_FIELD])
        .map_err(|_| ProxyError::MalformedPayload("M0/M2: message length not ASCII".into()))?;
    let byte_count = usize::from_str_radix(len_hex, 16).map_err(|_| {
        ProxyError::MalformedPayload(format!("M0/M2: invalid message length '{len_hex}'"))
    })?;
    pos += MSG_LEN_FIELD;

    // Message (2× byte_count hex chars)
    let msg_hex_chars = byte_count * 2;
    if payload.len() < pos + msg_hex_chars {
        return Err(ProxyError::MalformedPayload(format!(
            "M0/M2: message too short: need {} hex chars, got {}",
            msg_hex_chars,
            payload.len().saturating_sub(pos)
        )));
    }
    let msg =
        Zeroizing::new(String::from_utf8_lossy(&payload[pos..pos + msg_hex_chars]).to_string());

    Ok((key_id, msg))
}

async fn handle_m0(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (key_id, plain_text) = match parse_m0_fields(payload) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        EncryptionDecryptionAttributes, EncryptionMode, SymmetricEncryptionAttributes,
    };
    let sym = match SymmetricEncryptionAttributes::builder()
        .mode(EncryptionMode::Ecb)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(key = %key_arn, "M0: encrypt_data TDES-ECB");
    match state
        .data
        .encrypt_data()
        .key_identifier(&key_arn)
        .plain_text(plain_text.as_str())
        .encryption_attributes(EncryptionDecryptionAttributes::Symmetric(sym))
        .send()
        .await
    {
        Ok(resp) => {
            // Response: 4H message length + ciphertext
            let cipher = resp.cipher_text();
            let byte_len = cipher.len() / 2;
            let mut out = format!("{byte_len:04X}").into_bytes();
            out.extend_from_slice(cipher.as_bytes());
            HandlerResult::success(out)
        }
        Err(e) => {
            warn!(?e, "M0: encrypt_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_m2(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (key_id, cipher_text) = match parse_m0_fields(payload) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        EncryptionDecryptionAttributes, EncryptionMode, SymmetricEncryptionAttributes,
    };
    let sym = match SymmetricEncryptionAttributes::builder()
        .mode(EncryptionMode::Ecb)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(key = %key_arn, "M2: decrypt_data TDES-ECB");
    match state
        .data
        .decrypt_data()
        .key_identifier(&key_arn)
        .cipher_text(cipher_text.as_str())
        .decryption_attributes(EncryptionDecryptionAttributes::Symmetric(sym))
        .send()
        .await
    {
        Ok(resp) => {
            let plain = resp.plain_text();
            let byte_len = plain.len() / 2;
            let mut out = format!("{byte_len:04X}").into_bytes();
            out.extend_from_slice(plain.as_bytes());
            HandlerResult {
                error_code: *b"00",
                payload: Zeroizing::new(out),
            }
        }
        Err(e) => {
            warn!(?e, "M2: decrypt_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_m4(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let mut pos = 0;

    // Source Mode Flag (2N)
    if payload.len() < pos + MODE_FLAG_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "M4: source mode flag missing".into(),
        ));
    }
    if &payload[pos..pos + MODE_FLAG_LEN] != b"00" {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "M4: source mode not ECB ('00')".into(),
        ));
    }
    pos += MODE_FLAG_LEN;

    // Dest Mode Flag (2N)
    if payload.len() < pos + MODE_FLAG_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "M4: dest mode flag missing".into(),
        ));
    }
    if &payload[pos..pos + MODE_FLAG_LEN] != b"00" {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "M4: dest mode not ECB ('00')".into(),
        ));
    }
    pos += MODE_FLAG_LEN;

    // Input Format Flag (1N)
    if payload.len() < pos + FORMAT_FLAG_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "M4: input format flag missing".into(),
        ));
    }
    if payload[pos] != b'1' {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "M4: only hex input format '1' supported".into(),
        ));
    }
    pos += FORMAT_FLAG_LEN;

    // Output Format Flag (1N)
    if payload.len() < pos + FORMAT_FLAG_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "M4: output format flag missing".into(),
        ));
    }
    pos += FORMAT_FLAG_LEN;

    // Source Key Type (3H)
    if payload.len() < pos + KEY_TYPE_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "M4: source key type missing".into(),
        ));
    }
    pos += KEY_TYPE_LEN;

    // Source Key (variable)
    let (src_key_id, src_consumed) = match parse_legacy_key(payload, pos) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    pos += src_consumed;

    // Dest Key Type (3H)
    if payload.len() < pos + KEY_TYPE_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "M4: dest key type missing".into(),
        ));
    }
    pos += KEY_TYPE_LEN;

    // Dest Key (variable)
    let (dst_key_id, dst_consumed) = match parse_legacy_key(payload, pos) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    pos += dst_consumed;

    // Message Length (4H)
    if payload.len() < pos + MSG_LEN_FIELD {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "M4: message length field missing".into(),
        ));
    }
    let Ok(len_hex) = std::str::from_utf8(&payload[pos..pos + MSG_LEN_FIELD]) else {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "M4: message length not ASCII".into(),
        ));
    };
    let Ok(byte_count) = usize::from_str_radix(len_hex, 16) else {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "M4: invalid message length '{len_hex}'"
        )));
    };
    pos += MSG_LEN_FIELD;

    // Message (2× byte_count hex chars)
    let msg_hex_chars = byte_count * 2;
    if payload.len() < pos + msg_hex_chars {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "M4: message too short: need {msg_hex_chars} hex chars"
        )));
    }
    let cipher_text =
        Zeroizing::new(String::from_utf8_lossy(&payload[pos..pos + msg_hex_chars]).to_string());

    let src_arn = match state.key_map.resolve_descriptor(&src_key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let dst_arn = match state.key_map.resolve_descriptor(&dst_key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        EncryptionMode, ReEncryptionAttributes, SymmetricEncryptionAttributes,
    };
    let ecb = match SymmetricEncryptionAttributes::builder()
        .mode(EncryptionMode::Ecb)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(src = %src_arn, dst = %dst_arn, "M4: re_encrypt_data TDES-ECB");
    match state
        .data
        .re_encrypt_data()
        .incoming_key_identifier(&src_arn)
        .outgoing_key_identifier(&dst_arn)
        .cipher_text(cipher_text.as_str())
        .incoming_encryption_attributes(ReEncryptionAttributes::Symmetric(ecb.clone()))
        .outgoing_encryption_attributes(ReEncryptionAttributes::Symmetric(ecb))
        .send()
        .await
    {
        Ok(resp) => {
            let new_cipher = resp.cipher_text();
            let byte_len = new_cipher.len() / 2;
            let mut out = format!("{byte_len:04X}").into_bytes();
            out.extend_from_slice(new_cipher.as_bytes());
            HandlerResult::success(out)
        }
        Err(e) => {
            warn!(?e, "M4: re_encrypt_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ecb_hex_payload(key_type: &[u8], key: &[u8], data: &[u8]) -> Vec<u8> {
        // Mode='00' + input_fmt='1' + output_fmt='1' + key_type(3H) + key + len(4H) + data
        let mut v = b"00".to_vec(); // ECB
        v.push(b'1'); // input hex
        v.push(b'1'); // output hex
        v.extend_from_slice(key_type);
        v.extend_from_slice(key);
        let byte_count = data.len() / 2; // data is already hex chars
        v.extend_from_slice(format!("{byte_count:04X}").as_bytes());
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn m0_parse_ecb_hex() {
        let payload = ecb_hex_payload(b"00B", b"1234567890ABCDEF", b"AABBCCDDEE112233");
        let result = parse_m0_fields(&payload);
        assert!(result.is_ok(), "{result:?}");
        let (key_id, msg) = result.unwrap();
        assert_eq!(key_id.raw, "1234567890ABCDEF");
        assert_eq!(msg.as_str(), "AABBCCDDEE112233");
    }

    #[test]
    fn m0_rejects_cbc_mode() {
        let mut payload = b"01".to_vec(); // CBC mode
        payload.push(b'1');
        payload.push(b'1');
        payload.extend_from_slice(b"00B");
        payload.extend_from_slice(b"1234567890ABCDEF");
        payload.extend_from_slice(b"00080000000000000000"); // len + data
        let err = parse_m0_fields(&payload).unwrap_err();
        assert!(matches!(err, ProxyError::MalformedPayload(_)));
    }

    #[test]
    fn m0_rejects_binary_input_format() {
        let mut payload = b"00".to_vec(); // ECB
        payload.push(b'0'); // binary — rejected
        payload.push(b'1');
        payload.extend_from_slice(b"00B1234567890ABCDEF00080000000000000000");
        let err = parse_m0_fields(&payload).unwrap_err();
        assert!(matches!(err, ProxyError::MalformedPayload(_)));
    }

    #[test]
    fn m0_parse_double_length_key() {
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = ecb_hex_payload(b"00B", &key, b"AABBCCDDEE112233");
        let (key_id, _) = parse_m0_fields(&payload).unwrap();
        assert_eq!(key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
    }
}
