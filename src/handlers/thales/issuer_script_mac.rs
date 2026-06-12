use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::thales::common::{bytes_to_hex, decode_bcd_pan_seq, parse_legacy_key};
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield International Host Commands — EMV issuer script MAC generation.
///
/// JU (→ JV): Generate Secure Message with Integrity (UnionPay/CUP)
/// KU (→ KV): Generate Secure Message with Integrity (EMV 3.1.1)
/// KY (→ KZ): Generate Secure Message with Integrity (EMV 4.x)
///
/// Source: PUGD0538-003 p.124 (JU, authoritative); PUGD0537-004 Rev A, p.475 (KU) and p.480 (KY).
/// Wire format inferred from the JU command (UnionPay equivalent in PUGD0538 p.124) and
/// KQ command (same-family binary format) — treat as reference-quality until PUGD0537
/// is available for cross-check.
///
/// ## Inferred field layout (both KU and KY)
///   [1N] Mode Flag
///        '0' = MAC integrity only (supported)
///        '1'-'4' = integrity + confidentiality variants (not supported; return 15)
///   [1N] Scheme ID
///        '0' = Visa/Amex EMV Option A
///        '1' = Mastercard EMV Option B
///   [3H] Key Type (consumed)
///   [variable] MK-SMI Key (16H | U+32H | T+48H, encrypted under LMK)
///   [8B] PAN + PAN Sequence Number (BCD binary: pre-formatted PAN‖PSN, EMV Option A, 16 digits left zero-pad)
///   [2B] ATC (Application Transaction Counter, big-endian binary)
///   [4H] MAC Message Data Length (byte count, hex)
///   [nB] MAC Message Data (raw binary)
///   [1A] Delimiter (';')
///
/// KV / KZ response (after header):
///   [2H] Error Code
///   [16H] MAC (8 bytes hex)
///
/// ## APC mapping
///   Mode '0' → generate_mac with TR31_M6_ISO_9797_5_CMAC_KEY (or M3 / E2 depending on
///   key loaded in APC). The proxy passes the key_map ARN and calls generate_mac with
///   ISO9797_ALGORITHM3. Session key derivation from IMK using ATC + PAN must be done
///   externally; the APC key should be a pre-derived session key stored as TR31_M6 or E2.
///
/// Note: Modes 1-4 (confidentiality + PIN change) require generate_mac_emv_pin_change
/// and additional key/PIN block fields not supported in this handler. They return error 15.
///
/// KY extends KU for EMV 4.x profiles but the wire format is identical for mode '0'.
pub struct IssuerScriptMacHandler;

const KEY_TYPE_LEN: usize = 3;
const PAN_SEQ_BINARY_LEN: usize = 8;
const ATC_BINARY_LEN: usize = 2;
const MAC_DATA_LEN_FIELD: usize = 4;
const DELIMITER: u8 = b';';

struct KuFields {
    key_id: KeyDescriptor,
    pan: String,
    atc: String,
    mac_data_hex: String,
}

fn parse_ku_fields(payload: &[u8], cmd: &str) -> Result<KuFields, ProxyError> {
    let mut pos = 0;

    // Mode Flag (1N)
    if payload.is_empty() {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: empty payload"
        )));
    }
    match payload[pos] {
        b'0' => {}
        b'1'..=b'4' => {
            return Err(ProxyError::MalformedPayload(format!(
                "{cmd}: mode '{}' (confidentiality/PIN-change) not supported by this proxy \
                 (APC requires generate_mac_emv_pin_change with separate SMC key and PIN block)",
                payload[pos] as char
            )))
        }
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "{cmd}: invalid mode flag '{}'",
                other as char
            )))
        }
    }
    pos += 1;

    // Scheme ID (1N) — consumed; accepted but not used for MAC-only mode
    if payload.len() < pos + 1 {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: scheme ID missing"
        )));
    }
    pos += 1;

    // Key Type (3H) — consumed
    if payload.len() < pos + KEY_TYPE_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: key type field missing"
        )));
    }
    pos += KEY_TYPE_LEN;

    // MK-SMI Key (variable)
    let (key_id, key_consumed) = parse_legacy_key(payload, pos)?;
    pos += key_consumed;

    // PAN + PAN Sequence (8B binary BCD)
    if payload.len() < pos + PAN_SEQ_BINARY_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: PAN/seq field missing"
        )));
    }
    let pan_seq_bytes: [u8; 8] = payload[pos..pos + PAN_SEQ_BINARY_LEN]
        .try_into()
        .map_err(|_| ProxyError::MalformedPayload(format!("{cmd}: PAN/seq slice error")))?;
    let (pan, _pan_seq) = decode_bcd_pan_seq(pan_seq_bytes);
    pos += PAN_SEQ_BINARY_LEN;

    // ATC (2B binary big-endian)
    if payload.len() < pos + ATC_BINARY_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: ATC field missing"
        )));
    }
    let atc = bytes_to_hex(&payload[pos..pos + ATC_BINARY_LEN]);
    pos += ATC_BINARY_LEN;

    // MAC Message Data Length (4H)
    if payload.len() < pos + MAC_DATA_LEN_FIELD {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: MAC data length field missing"
        )));
    }
    let len_str = std::str::from_utf8(&payload[pos..pos + MAC_DATA_LEN_FIELD])
        .map_err(|_| ProxyError::MalformedPayload(format!("{cmd}: MAC data length not ASCII")))?;
    let byte_count = usize::from_str_radix(len_str, 16).map_err(|_| {
        ProxyError::MalformedPayload(format!("{cmd}: invalid MAC data length '{len_str}'"))
    })?;
    pos += MAC_DATA_LEN_FIELD;

    // MAC Message Data (nB binary)
    if payload.len() < pos + byte_count {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: MAC data truncated (need {byte_count}B)"
        )));
    }
    let mac_data_hex = bytes_to_hex(&payload[pos..pos + byte_count]);
    pos += byte_count;

    // Delimiter (';')
    if payload.len() < pos + 1 || payload[pos] != DELIMITER {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: expected ';' delimiter after MAC data"
        )));
    }

    Ok(KuFields {
        key_id,
        pan,
        atc,
        mac_data_hex,
    })
}

#[async_trait]
impl Handler for IssuerScriptMacHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["JU", "KU", "KY"]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"KU" => handle_ku(payload, state, "KU").await,
            b"KY" => handle_ku(payload, state, "KY").await,
            b"JU" => handle_ku(payload, state, "JU").await,
            _ => HandlerResult::err(*b"68"),
        }
    }
}

async fn handle_ku(payload: &[u8], state: &Arc<AppState>, cmd: &str) -> HandlerResult {
    let f = match parse_ku_fields(payload, cmd) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&f.key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    // The MAC data is the raw script command (already in hex).
    // For EMV issuer scripts, APC expects message_data as hex.
    // Note: The pan/pan_seq/atc fields are parsed and logged for diagnostics,
    // but not passed to generate_mac — session key derivation from IMK must
    // be handled by the key stored in APC (pre-derived) or at the application layer.
    use aws_sdk_paymentcryptographydata::types::{MacAlgorithm, MacAttributes};
    debug!(
        key = %key_arn, %cmd,
        pan_prefix = %&f.pan[..f.pan.len().min(6)],
        atc = %f.atc,
        "issuer script MAC generate_mac ISO9797_ALGORITHM3"
    );

    match state
        .data
        .generate_mac()
        .key_identifier(&key_arn)
        .message_data(&f.mac_data_hex)
        .generation_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm3))
        .send()
        .await
    {
        Ok(resp) => HandlerResult::success(resp.mac().as_bytes().to_vec()),
        Err(e) => {
            warn!(?e, "{cmd}: generate_mac failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ku_payload(
        key: &[u8],
        pan_seq_bytes: &[u8; 8],
        atc: &[u8; 2],
        data: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(b'0'); // mode 0 = MAC only
        v.push(b'0'); // scheme 0 = Visa/Amex
        v.extend_from_slice(b"00E"); // key type
        v.extend_from_slice(key);
        v.extend_from_slice(pan_seq_bytes);
        v.extend_from_slice(atc);
        v.extend_from_slice(format!("{:04X}", data.len()).as_bytes());
        v.extend_from_slice(data);
        v.push(DELIMITER);
        v
    }

    fn single_key() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec()
    }

    // PAN 4111111111111111, seq 00 → EMV Option A pre-format (rightmost-16(PAN‖PSN)):
    // "1111111111111100".
    fn pan_seq_bytes() -> [u8; 8] {
        [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x00]
    }

    #[test]
    fn parse_ku_mode0_single_key() {
        let payload = build_ku_payload(&single_key(), &pan_seq_bytes(), &[0x00, 0x12], b"SCRIPT");
        let f = parse_ku_fields(&payload, "KU").unwrap();
        assert_eq!(f.key_id.raw, "1234567890ABCDEF");
        assert_eq!(f.atc, "0012");
        assert_eq!(f.mac_data_hex, bytes_to_hex(b"SCRIPT"));
    }

    #[test]
    fn parse_ku_double_key() {
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = build_ku_payload(&key, &pan_seq_bytes(), &[0x00, 0x01], b"DATA");
        let f = parse_ku_fields(&payload, "KU").unwrap();
        assert!(f.key_id.raw.starts_with('U'));
        assert_eq!(f.atc, "0001");
    }

    #[test]
    fn parse_ku_mode1_returns_error() {
        let mut payload = build_ku_payload(&single_key(), &pan_seq_bytes(), &[0x00, 0x01], b"D");
        payload[0] = b'1'; // change mode to 1
        assert!(matches!(
            parse_ku_fields(&payload, "KU"),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn parse_ku_missing_delimiter_returns_error() {
        let mut payload = build_ku_payload(&single_key(), &pan_seq_bytes(), &[0x00, 0x01], b"D");
        payload.pop(); // remove ';' delimiter
        assert!(matches!(
            parse_ku_fields(&payload, "KU"),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn parse_ku_empty_returns_error() {
        assert!(parse_ku_fields(b"", "KU").is_err());
    }

    #[test]
    fn parse_ku_truncated_mac_data_returns_error() {
        let mut v = Vec::new();
        v.push(b'0');
        v.push(b'0');
        v.extend_from_slice(b"00E");
        v.extend_from_slice(&single_key());
        v.extend_from_slice(&pan_seq_bytes());
        v.extend_from_slice(&[0x00, 0x01]);
        v.extend_from_slice(b"0010"); // claims 16 bytes
        v.extend_from_slice(b"TOOSHORT"); // only 8
        v.push(DELIMITER);
        assert!(parse_ku_fields(&v, "KU").is_err());
    }
}
