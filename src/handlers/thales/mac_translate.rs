use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_legacy_key;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield MY — Verify and Translate MAC (PUGD0537-004 p.371).
///
/// Verifies an inbound MAC under one key, then generates a new MAC under a
/// second key for the same message. Maps to two sequential APC calls:
///   1. verify_mac  (inbound key + MAC)
///   2. generate_mac (outbound key)
///
/// Field layout — same header structure as M6/M8 (PUGD0537-004 p.363/368),
/// but with two key blocks and two MAC algo/size fields:
///
///   Mode Flag       1N  '0'=complete message (only '0' supported)
///   Input Format    1N  '1'=hex-encoded (only '1' supported)
///   In MAC Size     1N  '0'=full 4B, '1'=half 2B
///   In MAC Algo     1N  '1'=ISO9797_ALG1, '3'=ISO9797_ALG3, '6'=CMAC
///   In Pad Method   1N  consumed
///   In Key Type     3H  consumed
///   Inbound Key     var 16H | 'U'+32H | 'T'+48H
///   Out MAC Size    1N  '0'=full 4B, '1'=half 2B
///   Out MAC Algo    1N  '1'=ISO9797_ALG1, '3'=ISO9797_ALG3, '6'=CMAC
///   Out Pad Method  1N  consumed
///   Out Key Type    3H  consumed
///   Outbound Key    var 16H | 'U'+32H | 'T'+48H
///   Msg Length      4H  byte count of message
///   Message         var hex-encoded
///   Inbound MAC     mac_size*2 H  (to verify)
///
/// Response payload: outbound MAC (out_mac_size*2 H).
pub struct MacTranslateHandler;

const HEADER_BYTES: usize = 5; // Mode + InFmt + MACSize + MACAlgo + PadMethod
const KEY_TYPE_LEN: usize = 3;
const MSG_LEN_FIELD: usize = 4;

struct MacTranslateFields {
    in_algo: String,
    in_key_id: String,
    out_algo: String,
    out_mac_size: usize,
    out_key_id: String,
    message_hex: String,
    inbound_mac: String,
}

fn mac_size_from_byte(byte: u8) -> Result<usize, ProxyError> {
    match byte {
        b'0' => Ok(4),
        b'1' => Ok(2),
        other => Err(ProxyError::MalformedPayload(format!(
            "MY: unsupported MAC size byte '{}'",
            other as char
        ))),
    }
}

fn algo_from_byte(byte: u8) -> Result<String, ProxyError> {
    match byte {
        b'1' => Ok("ISO9797_ALGORITHM1".to_string()),
        b'3' => Ok("ISO9797_ALGORITHM3".to_string()),
        b'6' => Ok("CMAC".to_string()),
        other => Err(ProxyError::UnsupportedMacMode(format!("{}", other as char))),
    }
}

fn parse_my(payload: &[u8]) -> Result<MacTranslateFields, ProxyError> {
    if payload.len() < HEADER_BYTES + KEY_TYPE_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "MY payload too short: {}",
            payload.len()
        )));
    }

    // Mode '0' = complete single message. Continuation modes require multi-block
    // session state; APC is stateless and single-call only.
    if payload[0] != b'0' {
        return Err(ProxyError::UnsupportedMacMode(format!(
            "MY: mode '{}' (continuation) not supported; APC is stateless — use mode '0' (complete message) only",
            payload[0] as char
        )));
    }
    // Input format '1' = hex-encoded. Only hex input is supported.
    if payload[1] != b'1' {
        return Err(ProxyError::MalformedPayload(format!(
            "MY: input format '{}' not supported; only format '1' (hex-encoded) is accepted",
            payload[1] as char
        )));
    }

    // Inbound header: Mode(1) + InFmt(1) + MACSize(1) + MACAlgo(1) + PadMethod(1)
    let in_mac_size = mac_size_from_byte(payload[2])?;
    let in_algo = algo_from_byte(payload[3])?;
    // payload[4] = pad method, consumed

    let mut pos = HEADER_BYTES + KEY_TYPE_LEN; // skip inbound header + key type

    let (in_key_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;

    // Outbound header: MACSize(1) + MACAlgo(1) + PadMethod(1)
    if payload.len() < pos + 3 + KEY_TYPE_LEN {
        return Err(ProxyError::MalformedPayload(
            "MY: outbound header missing".into(),
        ));
    }
    let out_mac_size = mac_size_from_byte(payload[pos])?;
    let out_algo = algo_from_byte(payload[pos + 1])?;
    // payload[pos+2] = out pad method, consumed
    pos += 3 + KEY_TYPE_LEN;

    let (out_key_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;

    // Message length (4H)
    if payload.len() < pos + MSG_LEN_FIELD {
        return Err(ProxyError::MalformedPayload(
            "MY: message length missing".into(),
        ));
    }
    let msg_len_hex = std::str::from_utf8(&payload[pos..pos + MSG_LEN_FIELD])
        .map_err(|_| ProxyError::MalformedPayload("MY: msg length not ASCII".into()))?;
    let msg_byte_len = usize::from_str_radix(msg_len_hex, 16).map_err(|_| {
        ProxyError::MalformedPayload(format!("MY: invalid msg length '{msg_len_hex}'"))
    })?;
    pos += MSG_LEN_FIELD;

    // Message
    let msg_hex_chars = msg_byte_len * 2;
    if payload.len() < pos + msg_hex_chars {
        return Err(ProxyError::MalformedPayload("MY: message truncated".into()));
    }
    let message_hex = String::from_utf8_lossy(&payload[pos..pos + msg_hex_chars]).to_string();
    pos += msg_hex_chars;

    // Inbound MAC
    let in_mac_hex_chars = in_mac_size * 2;
    if payload.len() < pos + in_mac_hex_chars {
        return Err(ProxyError::MalformedPayload(
            "MY: inbound MAC missing".into(),
        ));
    }
    let inbound_mac = String::from_utf8_lossy(&payload[pos..pos + in_mac_hex_chars]).to_string();

    Ok(MacTranslateFields {
        in_algo,
        in_key_id,
        out_algo,
        out_mac_size,
        out_key_id,
        message_hex,
        inbound_mac,
    })
}

#[async_trait]
impl Handler for MacTranslateHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["MY"]
    }

    async fn handle(
        &self,
        _command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        let fields = match parse_my(payload) {
            Ok(f) => f,
            Err(e) => {
                warn!(?e, "MY parse error");
                return HandlerResult::from_proxy_error(&e);
            }
        };

        let in_arn = match state.key_map.resolve(&fields.in_key_id) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };
        let out_arn = match state.key_map.resolve(&fields.out_key_id) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };

        use aws_sdk_paymentcryptographydata::types::{MacAlgorithm, MacAttributes};

        let in_algo = match fields.in_algo.as_str() {
            "ISO9797_ALGORITHM1" => MacAlgorithm::Iso9797Algorithm1,
            "ISO9797_ALGORITHM3" => MacAlgorithm::Iso9797Algorithm3,
            "CMAC" => MacAlgorithm::Cmac,
            other => {
                return HandlerResult::from_proxy_error(&ProxyError::UnsupportedMacMode(
                    other.to_string(),
                ))
            }
        };
        let out_algo = match fields.out_algo.as_str() {
            "ISO9797_ALGORITHM1" => MacAlgorithm::Iso9797Algorithm1,
            "ISO9797_ALGORITHM3" => MacAlgorithm::Iso9797Algorithm3,
            "CMAC" => MacAlgorithm::Cmac,
            other => {
                return HandlerResult::from_proxy_error(&ProxyError::UnsupportedMacMode(
                    other.to_string(),
                ))
            }
        };

        debug!(in_key = %in_arn, out_key = %out_arn, "MY: verify_mac then generate_mac");

        // Step 1: verify inbound MAC
        match state
            .data
            .verify_mac()
            .key_identifier(&in_arn)
            .message_data(&fields.message_hex)
            .mac(&fields.inbound_mac)
            .verification_attributes(MacAttributes::Algorithm(in_algo))
            .send()
            .await
        {
            Ok(_) => {}
            Err(e) => {
                if e.as_service_error()
                    .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_mac::VerifyMacError::is_verification_failed_exception)
                {
                    warn!("MY: inbound MAC mismatch");
                    return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
                }
                warn!(?e, "MY: verify_mac failed");
                return HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()));
            }
        }

        // Step 2: generate outbound MAC
        match state
            .data
            .generate_mac()
            .key_identifier(&out_arn)
            .message_data(&fields.message_hex)
            .generation_attributes(MacAttributes::Algorithm(out_algo))
            .send()
            .await
        {
            Ok(resp) => {
                let mac_hex = resp.mac();
                let truncated_chars = fields.out_mac_size * 2;
                let out = &mac_hex[..truncated_chars.min(mac_hex.len())];
                HandlerResult::success(out.as_bytes().to_vec())
            }
            Err(e) => {
                warn!(?e, "MY: generate_mac failed");
                HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_key() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec() // 16H single-length
    }

    fn build_my_payload(
        in_mac_size: u8,
        in_algo: u8,
        in_key: &[u8],
        out_mac_size: u8,
        out_algo: u8,
        out_key: &[u8],
        msg_hex: &[u8],
        in_mac: &[u8],
    ) -> Vec<u8> {
        let mut v = vec![b'0', b'1', in_mac_size, in_algo, b'1']; // inbound header
        v.extend_from_slice(b"MA1"); // in key type
        v.extend_from_slice(in_key);
        v.extend_from_slice(&[out_mac_size, out_algo, b'1']); // outbound header
        v.extend_from_slice(b"MA1"); // out key type
        v.extend_from_slice(out_key);
        let byte_count = msg_hex.len() / 2;
        v.extend_from_slice(format!("{:04X}", byte_count).as_bytes());
        v.extend_from_slice(msg_hex);
        v.extend_from_slice(in_mac);
        v
    }

    #[test]
    fn my_parse_full_mac() {
        // in: ALG3, full MAC (4B→8H); out: CMAC, full MAC
        let p = build_my_payload(
            b'0',
            b'3',
            &single_key(),
            b'0',
            b'6',
            &single_key(),
            b"DEADBEEF",
            b"AABBCCDD",
        );
        let f = parse_my(&p).unwrap();
        assert_eq!(f.in_algo, "ISO9797_ALGORITHM3");
        assert_eq!(f.in_key_id, "1234567890ABCDEF");
        assert_eq!(f.inbound_mac.len(), 8, "full MAC = 4 bytes = 8 hex chars");
        assert_eq!(f.out_algo, "CMAC");
        assert_eq!(f.out_mac_size, 4);
        assert_eq!(f.message_hex, "DEADBEEF");
        assert_eq!(f.inbound_mac, "AABBCCDD");
    }

    #[test]
    fn my_parse_half_mac() {
        // in: half MAC (2B→4H); out: half MAC
        let p = build_my_payload(
            b'1',
            b'1',
            &single_key(),
            b'1',
            b'1',
            &single_key(),
            b"AABB",
            b"CCDD",
        );
        let f = parse_my(&p).unwrap();
        assert_eq!(f.out_mac_size, 2);
        assert_eq!(f.inbound_mac.len(), 4, "half MAC = 2 bytes = 4 hex chars");
        assert_eq!(f.inbound_mac, "CCDD");
    }

    #[test]
    fn my_parse_u_prefix_keys() {
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let p = build_my_payload(b'0', b'1', &key, b'0', b'1', &key, b"AABB", b"CCDDCCDD");
        let f = parse_my(&p).unwrap();
        assert_eq!(f.in_key_id, "U1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.out_key_id, "U1234567890ABCDEF1234567890ABCDEF");
    }

    #[test]
    fn my_rejects_bad_algo() {
        let p = build_my_payload(
            b'0',
            b'2',
            &single_key(), // algo '2' invalid
            b'0',
            b'1',
            &single_key(),
            b"AABB",
            b"CCDDCCDD",
        );
        assert!(matches!(
            parse_my(&p),
            Err(ProxyError::UnsupportedMacMode(_))
        ));
    }

    #[test]
    fn my_rejects_continuation_mode() {
        let mut p = build_my_payload(
            b'0',
            b'1',
            &single_key(),
            b'0',
            b'1',
            &single_key(),
            b"AABB",
            b"CCDDCCDD",
        );
        p[0] = b'1'; // set mode byte to continuation
        assert!(matches!(parse_my(&p), Err(ProxyError::UnsupportedMacMode(_))));
    }
}
