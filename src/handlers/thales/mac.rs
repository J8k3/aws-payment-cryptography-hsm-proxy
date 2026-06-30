use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_legacy_key;
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield MAC commands: C2/M6 (generate) and C4/M8 (verify).
///
/// C2/C4: X9.9/X9.19/AS2805 MAC — fixed-layout, static MAC key
/// M6/M8: Extended MAC (ISO9797 Alg1/Alg3/CMAC) — variable-layout per PUGD0537-004 p.363/368
///
/// All four map to APC GenerateMac / VerifyMac.
pub struct MacHandler;

// ── C2/C4 layout (PUGD0537-004 p.583) ────────────────────────────────────────
//   [0]       Block Number 1N  '0'=only block (continuation 1-3 unsupported)
//   [1]       Key Type     1N  '0'=TAK,'1'=ZAK,'2'=TAKs,'3'=ZAKs (consumed)
//   [2]       MAC Mode     1N  '0'=X9.9(ALG1), '1'=X9.19(ALG3), '2'/'3'=AS2805_4_1
//   [3]       Message Type 1N  '0'=binary, '1'=expanded hex (only '1' supported)
//   [4..]     Key          var (16H | U+32H | T+48H) via parse_legacy_key
//   after key: Msg Len     4H   byte count of message
//   after len: Message     var  hex-encoded message
//   (C4 appends 8H MAC to verify after message)

fn algorithm_from_mode_c2(mode: u8) -> Result<String, ProxyError> {
    match mode {
        b'0' => Ok("ISO9797_ALGORITHM1".to_string()),
        b'1' => Ok("ISO9797_ALGORITHM3".to_string()),
        b'2' | b'3' => Ok("AS2805_4_1".to_string()),
        other => Err(ProxyError::UnsupportedMacMode(format!("{}", other as char))),
    }
}

fn parse_c2_payload(payload: &[u8], is_verify: bool) -> Result<MacFields, ProxyError> {
    // Real C2 layout (PUGD0537-004 p.583):
    //   [0] Message Block Number 1N ('0' only / '1'-'3' continuation)
    //   [1] Key Type             1N ('0' TAK, '1' ZAK, '2' TAKs, '3' ZAKs — consumed)
    //   [2] MAC generation Mode  1N ('0' X9.9, '1' X9.19, '2'/'3' AS2805.4.1)
    //   [3] Message Type         1N ('0' binary, '1' expanded hex)
    //   [4..] Key                16H | 'U'+32H | 'T'+48H
    //   [IV  16H/32H if block number is 2 or 3]
    //   Message Length 4H, then the hex message; C4 appends an 8H MAC to verify.
    const HEADER_LEN: usize = 4;
    const MSG_LEN_FIELD: usize = 4;
    const MAC_HEX: usize = 8;

    if payload.len() < HEADER_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "C2/C4 payload too short: {}",
            payload.len()
        )));
    }
    // Only single-block messages: continuation modes need an inter-block IV and
    // session state that APC's single-call generate_mac cannot carry.
    if payload[0] != b'0' {
        return Err(ProxyError::UnsupportedMacMode(format!(
            "C2/C4: message block number '{}' (continuation) not supported; use '0' (only block)",
            payload[0] as char
        )));
    }
    // payload[1] Key Type is consumed — the key_map resolves the actual key.
    let algorithm = algorithm_from_mode_c2(payload[2])?;
    if payload[3] != b'1' {
        return Err(ProxyError::MalformedPayload(format!(
            "C2/C4: message type '{}' not supported; only '1' (expanded hex) is accepted",
            payload[3] as char
        )));
    }

    let (key_id, key_consumed) = parse_legacy_key(payload, HEADER_LEN)?;
    let mut pos = HEADER_LEN + key_consumed;

    if payload.len() < pos + MSG_LEN_FIELD {
        return Err(ProxyError::MalformedPayload(
            "C2/C4: message length field missing".into(),
        ));
    }
    let msg_len_hex = String::from_utf8_lossy(&payload[pos..pos + MSG_LEN_FIELD]);
    let msg_byte_len = usize::from_str_radix(msg_len_hex.trim(), 16)
        .map_err(|_| ProxyError::MalformedPayload("C2/C4: bad message length hex".into()))?;
    pos += MSG_LEN_FIELD;

    let msg_end = pos + msg_byte_len * 2;
    if payload.len() < msg_end {
        return Err(ProxyError::MalformedPayload(format!(
            "C2/C4: payload shorter than declared message: need {} got {}",
            msg_end,
            payload.len()
        )));
    }
    let message_hex = String::from_utf8_lossy(&payload[pos..msg_end]).to_string();
    let mac_to_verify = if is_verify {
        if payload.len() < msg_end + MAC_HEX {
            return Err(ProxyError::MalformedPayload("C4: missing MAC".into()));
        }
        Some(String::from_utf8_lossy(&payload[msg_end..msg_end + MAC_HEX]).to_string())
    } else {
        None
    };
    Ok(MacFields {
        algorithm,
        key_id,
        message_hex,
        mac_to_verify,
        mac_size_bytes: 4,
    })
}

// ── M6/M8 layout (PUGD0537-004 p.363/368) ────────────────────────────────────
//   [0]        Mode Flag    1N  '0'=complete message (only '0' supported)
//   [1]        Input Format 1N  '1'=hex-encoded input (only '1' supported)
//   [2]        MAC Size     1N  '0'=8 hex digits (4 bytes), '1'=16 hex digits (8 bytes)
//   [3]        MAC Algo     1N  '1'=ISO9797_ALG1, '3'=ISO9797_ALG3, '6'=CMAC
//   [4]        Pad Method   1N  consumed; 1-char padding selector
//   [5..8]     Key Type     3H  consumed
//   [8..]      Key          var (16H | U+32H | T+48H) via parse_legacy_key
//   after key: Msg Len      4H  byte count of message
//   after len: Message      var hex-encoded message
//   M8 appends: MAC        mac_size*2 H

fn algorithm_from_m6_algo_byte(byte: u8) -> Result<String, ProxyError> {
    match byte {
        b'1' => Ok("ISO9797_ALGORITHM1".to_string()),
        b'3' => Ok("ISO9797_ALGORITHM3".to_string()),
        b'6' => Ok("CMAC".to_string()),
        other => Err(ProxyError::UnsupportedMacMode(format!("{}", other as char))),
    }
}

fn parse_m6_payload(payload: &[u8], is_verify: bool) -> Result<MacFields, ProxyError> {
    const HEADER_LEN: usize = 5; // Mode + InFmt + MACSize + MACAlgo + PadMethod
    const KEY_TYPE_LEN: usize = 3;
    const MSG_LEN_FIELD: usize = 4;

    if payload.len() < HEADER_LEN + KEY_TYPE_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "M6/M8 payload too short: {}",
            payload.len()
        )));
    }

    // Mode '0' = complete single message. Modes 1-4 are continuation modes that
    // require multi-block session state; APC is stateless and single-call only.
    if payload[0] != b'0' {
        return Err(ProxyError::UnsupportedMacMode(format!(
            "M6/M8: mode '{}' (continuation) not supported; APC is stateless — use mode '0' (complete message) only",
            payload[0] as char
        )));
    }
    // Input format '1' = hex-encoded. Only hex input is supported.
    if payload[1] != b'1' {
        return Err(ProxyError::MalformedPayload(format!(
            "M6/M8: input format '{}' not supported; only format '1' (hex-encoded) is accepted",
            payload[1] as char
        )));
    }

    // Per PUGD0537-004 p.365: MAC Size '0' = 8 hex digits (4 bytes),
    // '1' = 16 hex digits (8 bytes). The larger size is the full double-length MAC.
    let mac_size_bytes: usize = match payload[2] {
        b'0' => 4,
        b'1' => 8,
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "M6/M8: unsupported MAC size byte '{}'",
                other as char
            )))
        }
    };
    let algorithm = algorithm_from_m6_algo_byte(payload[3])?;

    let mut pos = HEADER_LEN + KEY_TYPE_LEN; // skip past 5-byte header + 3-byte key type

    let (key_id, key_consumed) = parse_legacy_key(payload, pos)?;
    pos += key_consumed;

    if payload.len() < pos + MSG_LEN_FIELD {
        return Err(ProxyError::MalformedPayload(
            "M6/M8: message length field missing".into(),
        ));
    }
    let msg_len_hex = std::str::from_utf8(&payload[pos..pos + MSG_LEN_FIELD])
        .map_err(|_| ProxyError::MalformedPayload("M6/M8: msg length not ASCII".into()))?;
    let msg_byte_len = usize::from_str_radix(msg_len_hex, 16).map_err(|_| {
        ProxyError::MalformedPayload(format!("M6/M8: invalid msg length '{msg_len_hex}'"))
    })?;
    pos += MSG_LEN_FIELD;

    let msg_hex_chars = msg_byte_len * 2;
    if payload.len() < pos + msg_hex_chars {
        return Err(ProxyError::MalformedPayload(format!(
            "M6/M8: payload shorter than declared message: need {} got {}",
            pos + msg_hex_chars,
            payload.len()
        )));
    }
    let message_hex = String::from_utf8_lossy(&payload[pos..pos + msg_hex_chars]).to_string();
    pos += msg_hex_chars;

    let mac_to_verify = if is_verify {
        let mac_hex_chars = mac_size_bytes * 2;
        if payload.len() < pos + mac_hex_chars {
            return Err(ProxyError::MalformedPayload("M8: MAC field missing".into()));
        }
        Some(String::from_utf8_lossy(&payload[pos..pos + mac_hex_chars]).to_string())
    } else {
        None
    };

    Ok(MacFields {
        algorithm,
        key_id,
        message_hex,
        mac_to_verify,
        mac_size_bytes,
    })
}

struct MacFields {
    algorithm: String,
    key_id: KeyDescriptor,
    message_hex: String,
    mac_to_verify: Option<String>,
    mac_size_bytes: usize,
}

#[async_trait]
impl Handler for MacHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["C2", "C4", "M6", "M8"]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        let is_m_series = matches!(command_code, b"M6" | b"M8");
        let is_verify = matches!(command_code, b"C4" | b"M8");

        let fields = match if is_m_series {
            parse_m6_payload(payload, is_verify)
        } else {
            parse_c2_payload(payload, is_verify)
        } {
            Ok(f) => f,
            Err(e) => {
                warn!(?e, "MAC parse error");
                return HandlerResult::from_proxy_error(&e);
            }
        };

        let key_arn = match state.key_map.resolve_descriptor(&fields.key_id) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };

        debug!(key = %key_arn, algo = %fields.algorithm, verify = is_verify, "MAC operation");

        use aws_sdk_paymentcryptographydata::types::{MacAlgorithm, MacAttributes};

        let algo = match fields.algorithm.as_str() {
            "ISO9797_ALGORITHM1" => MacAlgorithm::Iso9797Algorithm1,
            "ISO9797_ALGORITHM3" => MacAlgorithm::Iso9797Algorithm3,
            "CMAC" => MacAlgorithm::Cmac,
            "AS2805_4_1" => MacAlgorithm::As280541,
            other => {
                return HandlerResult::from_proxy_error(&ProxyError::UnsupportedMacMode(
                    other.to_string(),
                ))
            }
        };

        let mac_attrs = MacAttributes::Algorithm(algo);

        if is_verify {
            let mac_val = fields.mac_to_verify.expect("is_verify guarantees Some");

            if fields.algorithm == "CMAC" {
                // APC verify_mac requires the full 32H (16-byte) AES-CMAC, but payShield M8
                // sends only the truncated mac_size bytes that M6 returned (8H for mac_size=0).
                // Workaround: regenerate the full CMAC and compare the leading mac_size bytes.
                match state
                    .data
                    .generate_mac()
                    .key_identifier(&key_arn)
                    .message_data(&fields.message_hex)
                    .generation_attributes(mac_attrs)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let full_mac = resp.mac();
                        let expected = &full_mac[..fields.mac_size_bytes * 2];
                        if mac_val.eq_ignore_ascii_case(expected) {
                            HandlerResult::success(vec![])
                        } else {
                            warn!("M8 CMAC: MAC prefix mismatch");
                            HandlerResult::from_proxy_error(&ProxyError::VerificationFailed)
                        }
                    }
                    Err(e) => {
                        warn!(?e, "M8 CMAC: generate_mac for verify failed");
                        HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
                    }
                }
            } else {
                match state
                    .data
                    .verify_mac()
                    .key_identifier(&key_arn)
                    .message_data(&fields.message_hex)
                    .mac(&mac_val)
                    .verification_attributes(mac_attrs)
                    .send()
                    .await
                {
                    Ok(_) => HandlerResult::success(vec![]),
                    Err(e) => {
                        if e.as_service_error().is_some_and(aws_sdk_paymentcryptographydata::operation::verify_mac::VerifyMacError::is_verification_failed_exception) {
                            warn!("verify_mac: MAC mismatch");
                            return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
                        }
                        warn!(?e, "verify_mac failed");
                        HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
                    }
                }
            }
        } else {
            match state
                .data
                .generate_mac()
                .key_identifier(&key_arn)
                .message_data(&fields.message_hex)
                .generation_attributes(mac_attrs)
                .send()
                .await
            {
                Ok(resp) => {
                    let mac_hex = resp.mac();
                    let truncated_chars = fields.mac_size_bytes * 2;
                    let out = &mac_hex[..truncated_chars.min(mac_hex.len())];
                    HandlerResult::success(out.as_bytes().to_vec())
                }
                Err(e) => {
                    warn!(?e, "generate_mac failed");
                    HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // C2/C4 header: block number + key type + MAC mode + message type.
    fn c2_payload(mac_mode: u8, key: &[u8], msg_hex: &[u8]) -> Vec<u8> {
        let mut p = vec![b'0', b'1', mac_mode, b'1']; // block '0', key type ZAK, mode, hex
        p.extend_from_slice(key);
        let byte_count = msg_hex.len() / 2;
        p.extend_from_slice(format!("{byte_count:04X}").as_bytes());
        p.extend_from_slice(msg_hex);
        p
    }

    #[test]
    fn c2_parse_generate() {
        let key = b"1234567890ABCDEF"; // 16H single-length TAK/ZAK
        let p = c2_payload(b'0', key, b"DEADBEEF"); // mode '0' = X9.9 / ALG1
        let f = parse_c2_payload(&p, false).unwrap();
        assert_eq!(f.algorithm, "ISO9797_ALGORITHM1");
        assert_eq!(f.key_id.raw, "1234567890ABCDEF");
        assert_eq!(f.message_hex, "DEADBEEF");
        assert!(f.mac_to_verify.is_none());
        assert_eq!(f.mac_size_bytes, 4);
    }

    #[test]
    fn c2_parse_u_prefixed_key() {
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let p = c2_payload(b'1', &key, b"AABBCCDD"); // mode '1' = X9.19 / ALG3
        let f = parse_c2_payload(&p, false).unwrap();
        assert_eq!(f.algorithm, "ISO9797_ALGORITHM3");
        assert_eq!(f.key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
    }

    #[test]
    fn c4_parse_verify() {
        let key = b"1234567890ABCDEF";
        let mut p = c2_payload(b'1', key, b"DEADBEEF");
        p.extend_from_slice(b"AABBCCDD"); // MAC 8H
        let f = parse_c2_payload(&p, true).unwrap();
        assert_eq!(f.algorithm, "ISO9797_ALGORITHM3");
        assert_eq!(f.mac_to_verify, Some("AABBCCDD".to_string()));
    }

    #[test]
    fn c2_rejects_continuation_block() {
        let key = b"1234567890ABCDEF";
        let mut p = c2_payload(b'0', key, b"DEADBEEF");
        p[0] = b'1'; // first-block continuation
        assert!(matches!(
            parse_c2_payload(&p, false),
            Err(ProxyError::UnsupportedMacMode(_))
        ));
    }

    fn m6_payload(algo: u8, mac_size: u8, key: &[u8], msg_hex: &[u8]) -> Vec<u8> {
        let mut p = vec![b'0', b'1', mac_size, algo, b'1']; // mode+infmt+macsize+algo+pad
        p.extend_from_slice(b"MA1"); // key type 3H
        p.extend_from_slice(key);
        let byte_count = msg_hex.len() / 2;
        p.extend_from_slice(format!("{byte_count:04X}").as_bytes());
        p.extend_from_slice(msg_hex);
        p
    }

    #[test]
    fn m6_parse_generate_alg1() {
        let key = b"1234567890ABCDEF"; // 16H single-length
        let p = m6_payload(b'1', b'0', key, b"DEADBEEF");
        let f = parse_m6_payload(&p, false).unwrap();
        assert_eq!(f.algorithm, "ISO9797_ALGORITHM1");
        assert_eq!(f.key_id.raw, "1234567890ABCDEF");
        assert_eq!(f.message_hex, "DEADBEEF");
        assert_eq!(f.mac_size_bytes, 4);
        assert!(f.mac_to_verify.is_none());
    }

    #[test]
    fn m6_parse_generate_cmac() {
        let key = b"1234567890ABCDEF"; // 16H
        let p = m6_payload(b'6', b'0', key, b"AABBCC");
        let f = parse_m6_payload(&p, false).unwrap();
        assert_eq!(f.algorithm, "CMAC");
    }

    #[test]
    fn m8_parse_verify_full_double_length_mac() {
        let key = b"1234567890ABCDEF"; // 16H
        let mut p = m6_payload(b'3', b'1', key, b"DEADBEEF"); // mac_size='1' → 8 bytes (16 hex)
        p.extend_from_slice(b"AABBCCDD11223344"); // 16H = 8-byte MAC
        let f = parse_m6_payload(&p, true).unwrap();
        assert_eq!(f.algorithm, "ISO9797_ALGORITHM3");
        assert_eq!(f.mac_size_bytes, 8);
        assert_eq!(f.mac_to_verify, Some("AABBCCDD11223344".to_string()));
    }

    #[test]
    fn m6_parse_double_length_key() {
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let p = m6_payload(b'1', b'0', &key, b"AABBCCDD");
        let f = parse_m6_payload(&p, false).unwrap();
        assert_eq!(f.key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
    }

    #[test]
    fn m6_rejects_bad_algo() {
        let key = b"1234567890ABCDEF1234567890ABCDEF";
        let p = m6_payload(b'2', b'0', key, b"AABB"); // algo '2' invalid for M6
        assert!(matches!(
            parse_m6_payload(&p, false),
            Err(ProxyError::UnsupportedMacMode(_))
        ));
    }

    #[test]
    fn m6_rejects_continuation_mode() {
        let key = b"1234567890ABCDEF";
        let mut p = m6_payload(b'1', b'0', key, b"AABB"); // algo byte '1'=ALG1 but mode byte overridden
        p[0] = b'1'; // set mode byte to continuation
        assert!(matches!(
            parse_m6_payload(&p, false),
            Err(ProxyError::UnsupportedMacMode(_))
        ));
    }

    #[test]
    fn m6_rejects_non_hex_input_format() {
        let key = b"1234567890ABCDEF";
        let mut p = m6_payload(b'1', b'0', key, b"AABB");
        p[1] = b'0'; // set input format to non-hex
        assert!(matches!(
            parse_m6_payload(&p, false),
            Err(ProxyError::MalformedPayload(_))
        ));
    }
}
