use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_legacy_key;
use crate::handlers::thales::reader::FieldReader;
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield MY — Verify and Translate MAC (PUGD0537-004 Rev A p.371).
///
/// Verifies an inbound MAC under one key, then generates a new MAC under a
/// second key for the same message. Maps to two sequential APC calls:
///   1. verify_mac  (inbound key + MAC)
///   2. generate_mac (outbound key)
///
/// Field layout — same header structure as M6/M8 (PUGD0537-004 Rev A p.365/368),
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

const KEY_TYPE_LEN: usize = 3;
const MSG_LEN_FIELD: usize = 4;

struct MacTranslateFields {
    in_algo: String,
    in_key_id: KeyDescriptor,
    out_algo: String,
    out_mac_size: usize,
    out_key_id: KeyDescriptor,
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
    let mut r = FieldReader::new(payload, "MY");

    // Mode '0' = complete single message. Continuation modes require multi-block
    // session state; APC is stateless and single-call only.
    let mode = r.byte("mode")?;
    if mode != b'0' {
        return Err(ProxyError::UnsupportedMacMode(format!(
            "MY: mode '{}' (continuation) not supported; APC is stateless — use mode '0' (complete message) only",
            mode as char
        )));
    }
    // Input format '1' = hex-encoded. Only hex input is supported.
    let infmt = r.byte("input format")?;
    if infmt != b'1' {
        return Err(ProxyError::MalformedPayload(format!(
            "MY: input format '{}' not supported; only format '1' (hex-encoded) is accepted",
            infmt as char
        )));
    }

    // Inbound header: MACSize(1) + MACAlgo(1) + PadMethod(1), then key type + key.
    let in_mac_size = mac_size_from_byte(r.byte("in MAC size")?)?;
    let in_algo = algo_from_byte(r.byte("in MAC algo")?)?;
    r.byte("in pad method")?; // consumed
    r.take(KEY_TYPE_LEN, "in key type")?; // consumed
    let in_key_id = r.parse_with(parse_legacy_key)?;

    // Outbound header: MACSize(1) + MACAlgo(1) + PadMethod(1), then key type + key.
    let out_mac_size = mac_size_from_byte(r.byte("out MAC size")?)?;
    let out_algo = algo_from_byte(r.byte("out MAC algo")?)?;
    r.byte("out pad method")?; // consumed
    r.take(KEY_TYPE_LEN, "out key type")?; // consumed
    let out_key_id = r.parse_with(parse_legacy_key)?;

    // Message: 4-char ASCII byte-count, then that many hex-encoded bytes.
    let message_hex =
        String::from_utf8_lossy(r.take_ascii_len_hex(MSG_LEN_FIELD, 16, "message")?).to_string();

    // Inbound MAC (hex; size per the inbound header).
    let inbound_mac = String::from_utf8_lossy(r.take(in_mac_size * 2, "inbound MAC")?).to_string();

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

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[
            Evidence {
                decision: "MY verifies an inbound MAC under one key, then generates an outbound MAC under a second key for the same message (per-direction MAC size/algorithm). A half inbound MAC (size '1' = 2 bytes) is verified by regenerating the full MAC and comparing the leading bytes.",
                because: "PUGD0537-004 Rev A p.371. Verified live (ISO9797 Alg1) across all inbound×outbound MAC-size combos: proxy outbound MAC == APC generate_mac under the outbound key. The live differential caught the same half-MAC verify bug as GW — the inbound half MAC was handed to APC verify_mac, which rejects it — fixed with the regenerate-and-compare-prefix path.",
                wire: WireGrounding::DiffXprov,
                crypto: CryptoGrounding::Apc,
                proof: Proof::LiveTest("mac_translate_my_differential"),
            },
            Evidence {
                decision: "ALG3 and CMAC directions, and differing inbound/outbound algorithms, are parsed but not yet covered by a live differential (only ALG1 is).",
                because: "PUGD0537-004 Rev A p.371 — same per-direction generate/verify mapping as the live-verified ALG1 path; broadening the differential is the tracked next step.",
                wire: WireGrounding::Cited,
                crypto: CryptoGrounding::None,
                proof: Proof::ManualCite("PUGD0537-004 Rev A p.371; ALG3/CMAC not yet live-differentialed"),
            },
        ]
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

        let in_arn = match state.key_map.resolve_descriptor(&fields.in_key_id) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };
        let out_arn = match state.key_map.resolve_descriptor(&fields.out_key_id) {
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

        // Step 1: verify inbound MAC. APC verify_mac only accepts a full 8H/16H
        // MAC, so a Thales half MAC (inbound size '1' = 2 bytes = 4H) is verified
        // by regenerating the full MAC and comparing the leading bytes (same as the
        // GW and M6 CMAC verify paths).
        let inbound_ok = if fields.inbound_mac.len() < 8 {
            match state
                .data
                .generate_mac()
                .key_identifier(&in_arn)
                .message_data(&fields.message_hex)
                .generation_attributes(MacAttributes::Algorithm(in_algo))
                .send()
                .await
            {
                Ok(resp) => {
                    let full = resp.mac();
                    let expected = &full[..fields.inbound_mac.len().min(full.len())];
                    Ok(fields.inbound_mac.eq_ignore_ascii_case(expected))
                }
                Err(e) => Err(e.to_string()),
            }
        } else {
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
                Ok(_) => Ok(true),
                Err(e) => {
                    if e.as_service_error()
                        .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_mac::VerifyMacError::is_verification_failed_exception)
                    {
                        Ok(false)
                    } else {
                        Err(e.to_string())
                    }
                }
            }
        };
        match inbound_ok {
            Ok(true) => {}
            Ok(false) => {
                warn!("MY: inbound MAC mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            Err(msg) => {
                warn!(%msg, "MY: inbound verify failed");
                return HandlerResult::from_proxy_error(&ProxyError::ApcError(msg));
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

    // Test wire-builder: each parameter is a distinct MY protocol field, so a
    // bundling struct would only obscure the payload layout.
    #[allow(clippy::too_many_arguments)]
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
        v.extend_from_slice(format!("{byte_count:04X}").as_bytes());
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
        assert_eq!(f.in_key_id.raw, "1234567890ABCDEF");
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
        assert_eq!(f.in_key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.out_key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
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
        assert!(matches!(
            parse_my(&p),
            Err(ProxyError::UnsupportedMacMode(_))
        ));
    }
}
