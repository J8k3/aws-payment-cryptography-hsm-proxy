use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::thales::common::{parse_bdk, parse_ksn_with_descriptor};
use crate::handlers::thales::reader::FieldReader;
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield GW — Generate or Verify MAC (3DES/AES DUKPT).
///
/// Wire format per PUGD0537-004 Rev A (Core Host Commands) p.361 —
/// "Generate/Verify a MAC (3DES & AES DUKPT)":
///
///   Mode Flag     1N  '0'=generate, '1'=verify
///   Input Format  1N  '1'=hex-encoded (only '1' supported)
///   MAC Size      1N  '0'=full (4 bytes → 8H), '1'=half (2 bytes → 4H)
///   MAC Algorithm 1N  '1'=ISO9797_ALG1, '3'=ISO9797_ALG3, '6'=CMAC
///   Pad Method    1N  consumed
///   BDK           32H | 'U'+32H  (double-length DUKPT Base Derivation Key)
///   KSN Desc      3H  (key type nibble + KSN length as 2H nibble count)
///   KSN           20H (3DES X9.24-1) | 24H (AES X9.24-3) from descriptor
///   Msg Length    4H  hex-encoded byte count of message
///   Message       var hex-encoded message data
///   (verify only) MAC  mac_size*2 H  MAC to verify
///
/// APC mapping:
///   generate_mac / verify_mac with MacAttributes::Dukpt{Iso9797Algorithm1,
///   Iso9797Algorithm3, Cmac}, each wrapping MacAlgorithmDukpt{key_serial_number,
///   dukpt_key_variant=Bidirectional, dukpt_derivation_type from KSN descriptor}.
pub struct DukptMacHandler;

const MSG_LEN_FIELD: usize = 4;

struct GwFields {
    is_verify: bool,
    mac_size_bytes: usize,
    algo: &'static str,
    bdk_id: KeyDescriptor,
    ksn: String,
    deriv_type: aws_sdk_paymentcryptographydata::types::DukptDerivationType,
    message_hex: String,
    mac_to_verify: Option<String>,
}

fn parse_gw(payload: &[u8]) -> Result<GwFields, ProxyError> {
    let mut r = FieldReader::new(payload, "GW");

    let is_verify = match r.byte("mode")? {
        b'0' => false,
        b'1' => true,
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "GW: invalid mode '{}' (0=generate, 1=verify)",
                other as char
            )))
        }
    };

    let fmt = r.byte("input format")?;
    if fmt != b'1' {
        return Err(ProxyError::MalformedPayload(format!(
            "GW: unsupported input format '{}' (only '1'=hex)",
            fmt as char
        )));
    }

    let mac_size_bytes: usize = match r.byte("MAC size")? {
        b'0' => 4,
        b'1' => 2,
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "GW: unsupported MAC size '{}'",
                other as char
            )))
        }
    };

    let algo: &'static str = match r.byte("algorithm")? {
        b'1' => "ISO9797_ALG1",
        b'3' => "ISO9797_ALG3",
        b'6' => "CMAC",
        other => return Err(ProxyError::UnsupportedMacMode(format!("{}", other as char))),
    };

    r.byte("pad method")?; // consumed

    let bdk_id = r.parse_with(parse_bdk)?;
    let (ksn, deriv_type) = r.parse_with(|b, o| {
        parse_ksn_with_descriptor(b, o).map(|(ksn, consumed, dt)| ((ksn, dt), consumed))
    })?;

    // Message: MSG_LEN_FIELD-char ASCII byte-count, then that many hex-encoded bytes.
    let message_hex =
        String::from_utf8_lossy(r.take_ascii_len_hex(MSG_LEN_FIELD, 16, "message")?).to_string();

    let mac_to_verify = if is_verify {
        Some(String::from_utf8_lossy(r.take(mac_size_bytes * 2, "MAC")?).to_string())
    } else {
        None
    };

    Ok(GwFields {
        is_verify,
        mac_size_bytes,
        algo,
        bdk_id,
        ksn,
        deriv_type,
        message_hex,
        mac_to_verify,
    })
}

#[async_trait]
impl Handler for DukptMacHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["GW"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[
            Evidence {
                decision: "GW generate/verify a DUKPT MAC (Alg1/Alg3/CMAC, MAC size '0'=4 bytes / '1'=2 bytes). Half MACs (size '1') verify by regenerating the full MAC and comparing the leading bytes, because APC verify_mac only accepts an 8H or 16H MAC.",
                because: "PUGD0537-004 Rev A p.361 (GW). Verified live across every algorithm×size combo: proxy MAC == APC generate_mac (Dukpt Alg1/Alg3/CMAC, 3DES), plus the verify round-trip. The live differential caught a bug: GW verify of a 2-byte half MAC was passed straight to APC verify_mac, which rejects it ('valid length of 8 or 16') — fixed with the regenerate-and-compare-prefix path (mirrors M6 CMAC). APC constraints (verified live): DUKPT MAC needs message ≥8 bytes; the CBC-MAC variants (Alg1/Alg3) require a block-aligned (×8 byte) message — APC does not pad — while CMAC accepts any length.",
                wire: WireGrounding::DiffXprov,
                crypto: CryptoGrounding::Apc,
                proof: Proof::LiveTest("dukpt_mac_gw_differential"),
            },
            Evidence {
                decision: "The APC DukptKeyVariant is hardcoded to Request (terminal MAC direction).",
                because: "payShield GW carries no direction field, so the variant is a documented assumption. The differential proves proxy == APC under Request; it does NOT verify Request is what a real payShield derives. Host-response MACs (Response variant) are a known gap.",
                wire: WireGrounding::Cited,
                crypto: CryptoGrounding::Apc,
                proof: Proof::ManualCite("PUGD0537-004 Rev A p.361; direction not in the wire — assumption, not HSM-verified"),
            },
        ]
    }

    async fn handle(
        &self,
        _command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        let fields = match parse_gw(payload) {
            Ok(f) => f,
            Err(e) => {
                warn!(?e, "GW parse error");
                return HandlerResult::from_proxy_error(&e);
            }
        };

        let bdk_arn = match state.key_map.resolve_descriptor(&fields.bdk_id) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };

        debug!(bdk = %bdk_arn, algo = %fields.algo, verify = fields.is_verify, "GW: DUKPT MAC");

        use aws_sdk_paymentcryptographydata::types::{
            DukptKeyVariant, MacAlgorithmDukpt, MacAttributes,
        };

        // APC: DukptKeyVariant::Bidirectional is AES DUKPT (X9.24-3) only; 3DES DUKPT
        // X9.24-1 requires Request or Response. Use Request (terminal MAC direction).
        // KNOWN GAP: payShield GW does not expose direction — host-response MACs
        // would need Response variant. A future enhancement could infer from key type.
        let mac_alg_dukpt = match MacAlgorithmDukpt::builder()
            .key_serial_number(&fields.ksn)
            .dukpt_key_variant(DukptKeyVariant::Request)
            .dukpt_derivation_type(fields.deriv_type)
            .build()
        {
            Ok(v) => v,
            Err(e) => return HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string())),
        };

        let mac_attrs = match fields.algo {
            "ISO9797_ALG1" => MacAttributes::DukptIso9797Algorithm1(mac_alg_dukpt),
            "ISO9797_ALG3" => MacAttributes::DukptIso9797Algorithm3(mac_alg_dukpt),
            "CMAC" => MacAttributes::DukptCmac(mac_alg_dukpt),
            other => {
                return HandlerResult::from_proxy_error(&ProxyError::UnsupportedMacMode(
                    other.to_string(),
                ))
            }
        };

        if fields.is_verify {
            let mac_val = fields.mac_to_verify.expect("is_verify guarantees Some");
            // APC verify_mac only accepts a full 8H or 16H MAC. A Thales half MAC
            // (MAC size '1' = 2 bytes = 4H) is shorter, so for it we regenerate the
            // full MAC and compare the leading bytes (same approach as the M6 CMAC
            // verify path). Full MACs go through verify_mac directly.
            if mac_val.len() < 8 {
                match state
                    .data
                    .generate_mac()
                    .key_identifier(&bdk_arn)
                    .message_data(&fields.message_hex)
                    .generation_attributes(mac_attrs)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let full = resp.mac();
                        let expected = &full[..mac_val.len().min(full.len())];
                        if mac_val.eq_ignore_ascii_case(expected) {
                            HandlerResult::success(vec![])
                        } else {
                            warn!("GW: half-MAC prefix mismatch");
                            HandlerResult::from_proxy_error(&ProxyError::VerificationFailed)
                        }
                    }
                    Err(e) => {
                        warn!(?e, "GW: generate_mac for half-MAC verify failed");
                        HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
                    }
                }
            } else {
                match state
                    .data
                    .verify_mac()
                    .key_identifier(&bdk_arn)
                    .message_data(&fields.message_hex)
                    .mac(&mac_val)
                    .verification_attributes(mac_attrs)
                    .send()
                    .await
                {
                    Ok(_) => HandlerResult::success(vec![]),
                    Err(e) => {
                        if e.as_service_error()
                            .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_mac::VerifyMacError::is_verification_failed_exception)
                        {
                            warn!("GW: MAC mismatch");
                            return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
                        }
                        warn!(?e, "GW: verify_mac failed");
                        HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
                    }
                }
            }
        } else {
            match state
                .data
                .generate_mac()
                .key_identifier(&bdk_arn)
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
                    warn!(?e, "GW: generate_mac failed");
                    HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_bdk() -> Vec<u8> {
        b"1234567890ABCDEF1234567890ABCDEF".to_vec() // 32H baseline, no prefix
    }

    fn double_bdk() -> Vec<u8> {
        let mut v = vec![b'U'];
        v.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        v
    }

    fn ksn_tdes() -> Vec<u8> {
        let mut v = b"014".to_vec(); // key type '0', 0x14=20 nibbles → 3DES
        v.extend_from_slice(b"12345678901234567890"); // 20H KSN
        v
    }

    fn build_gw(
        mode: u8,
        mac_size: u8,
        algo: u8,
        bdk: &[u8],
        ksn_block: &[u8],
        msg_hex: &[u8],
        mac: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut v = vec![mode, b'1', mac_size, algo, b'1'];
        v.extend_from_slice(bdk);
        v.extend_from_slice(ksn_block);
        let byte_count = msg_hex.len() / 2;
        v.extend_from_slice(format!("{byte_count:04X}").as_bytes());
        v.extend_from_slice(msg_hex);
        if let Some(m) = mac {
            v.extend_from_slice(m);
        }
        v
    }

    #[test]
    fn gw_parse_generate_alg1() {
        let p = build_gw(
            b'0',
            b'0',
            b'1',
            &single_bdk(),
            &ksn_tdes(),
            b"DEADBEEF",
            None,
        );
        let f = parse_gw(&p).unwrap();
        assert!(!f.is_verify);
        assert_eq!(f.mac_size_bytes, 4);
        assert_eq!(f.algo, "ISO9797_ALG1");
        assert_eq!(f.bdk_id.raw, "1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.ksn, "12345678901234567890");
        assert_eq!(f.message_hex, "DEADBEEF");
        assert!(f.mac_to_verify.is_none());
    }

    #[test]
    fn gw_parse_verify_alg3_half_mac() {
        let p = build_gw(
            b'1',
            b'1',
            b'3',
            &single_bdk(),
            &ksn_tdes(),
            b"AABBCCDD",
            Some(b"AABB"),
        );
        let f = parse_gw(&p).unwrap();
        assert!(f.is_verify);
        assert_eq!(f.mac_size_bytes, 2);
        assert_eq!(f.algo, "ISO9797_ALG3");
        assert_eq!(f.mac_to_verify, Some("AABB".to_string()));
    }

    #[test]
    fn gw_parse_generate_cmac() {
        let p = build_gw(b'0', b'0', b'6', &single_bdk(), &ksn_tdes(), b"AABB", None);
        let f = parse_gw(&p).unwrap();
        assert_eq!(f.algo, "CMAC");
    }

    #[test]
    fn gw_parse_u_prefix_bdk() {
        let p = build_gw(
            b'0',
            b'0',
            b'1',
            &double_bdk(),
            &ksn_tdes(),
            b"AABBCCDD",
            None,
        );
        let f = parse_gw(&p).unwrap();
        assert_eq!(f.bdk_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
    }

    #[test]
    fn gw_parse_aes_ksn() {
        let mut ksn_aes = b"018".to_vec(); // 0x18=24 nibbles → AES-128
        ksn_aes.extend_from_slice(b"123456789012345678901234"); // 24H
        let p = build_gw(b'0', b'0', b'6', &single_bdk(), &ksn_aes, b"AABBCCDD", None);
        let f = parse_gw(&p).unwrap();
        assert!(matches!(
            f.deriv_type,
            aws_sdk_paymentcryptographydata::types::DukptDerivationType::Aes128
        ));
    }

    #[test]
    fn gw_parse_verify_full_mac() {
        let p = build_gw(
            b'1',
            b'0',
            b'1',
            &single_bdk(),
            &ksn_tdes(),
            b"AABBCCDD",
            Some(b"CCDDAABB"),
        );
        let f = parse_gw(&p).unwrap();
        assert!(f.is_verify);
        assert_eq!(f.mac_size_bytes, 4);
        assert_eq!(f.mac_to_verify, Some("CCDDAABB".to_string()));
    }

    #[test]
    fn gw_rejects_bad_mode() {
        let p = build_gw(b'2', b'0', b'1', &single_bdk(), &ksn_tdes(), b"AABB", None);
        assert!(matches!(parse_gw(&p), Err(ProxyError::MalformedPayload(_))));
    }

    #[test]
    fn gw_rejects_bad_algo() {
        let p = build_gw(b'0', b'0', b'2', &single_bdk(), &ksn_tdes(), b"AABB", None);
        assert!(matches!(
            parse_gw(&p),
            Err(ProxyError::UnsupportedMacMode(_))
        ));
    }

    #[test]
    fn gw_rejects_missing_mac_for_verify() {
        // mode='1' but no MAC appended
        let p = build_gw(
            b'1',
            b'0',
            b'1',
            &single_bdk(),
            &ksn_tdes(),
            b"DEADBEEF",
            None,
        );
        assert!(matches!(parse_gw(&p), Err(ProxyError::MalformedPayload(_))));
    }

    #[test]
    fn gw_rejects_bad_input_format() {
        // Input format '0' not supported
        let mut v = vec![b'0', b'0', b'0', b'1', b'1']; // note InFmt='0'
        v.extend_from_slice(&single_bdk());
        v.extend_from_slice(&ksn_tdes());
        v.extend_from_slice(b"0002");
        v.extend_from_slice(b"AABB");
        assert!(matches!(parse_gw(&v), Err(ProxyError::MalformedPayload(_))));
    }

    #[test]
    fn gw_rejects_payload_too_short() {
        let p = vec![b'0', b'1', b'0']; // only 3 bytes
        assert!(matches!(parse_gw(&p), Err(ProxyError::MalformedPayload(_))));
    }
}
