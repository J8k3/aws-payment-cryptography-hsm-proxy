use async_trait::async_trait;
use std::sync::Arc;
use tracing::debug;
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{
    build_arpc_attrs, build_session_key, bytes_to_hex, decode_bcd_pan_seq, emv_pad,
    parse_legacy_key, verify_arqc, ArpcParams, EmvSession,
};
use crate::handlers::thales::reader::FieldReader;
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield KW — Verify ARQC and optionally generate ARPC (EMV & Cloud-Based SKD).
///
/// Wire format per PUGD0537-004 Rev A p.471 — identical to KQ with one extra field:
///
///   Mode Flag        1N ASCII  '0'=verify only
///                              '1'=verify + ARPC Method 1 (ARC)
///                              '2'=verify + ARPC Method 2 (CSU)
///                              '3'/'4'=skip-verify ARPC (not supported by APC)
///   Scheme ID        1A ASCII  selects major mode + session-key method (p.471):
///                              '0'=Option A + EMV2000   '1'=Option B + EMV2000
///                              '2'=Option A + EMV Common '3'=Option B + EMV Common
///                              '5'=MC cloud: Option A + EMV Common
///                              (Option C '9', JCB, UnionPay, cloud/LUK: no APC map)
///   Derivation Method 1A ASCII 'A'/'B' (consumed; see note below)
///   Key Type         3H ASCII  consumed
///   Key              var       16H | 'U'+32H | 'T'+48H
///   PAN+Seq          8B binary BCD — EMV pre-formatted: rightmost 16 of (PAN||PSN), left 0-padded
///   ATC              2B binary Application Transaction Counter
///   UN               4B binary Unpredictable Number
///   TxnLen           2B binary big-endian byte count of transaction data
///   TxnData          nB binary
///   0x3B             1B        delimiter
///   ARQC             8B binary
///   Mode 1:  ARC     2B binary Auth Response Code
///   Mode 2:  CSU     4B binary Card Status Update
///            PAD_len 1B binary byte count of proprietary auth data
///            PAD     nB binary
///
/// KW covers the EMV / Cloud-Based SKD methods (EMV2000 and EMV Common Session
/// Key). The Scheme ID selects the session-key method; the explicit Derivation
/// Method byte ('A'/'B') selects the major derivation mode (EMV Option A/B) and is
/// authoritative — the Scheme ID's even/odd Option-A/B convention is not used for
/// the major key, so an inconsistent host gets the mode it stated explicitly (#23).
pub struct KwArqcHandler;

#[derive(Debug)]
enum KwMode {
    VerifyOnly,
    VerifyArpcMethod1,
    VerifyArpcMethod2,
}

struct KwFields {
    key_id: KeyDescriptor,
    mode: KwMode,
    deriv_mode_a: bool,
    session: EmvSession,
    pan: String,
    pan_seq: String,
    atc: String,
    un: String,
    txn_data: Zeroizing<String>,
    arqc: String,
    arpc_params: Option<ArpcParams>,
}

fn parse_kw(payload: &[u8]) -> Result<KwFields, ProxyError> {
    let mut r = FieldReader::new(payload, "KW");

    // Mode Flag (1N ASCII)
    let mode = match r.byte("mode flag")? {
        b'0' => KwMode::VerifyOnly,
        b'1' => KwMode::VerifyArpcMethod1,
        b'2' => KwMode::VerifyArpcMethod2,
        b'3' | b'4' => {
            return Err(ProxyError::MalformedPayload(
                "KW: modes 3/4 (skip-verify) not supported by APC".into(),
            ))
        }
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "KW: invalid mode flag '{}'",
                other as char
            )))
        }
    };

    // Scheme ID (1A ASCII) — selects the session-key method only. The major
    // derivation mode comes from the explicit Derivation Method byte below (#23):
    // the Scheme ID's even/odd Option-A/B convention is not used for the mode, so a
    // host that sets them inconsistently gets the mode it asked for explicitly.
    let scheme = r.byte("scheme ID")?;
    let session = match scheme {
        b'0' | b'1' => EmvSession::Emv2000,
        b'2' | b'3' | b'5' => EmvSession::EmvCommon, // '5' = Mastercard cloud
        b'4' | b'6' | b'7' | b'8' | b'9' | b'A' | b'B' | b'C' => {
            return Err(ProxyError::Unsupported(format!(
                "KW scheme '{}' (cloud/LUK/Option-C/JCB/UnionPay SKD) has no APC equivalent",
                scheme as char
            )))
        }
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "KW: invalid scheme ID '{}'",
                other as char
            )))
        }
    };

    // Derivation Method (1A ASCII) → MajorKeyDerivationMode. This is the host's
    // explicit EMV Option A/B selector and is authoritative for the major key (#23).
    let deriv_mode_a = match r.byte("derivation method")? {
        b'A' => true,
        b'B' => false,
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "KW: invalid derivation method '{}' ('A' or 'B')",
                other as char
            )))
        }
    };

    r.take(3, "key type")?; // Key Type (3H ASCII) — consumed
    let key_id = r.parse_with(parse_legacy_key)?; // Key (16H | U+32H | T+48H)

    // PAN+Seq (8B binary BCD)
    let (pan, pan_seq) = decode_bcd_pan_seq(r.take_array::<8>("PAN+seq")?);

    let atc = r.take_hex(2, "ATC")?;
    // UN forwarded; required by the Mastercard proprietary SKD.
    let un = r.take_hex(4, "UN")?;

    // TxnData: length (2B BE) then that many bytes. APC does not pad; forward the
    // EMV (ISO 9797-1 method 2) padded data.
    let txn_byte_len = r.u16_be("txn length")?;
    let txn_data = Zeroizing::new(bytes_to_hex(&emv_pad(r.take(txn_byte_len, "txn data")?)));

    r.expect_byte(0x3B, "delimiter")?;
    let arqc = r.take_hex(8, "ARQC")?;

    // ARPC params (mode-dependent, binary)
    let arpc_params = match mode {
        KwMode::VerifyArpcMethod1 => Some(ArpcParams::Method1 {
            auth_response_code: r.take_hex(2, "ARC")?,
        }),
        KwMode::VerifyArpcMethod2 => {
            let csu = r.take_hex(4, "CSU")?;
            let pad_len = r.byte("PAD length")? as usize;
            let pad = r.take_hex(pad_len, "PAD data")?;
            Some(ArpcParams::Method2 {
                card_status_update: csu,
                proprietary_auth_data: pad,
            })
        }
        KwMode::VerifyOnly => None,
    };

    Ok(KwFields {
        key_id,
        mode,
        deriv_mode_a,
        session,
        pan,
        pan_seq,
        atc,
        un,
        txn_data,
        arqc,
        arpc_params,
    })
}

#[async_trait]
impl Handler for KwArqcHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["KW"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision: "KW verifies an ARQC and optionally generates an ARPC for the EMV / \
                       Cloud-Based SKD methods → APC verify_auth_request_cryptogram. The Scheme ID \
                       selects the session method (EMV2000 / EMV Common); the explicit Derivation \
                       Method byte ('A'/'B') selects the EMV Option A/B major key and is \
                       authoritative (#23) rather than inferring it from the Scheme ID's even/odd \
                       convention. Cloud / LUK / Option-C / JCB / UnionPay SKD schemes are rejected \
                       as having no APC equivalent.",
            because: "PUGD0537-004 Rev A p.471 (KW). Verified live for the Option-A schemes: APC \
                      mints a valid ARQC via generate_auth_request_cryptogram under a created E0 IMK \
                      (DeriveKey mode), the proxy's KW handler verifies it through APC and ACCEPTS \
                      (00), and a one-bit-corrupted ARQC is REJECTED (01), across randomized inputs \
                      — sweeping scheme '0' (EMV2000) and '2' (EMV Common), both Option A \
                      (arqc_verify_kw_differential). The Option-B schemes ('1'/'3') need a PAN > 16 \
                      digits, which the 8-byte BCD PAN field can't carry (see the EMV PAN-length \
                      gap), and the ARPC Method 1/2 generation path stays mock-tested; those are the \
                      next step.",
            wire: WireGrounding::DiffXprov,
            crypto: CryptoGrounding::Apc,
            proof: Proof::LiveTest("arqc_verify_kw_differential"),
        }]
    }

    async fn handle(
        &self,
        _command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        handle_kw(payload, state).await
    }
}

async fn handle_kw(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_kw(payload) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let key_arn = match state.key_map.resolve_descriptor(&fields.key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::MajorKeyDerivationMode;

    let deriv_mode = if fields.deriv_mode_a {
        MajorKeyDerivationMode::EmvOptionA
    } else {
        MajorKeyDerivationMode::EmvOptionB
    };

    let session_key_attrs = match build_session_key(
        fields.session,
        &fields.pan,
        &fields.pan_seq,
        &fields.atc,
        &fields.un,
    ) {
        Ok(s) => s,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let auth_response_attrs = match fields
        .arpc_params
        .as_ref()
        .map(build_arpc_attrs)
        .transpose()
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(
        key = %key_arn,
        mode = ?fields.mode,
        deriv = if fields.deriv_mode_a { "EmvOptionA" } else { "EmvOptionB" },
        session = ?fields.session,
        "KW: verify_auth_request_cryptogram"
    );

    verify_arqc(
        state,
        "KW",
        &key_arn,
        fields.txn_data.as_str(),
        &fields.arqc,
        deriv_mode,
        session_key_attrs,
        auth_response_attrs,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_key() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec() // 16H single-length
    }

    // EMV pre-formatted (rightmost 16 of PAN||PSN) "1234567890123401" -> PAN 12345678901234, Seq 01
    fn pan_bcd() -> [u8; 8] {
        [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x01]
    }

    fn kw_prefix(mode: u8, scheme: u8, deriv: u8, key: &[u8], txn: &[u8]) -> Vec<u8> {
        let mut v = vec![mode, scheme, deriv];
        v.extend_from_slice(b"00E");
        v.extend_from_slice(key);
        v.extend_from_slice(&pan_bcd());
        v.extend_from_slice(&[0x00, 0x01]); // ATC
        v.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // UN
        let len = txn.len() as u16;
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(txn);
        v.push(0x3B);
        v.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]);
        v
    }

    #[test]
    fn kw_parse_verify_only() {
        let payload = kw_prefix(b'0', b'0', b'A', &single_key(), &[0xDE, 0xAD]);
        let f = parse_kw(&payload).unwrap();
        assert!(matches!(f.mode, KwMode::VerifyOnly));
        assert!(f.deriv_mode_a); // scheme '0' = Option A
        assert_eq!(f.session, EmvSession::Emv2000); // scheme '0' = EMV2000
        assert_eq!(f.pan, "12345678901234");
        assert_eq!(f.pan_seq, "01");
        assert_eq!(f.atc, "0001");
        assert_eq!(f.un, "DEADBEEF");
        assert_eq!(f.arqc, "AABBCCDDEEFF0011");
        assert!(f.arpc_params.is_none());
    }

    #[test]
    fn kw_parse_method1_arpc() {
        let mut payload = kw_prefix(b'1', b'0', b'A', &single_key(), &[0xDE]);
        payload.extend_from_slice(&[0x00, 0x10]);
        let f = parse_kw(&payload).unwrap();
        assert!(matches!(f.mode, KwMode::VerifyArpcMethod1));
        assert!(matches!(
            f.arpc_params,
            Some(ArpcParams::Method1 { ref auth_response_code }) if auth_response_code == "0010"
        ));
    }

    #[test]
    fn kw_parse_option_b_emv2000_scheme() {
        // Scheme '1' = Option B + EMV2000.
        let payload = kw_prefix(b'0', b'1', b'B', &single_key(), &[]);
        let f = parse_kw(&payload).unwrap();
        assert!(!f.deriv_mode_a);
        assert_eq!(f.session, EmvSession::Emv2000);
    }

    #[test]
    fn kw_parse_emv_common_schemes() {
        // Scheme '2' = Option A + EMV Common; scheme '3' = Option B + EMV Common.
        let f2 = parse_kw(&kw_prefix(b'0', b'2', b'A', &single_key(), &[])).unwrap();
        assert!(f2.deriv_mode_a);
        assert_eq!(f2.session, EmvSession::EmvCommon);
        let f3 = parse_kw(&kw_prefix(b'0', b'3', b'B', &single_key(), &[])).unwrap();
        assert!(!f3.deriv_mode_a);
        assert_eq!(f3.session, EmvSession::EmvCommon);
    }

    #[test]
    fn kw_rejects_unsupported_scheme() {
        // Option C / JCB / UnionPay / cloud-LUK have no APC equivalent.
        let payload = kw_prefix(b'0', b'9', b'A', &single_key(), &[]);
        assert!(matches!(
            parse_kw(&payload),
            Err(ProxyError::Unsupported(_))
        ));
    }

    #[test]
    fn kw_rejects_mode_3() {
        let payload = kw_prefix(b'3', b'0', b'A', &single_key(), &[]);
        assert!(matches!(
            parse_kw(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn kw_rejects_invalid_deriv_method() {
        let payload = kw_prefix(b'0', b'0', b'C', &single_key(), &[]);
        assert!(matches!(
            parse_kw(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }
}
