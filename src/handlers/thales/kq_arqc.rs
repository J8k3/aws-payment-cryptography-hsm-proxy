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

/// payShield KQ — Verify ARQC and optionally generate ARPC.
///
/// Wire format per PUGD0537-004 Rev A p.468 (binary, not ASCII hex):
///
///   Mode Flag   1N ASCII  '0'=verify only
///                         '1'=verify + ARPC Method 1 (ARC)
///                         '2'=verify + ARPC Method 2 (CSU)
///                         '3'/'4'=skip-verify ARPC (not supported by APC)
///   Scheme ID   1N ASCII  selects session-key derivation; all use EMV Option A:
///                         '0'=Visa (Visa SKD: PAN + PAN seq)
///                         '1'=Mastercard M/Chip (Mastercard proprietary SKD + UN)
///                         '2'=Amex AEIPS (Amex SKD)
///   Key Type    3H ASCII  e.g. '00E' for IMK-AC (consumed)
///   Key         var       16H | 'U'+32H | 'T'+48H  (parse_legacy_key)
///   PAN+Seq     8B binary BCD — EMV pre-formatted: rightmost 16 of (PAN||PSN), left 0-padded
///   ATC         2B binary Application Transaction Counter
///   UN          4B binary Unpredictable Number
///   TxnLen      2B binary big-endian byte count of transaction data
///   TxnData     nB binary EMV terminal transaction data
///   0x3B        1B        delimiter
///   ARQC        8B binary Authorization Request Cryptogram
///   Mode 1 only:
///     ARC       2B binary Auth Response Code
///   Mode 2 only:
///     CSU       4B binary Card Status Update
///     PAD_len   1B binary byte count of proprietary auth data
///     PAD       nB binary proprietary auth data
///
/// ARQC mismatch → error 01.  Modes 3/4 → error 15 (unsupported).
pub struct KqArqcHandler;

#[derive(Debug)]
enum KqMode {
    VerifyOnly,
    VerifyArpcMethod1,
    VerifyArpcMethod2,
}

struct KqFields {
    key_id: KeyDescriptor,
    mode: KqMode,
    session: EmvSession,
    pan: String,
    pan_seq: String,
    atc: String,
    un: String,
    txn_data: Zeroizing<String>,
    arqc: String,
    arpc_params: Option<ArpcParams>,
}

fn parse_kq(payload: &[u8]) -> Result<KqFields, ProxyError> {
    let mut r = FieldReader::new(payload, "KQ");

    // Mode Flag (1N ASCII)
    let mode = match r.byte("mode flag")? {
        b'0' => KqMode::VerifyOnly,
        b'1' => KqMode::VerifyArpcMethod1,
        b'2' => KqMode::VerifyArpcMethod2,
        b'3' | b'4' => {
            return Err(ProxyError::MalformedPayload(
                "KQ: modes 3/4 (skip-verify) not supported by APC".into(),
            ))
        }
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "KQ: invalid mode flag '{}'",
                other as char
            )))
        }
    };

    // Scheme ID (1N ASCII) — all KQ schemes use EMV Option A major derivation
    // (PUGD0537-004 Rev A p.468); the Scheme ID selects the session-key method.
    let session = match r.byte("scheme ID")? {
        b'0' => EmvSession::Visa,       // Option A + Visa SKD (PAN + PAN seq)
        b'1' => EmvSession::Mastercard, // Option A + Mastercard proprietary SKD (M/Chip)
        b'2' => EmvSession::Amex,       // Option A + Amex AEIPS
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "KQ: invalid scheme ID '{}' (0=Visa, 1=MC M/Chip, 2=Amex)",
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
        KqMode::VerifyArpcMethod1 => Some(ArpcParams::Method1 {
            auth_response_code: r.take_hex(2, "ARC")?,
        }),
        KqMode::VerifyArpcMethod2 => {
            let csu = r.take_hex(4, "CSU")?;
            let pad_len = r.byte("PAD length")? as usize;
            let pad = r.take_hex(pad_len, "PAD data")?;
            Some(ArpcParams::Method2 {
                card_status_update: csu,
                proprietary_auth_data: pad,
            })
        }
        KqMode::VerifyOnly => None,
    };

    Ok(KqFields {
        key_id,
        mode,
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
impl Handler for KqArqcHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["KQ"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision: "KQ verifies an ARQC and optionally generates an ARPC → APC \
                       verify_auth_request_cryptogram. Scheme ID selects the session-key method on \
                       EMV Option A: Visa (Scheme '0'), Mastercard M/Chip (Scheme '1'), Amex AEIPS \
                       (Scheme '2'). Skip-verify modes 3/4 are rejected as having no APC equivalent. \
                       Mode 1/2 map to ARPC Method 1 (ARC) / Method 2 (CSU + proprietary data).",
            because: "PUGD0537-004 Rev A p.468 (KQ). Verified live for the Mastercard scheme ('1', \
                      Option A + Mastercard proprietary SKD): APC mints a valid ARQC via \
                      generate_auth_request_cryptogram under a created E0 IMK (DeriveKey mode), the \
                      proxy's KQ handler verifies it through APC and ACCEPTS (00), and a \
                      one-bit-corrupted ARQC is REJECTED (01), across randomized PAN / PSN / ATC / \
                      Unpredictable Number / txn length — the differential confirms the UN is \
                      forwarded to APC's Mastercard session-key derivation. The Amex scheme ('2', \
                      Option A + Amex SKD) is verified the same way in arqc_verify_kq_amex_differential. \
                      The Visa scheme ('0', Option A + Visa SKD: PAN + PAN seq, no ATC/UN in \
                      derivation) is verified the same way in arqc_verify_kq_visa_differential: APC \
                      mints a valid Visa ARQC under SessionKeyDerivation::Visa, the proxy ACCEPTS \
                      (00), and a one-bit-corrupted ARQC is REJECTED (01) across 32 randomized cases. \
                      (This corrected an earlier over-conservative gate — Visa VIS is not static-only; \
                      APC exposes SessionKeyDerivation::Visa, AWS's payShield migration maps KQ Scheme \
                      0 Visa -> it, and this repo's KU handler already uses it.) \
                      ARPC generation is also verified live: the proxy's ARPC equals a direct APC \
                      verify with the same response attributes — Method 1 (ARC) in \
                      arqc_verify_kq_arpc_method1_differential and Method 2 (CSU + proprietary auth \
                      data, incl. empty) in arqc_verify_kq_arpc_method2_differential. The error \
                      plumbing (key-not-found → 10, unsupported-mode → 15) stays mock-tested.",
            wire: WireGrounding::DiffXprov,
            crypto: CryptoGrounding::Apc,
            proof: Proof::LiveTest("arqc_verify_kq_differential"),
        }]
    }

    async fn handle(
        &self,
        _command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        handle_kq(payload, state).await
    }
}

async fn handle_kq(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_kq(payload) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let key_arn = match state.key_map.resolve_descriptor(&fields.key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::MajorKeyDerivationMode;

    // Every KQ scheme uses EMV Option A major (ICC master key) derivation
    // (PUGD0537-004 Rev A p.468); the Scheme ID selects only the session-key method.
    let deriv_mode = MajorKeyDerivationMode::EmvOptionA;

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
        session = ?fields.session,
        "KQ: verify_auth_request_cryptogram"
    );

    verify_arqc(
        state,
        "KQ",
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

    /// Build a complete KQ binary payload up through ARQC.
    fn kq_prefix(mode: u8, scheme: u8, key: &[u8], pan_seq_bcd: [u8; 8], txn: &[u8]) -> Vec<u8> {
        let mut v = vec![mode, scheme];
        v.extend_from_slice(b"00E"); // key type 3H
        v.extend_from_slice(key);
        v.extend_from_slice(&pan_seq_bcd); // 8B BCD
        v.extend_from_slice(&[0x00, 0x01]); // ATC 2B
        v.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // UN 4B
        let len = txn.len() as u16;
        v.extend_from_slice(&len.to_be_bytes()); // TxnLen 2B BE
        v.extend_from_slice(txn); // TxnData
        v.push(0x3B); // delimiter
        v.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]); // ARQC 8B
        v
    }

    fn single_key() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec() // 16H single-length
    }

    // EMV pre-formatted (rightmost 16 of PAN||PSN) "1234567890123401" -> PAN 12345678901234, Seq 01
    fn pan_bcd() -> [u8; 8] {
        [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x01]
    }

    #[test]
    fn kq_parse_verify_only() {
        let payload = kq_prefix(b'0', b'1', &single_key(), pan_bcd(), &[0xDE, 0xAD]);
        let f = parse_kq(&payload).unwrap();
        assert!(matches!(f.mode, KqMode::VerifyOnly));
        assert_eq!(f.session, EmvSession::Mastercard);
        assert_eq!(f.key_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pan, "12345678901234");
        assert_eq!(f.pan_seq, "01");
        assert_eq!(f.atc, "0001");
        assert_eq!(f.un, "DEADBEEF");
        // txn data is EMV (ISO 9797-1 method 2) padded for APC: DEAD + 80 + zeros
        assert_eq!(f.txn_data.as_str(), "DEAD800000000000");
        assert_eq!(f.arqc, "AABBCCDDEEFF0011");
        assert!(f.arpc_params.is_none());
    }

    #[test]
    fn kq_parse_method1_arpc() {
        let mut payload = kq_prefix(b'1', b'1', &single_key(), pan_bcd(), &[0xDE, 0xAD]);
        payload.extend_from_slice(&[0x00, 0x10]); // ARC 2B binary
        let f = parse_kq(&payload).unwrap();
        assert!(matches!(f.mode, KqMode::VerifyArpcMethod1));
        assert!(matches!(
            f.arpc_params,
            Some(ArpcParams::Method1 { ref auth_response_code }) if auth_response_code == "0010"
        ));
    }

    #[test]
    fn kq_parse_method2_arpc_no_pad() {
        let mut payload = kq_prefix(b'2', b'1', &single_key(), pan_bcd(), &[0xDE, 0xAD]);
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CSU 4B
        payload.push(0x00); // PAD len 0
        let f = parse_kq(&payload).unwrap();
        assert_eq!(f.session, EmvSession::Mastercard);
        assert!(matches!(f.mode, KqMode::VerifyArpcMethod2));
        assert!(matches!(
            f.arpc_params,
            Some(ArpcParams::Method2 { ref card_status_update, ref proprietary_auth_data })
                if card_status_update == "00000000" && proprietary_auth_data.is_empty()
        ));
    }

    #[test]
    fn kq_parse_method2_arpc_with_pad() {
        let mut payload = kq_prefix(b'2', b'1', &single_key(), pan_bcd(), &[0xDE, 0xAD]);
        payload.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x12]); // CSU 4B
        payload.push(0x02); // PAD len 2
        payload.extend_from_slice(&[0xCA, 0xFE]); // PAD 2B
        let f = parse_kq(&payload).unwrap();
        assert!(matches!(
            f.arpc_params,
            Some(ArpcParams::Method2 { ref proprietary_auth_data, .. })
                if proprietary_auth_data == "CAFE"
        ));
    }

    #[test]
    fn kq_rejects_mode_3() {
        let payload = kq_prefix(b'3', b'0', &single_key(), pan_bcd(), &[]);
        assert!(matches!(
            parse_kq(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn kq_parse_amex_scheme() {
        let payload = kq_prefix(b'0', b'2', &single_key(), pan_bcd(), &[0xDE, 0xAD]);
        let f = parse_kq(&payload).unwrap();
        assert_eq!(f.session, EmvSession::Amex);
    }

    #[test]
    fn kq_scheme_0_maps_to_visa() {
        // Scheme '0' = Visa (APC SessionKeyVisa: PAN + PAN seq). Parses, not rejected.
        let payload = kq_prefix(b'0', b'0', &single_key(), pan_bcd(), &[0xDE, 0xAD]);
        let f = parse_kq(&payload).unwrap();
        assert_eq!(f.session, EmvSession::Visa);
    }

    #[test]
    fn kq_rejects_invalid_scheme() {
        let payload = kq_prefix(b'0', b'9', &single_key(), pan_bcd(), &[]);
        assert!(matches!(
            parse_kq(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn kq_parse_double_length_key() {
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = kq_prefix(b'0', b'1', &key, pan_bcd(), &[0xAB]);
        let f = parse_kq(&payload).unwrap();
        assert_eq!(f.key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
    }

    #[test]
    fn kq_rejects_missing_delimiter() {
        // Build a payload but replace the 0x3B with 0x00
        let mut payload = kq_prefix(b'0', b'1', &single_key(), pan_bcd(), &[0xDE]);
        // The 0x3B delimiter is at the end before ARQC — find and corrupt it
        let delim_pos = payload.len() - 9; // 1B delim + 8B ARQC
        payload[delim_pos] = 0x00;
        assert!(matches!(
            parse_kq(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }
}
