use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{
    build_session_key, bytes_to_hex, decode_bcd_pan_seq, emv_pad, parse_legacy_key, EmvSession,
};
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
///                         '0'=Visa VIS (static, no session key — no APC equivalent)
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

enum ArpcParams {
    Method1 {
        auth_response_code: String,
    },
    Method2 {
        card_status_update: String,
        proprietary_auth_data: String,
    },
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
    let mut pos = 0;

    // Mode Flag (1N ASCII)
    if payload.len() < pos + 1 {
        return Err(ProxyError::MalformedPayload("KQ: mode flag missing".into()));
    }
    let mode = match payload[pos] {
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
    pos += 1;

    // Scheme ID (1N ASCII)
    if payload.len() < pos + 1 {
        return Err(ProxyError::MalformedPayload("KQ: scheme ID missing".into()));
    }
    // All KQ schemes use EMV Option A major derivation (PUGD0537-004 Rev A p.468);
    // the Scheme ID selects the session-key method.
    let session = match payload[pos] {
        b'1' => EmvSession::Mastercard, // Option A + Mastercard proprietary SKD (M/Chip)
        b'2' => EmvSession::Amex,       // Option A + Amex AEIPS
        b'0' => {
            // Visa VIS is static (ICC master key used directly, no session key).
            // APC always derives a session key, so this has no faithful equivalent
            // (verified against live APC: every APC session mode rejects it).
            return Err(ProxyError::Unsupported(
                "KQ scheme '0' (Visa VIS, static session key) has no APC equivalent".into(),
            ));
        }
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "KQ: invalid scheme ID '{}' (1=MC M/Chip, 2=Amex)",
                other as char
            )))
        }
    };
    pos += 1;

    // Key Type (3H ASCII) — consumed
    if payload.len() < pos + 3 {
        return Err(ProxyError::MalformedPayload("KQ: key type missing".into()));
    }
    pos += 3;

    // Key (variable ASCII hex)
    let (key_id, key_consumed) = parse_legacy_key(payload, pos)?;
    pos += key_consumed;

    // PAN+Seq (8B binary BCD)
    if payload.len() < pos + 8 {
        return Err(ProxyError::MalformedPayload(
            "KQ: PAN+seq field missing".into(),
        ));
    }
    let pan_seq_bytes: [u8; 8] = payload[pos..pos + 8]
        .try_into()
        .expect("length checked above");
    let (pan, pan_seq) = decode_bcd_pan_seq(pan_seq_bytes);
    pos += 8;

    // ATC (2B binary)
    if payload.len() < pos + 2 {
        return Err(ProxyError::MalformedPayload("KQ: ATC missing".into()));
    }
    let atc = bytes_to_hex(&payload[pos..pos + 2]);
    pos += 2;

    // UN (4B binary) — forwarded; required by the Mastercard proprietary SKD
    if payload.len() < pos + 4 {
        return Err(ProxyError::MalformedPayload("KQ: UN missing".into()));
    }
    let un = bytes_to_hex(&payload[pos..pos + 4]);
    pos += 4;

    // TxnLen (2B binary big-endian)
    if payload.len() < pos + 2 {
        return Err(ProxyError::MalformedPayload(
            "KQ: transaction data length missing".into(),
        ));
    }
    let txn_byte_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    // TxnData (txn_byte_len binary bytes)
    if payload.len() < pos + txn_byte_len {
        return Err(ProxyError::MalformedPayload(format!(
            "KQ: transaction data too short: need {txn_byte_len} bytes"
        )));
    }
    // APC does not pad; forward EMV (ISO 9797-1 method 2) padded data.
    let txn_data = Zeroizing::new(bytes_to_hex(&emv_pad(&payload[pos..pos + txn_byte_len])));
    pos += txn_byte_len;

    // Delimiter 0x3B
    if payload.len() < pos + 1 || payload[pos] != 0x3B {
        return Err(ProxyError::MalformedPayload(
            "KQ: missing 0x3B delimiter".into(),
        ));
    }
    pos += 1;

    // ARQC (8B binary)
    if payload.len() < pos + 8 {
        return Err(ProxyError::MalformedPayload("KQ: ARQC missing".into()));
    }
    let arqc = bytes_to_hex(&payload[pos..pos + 8]);
    pos += 8;

    // ARPC params (mode-dependent, binary)
    let arpc_params = match mode {
        KqMode::VerifyArpcMethod1 => {
            // ARC (2B binary)
            if payload.len() < pos + 2 {
                return Err(ProxyError::MalformedPayload(
                    "KQ Method1: ARC missing".into(),
                ));
            }
            let arc = bytes_to_hex(&payload[pos..pos + 2]);
            Some(ArpcParams::Method1 {
                auth_response_code: arc,
            })
        }
        KqMode::VerifyArpcMethod2 => {
            // CSU (4B binary)
            if payload.len() < pos + 4 {
                return Err(ProxyError::MalformedPayload(
                    "KQ Method2: CSU missing".into(),
                ));
            }
            let csu = bytes_to_hex(&payload[pos..pos + 4]);
            pos += 4;
            // PAD_len (1B binary)
            if payload.len() < pos + 1 {
                return Err(ProxyError::MalformedPayload(
                    "KQ Method2: PAD length missing".into(),
                ));
            }
            let pad_len = payload[pos] as usize;
            pos += 1;
            if payload.len() < pos + pad_len {
                return Err(ProxyError::MalformedPayload(
                    "KQ Method2: PAD data truncated".into(),
                ));
            }
            let pad = bytes_to_hex(&payload[pos..pos + pad_len]);
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
                       verify_auth_request_cryptogram. Scheme ID selects the session-key method \
                       (Mastercard M/Chip, Amex AEIPS) on EMV Option A; Visa VIS (static, Scheme \
                       '0') and skip-verify modes 3/4 are rejected as having no APC equivalent. \
                       Mode 1/2 map to ARPC Method 1 (ARC) / Method 2 (CSU + proprietary data).",
            because: "PUGD0537-004 Rev A p.468 (KQ). Verified live for the Mastercard scheme ('1', \
                      Option A + Mastercard proprietary SKD): APC mints a valid ARQC via \
                      generate_auth_request_cryptogram under a created E0 IMK (DeriveKey mode), the \
                      proxy's KQ handler verifies it through APC and ACCEPTS (00), and a \
                      one-bit-corrupted ARQC is REJECTED (01), across randomized PAN / PSN / ATC / \
                      Unpredictable Number / txn length — the differential confirms the UN is \
                      forwarded to APC's Mastercard session-key derivation. The Amex scheme ('2', \
                      Option A + Amex SKD) is verified the same way in arqc_verify_kq_amex_differential. \
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

    use aws_sdk_paymentcryptographydata::types::{
        CryptogramAuthResponse, CryptogramVerificationArpcMethod1,
        CryptogramVerificationArpcMethod2, MajorKeyDerivationMode,
    };

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

    let auth_response_attrs: Option<CryptogramAuthResponse> = match fields.arpc_params {
        Some(ArpcParams::Method1 {
            ref auth_response_code,
        }) => {
            match CryptogramVerificationArpcMethod1::builder()
                .auth_response_code(auth_response_code)
                .build()
                .map_err(|e: aws_sdk_paymentcryptographydata::error::BuildError| {
                    ProxyError::ApcError(e.to_string())
                }) {
                Ok(m1) => Some(CryptogramAuthResponse::ArpcMethod1(m1)),
                Err(e) => return HandlerResult::from_proxy_error(&e),
            }
        }
        Some(ArpcParams::Method2 {
            ref card_status_update,
            ref proprietary_auth_data,
        }) => {
            let mut m2_b =
                CryptogramVerificationArpcMethod2::builder().card_status_update(card_status_update);
            if !proprietary_auth_data.is_empty() {
                m2_b = m2_b.proprietary_authentication_data(proprietary_auth_data);
            }
            match m2_b
                .build()
                .map_err(|e: aws_sdk_paymentcryptographydata::error::BuildError| {
                    ProxyError::ApcError(e.to_string())
                }) {
                Ok(m2) => Some(CryptogramAuthResponse::ArpcMethod2(m2)),
                Err(e) => return HandlerResult::from_proxy_error(&e),
            }
        }
        None => None,
    };

    debug!(
        key = %key_arn,
        mode = ?fields.mode,
        session = ?fields.session,
        "KQ: verify_auth_request_cryptogram"
    );

    let mut req = state
        .data
        .verify_auth_request_cryptogram()
        .key_identifier(&key_arn)
        .transaction_data(fields.txn_data.as_str())
        .auth_request_cryptogram(&fields.arqc)
        .major_key_derivation_mode(deriv_mode)
        .session_key_derivation_attributes(session_key_attrs);

    if let Some(ara) = auth_response_attrs {
        req = req.auth_response_attributes(ara);
    }

    match req.send().await {
        Ok(resp) => match resp.auth_response_value() {
            Some(arpc) => HandlerResult::success(arpc.as_bytes().to_vec()),
            None => HandlerResult::success(vec![]),
        },
        Err(e) => {
            if e.as_service_error()
                .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_auth_request_cryptogram::VerifyAuthRequestCryptogramError::is_verification_failed_exception)
            {
                warn!("KQ: ARQC mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "KQ: verify_auth_request_cryptogram failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
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
    fn kq_rejects_scheme_0_static() {
        // Visa VIS static has no APC equivalent → Unsupported (payShield 68).
        let payload = kq_prefix(b'0', b'0', &single_key(), pan_bcd(), &[0xDE, 0xAD]);
        assert!(matches!(
            parse_kq(&payload),
            Err(ProxyError::Unsupported(_))
        ));
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
