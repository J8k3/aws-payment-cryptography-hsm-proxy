use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{bytes_to_hex, decode_bcd_pan_seq, parse_legacy_key};
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield KW — Verify ARQC and optionally generate ARPC (EMV & Cloud-Based SKD).
///
/// Wire format per PUGD0537-004 p.471 — identical to KQ with one extra field:
///
///   Mode Flag        1N ASCII  '0'=verify only
///                              '1'=verify + ARPC Method 1 (ARC)
///                              '2'=verify + ARPC Method 2 (CSU)
///                              '3'/'4'=skip-verify ARPC (not supported by APC)
///   Scheme ID        1N ASCII  '0'=Visa/Amex → EmvOptionA
///                              '1'=Mastercard → EmvOptionB
///   Derivation Method 1A ASCII 'A'=EMV_OPTION_A, 'B'=EMV_OPTION_B (used for session key)
///   Key Type         3H ASCII  consumed
///   Key              var       16H | 'U'+32H | 'T'+48H
///   PAN+Seq          8B binary BCD — 12 PAN digits + 2 seq digits, right-padded 0xFF
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
/// KW extends KQ with Visa CVN14/CVN18/CVN22 and Mastercard M/Chip SKD variants.
/// The Derivation Method byte ('A'/'B') selects the session key derivation algorithm;
/// it maps to the same MajorKeyDerivationMode as Scheme ID in KQ, so the proxy
/// uses Scheme ID for the APC parameter and consumes Derivation Method.
pub struct KwArqcHandler;

#[derive(Debug)]
enum KwMode {
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

struct KwFields {
    key_id: String,
    mode: KwMode,
    deriv_mode_a: bool,
    pan: String,
    pan_seq: String,
    atc: String,
    txn_data: Zeroizing<String>,
    arqc: String,
    arpc_params: Option<ArpcParams>,
}

fn parse_kw(payload: &[u8]) -> Result<KwFields, ProxyError> {
    let mut pos = 0;

    // Mode Flag (1N ASCII)
    if payload.len() < pos + 1 {
        return Err(ProxyError::MalformedPayload("KW: mode flag missing".into()));
    }
    let mode = match payload[pos] {
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
    pos += 1;

    // Scheme ID (1N ASCII) → MajorKeyDerivationMode
    if payload.len() < pos + 1 {
        return Err(ProxyError::MalformedPayload("KW: scheme ID missing".into()));
    }
    let deriv_mode_a = match payload[pos] {
        b'0' => true,  // Visa/Amex → EmvOptionA
        b'1' => false, // Mastercard → EmvOptionB
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "KW: invalid scheme ID '{}' (0=Visa/Amex, 1=MC)",
                other as char
            )))
        }
    };
    pos += 1;

    // Derivation Method (1A ASCII) — consumed; redundant with Scheme ID for APC
    if payload.len() < pos + 1 {
        return Err(ProxyError::MalformedPayload(
            "KW: derivation method missing".into(),
        ));
    }
    if !matches!(payload[pos], b'A' | b'B') {
        return Err(ProxyError::MalformedPayload(format!(
            "KW: invalid derivation method '{}' ('A' or 'B')",
            payload[pos] as char
        )));
    }
    pos += 1;

    // Key Type (3H ASCII) — consumed
    if payload.len() < pos + 3 {
        return Err(ProxyError::MalformedPayload("KW: key type missing".into()));
    }
    pos += 3;

    // Key (variable ASCII hex)
    let (key_id, key_consumed) = parse_legacy_key(payload, pos)?;
    pos += key_consumed;

    // PAN+Seq (8B binary BCD)
    if payload.len() < pos + 8 {
        return Err(ProxyError::MalformedPayload(
            "KW: PAN+seq field missing".into(),
        ));
    }
    let pan_seq_bytes: [u8; 8] = payload[pos..pos + 8]
        .try_into()
        .expect("length checked above");
    let (pan, pan_seq) = decode_bcd_pan_seq(pan_seq_bytes);
    pos += 8;

    // ATC (2B binary)
    if payload.len() < pos + 2 {
        return Err(ProxyError::MalformedPayload("KW: ATC missing".into()));
    }
    let atc = bytes_to_hex(&payload[pos..pos + 2]);
    pos += 2;

    // UN (4B binary)
    if payload.len() < pos + 4 {
        return Err(ProxyError::MalformedPayload("KW: UN missing".into()));
    }
    pos += 4; // UN: parsed for position only; not forwarded (see KNOWN GAP in EmvCommon comment)

    // TxnLen (2B binary big-endian)
    if payload.len() < pos + 2 {
        return Err(ProxyError::MalformedPayload(
            "KW: transaction data length missing".into(),
        ));
    }
    let txn_byte_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    // TxnData
    if payload.len() < pos + txn_byte_len {
        return Err(ProxyError::MalformedPayload(format!(
            "KW: transaction data too short: need {txn_byte_len} bytes"
        )));
    }
    let txn_data = Zeroizing::new(bytes_to_hex(&payload[pos..pos + txn_byte_len]));
    pos += txn_byte_len;

    // Delimiter 0x3B
    if payload.len() < pos + 1 || payload[pos] != 0x3B {
        return Err(ProxyError::MalformedPayload(
            "KW: missing 0x3B delimiter".into(),
        ));
    }
    pos += 1;

    // ARQC (8B binary)
    if payload.len() < pos + 8 {
        return Err(ProxyError::MalformedPayload("KW: ARQC missing".into()));
    }
    let arqc = bytes_to_hex(&payload[pos..pos + 8]);
    pos += 8;

    // ARPC params
    let arpc_params = match mode {
        KwMode::VerifyArpcMethod1 => {
            if payload.len() < pos + 2 {
                return Err(ProxyError::MalformedPayload(
                    "KW Method1: ARC missing".into(),
                ));
            }
            let arc = bytes_to_hex(&payload[pos..pos + 2]);
            Some(ArpcParams::Method1 {
                auth_response_code: arc,
            })
        }
        KwMode::VerifyArpcMethod2 => {
            if payload.len() < pos + 4 {
                return Err(ProxyError::MalformedPayload(
                    "KW Method2: CSU missing".into(),
                ));
            }
            let csu = bytes_to_hex(&payload[pos..pos + 4]);
            pos += 4;
            if payload.len() < pos + 1 {
                return Err(ProxyError::MalformedPayload(
                    "KW Method2: PAD length missing".into(),
                ));
            }
            let pad_len = payload[pos] as usize;
            pos += 1;
            if payload.len() < pos + pad_len {
                return Err(ProxyError::MalformedPayload(
                    "KW Method2: PAD data truncated".into(),
                ));
            }
            let pad = bytes_to_hex(&payload[pos..pos + pad_len]);
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
        pan,
        pan_seq,
        atc,
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

    let key_arn = match state.key_map.resolve(&fields.key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        CryptogramAuthResponse, CryptogramVerificationArpcMethod1,
        CryptogramVerificationArpcMethod2, MajorKeyDerivationMode, SessionKeyDerivation,
        SessionKeyEmvCommon,
    };

    let deriv_mode = if fields.deriv_mode_a {
        MajorKeyDerivationMode::EmvOptionA
    } else {
        MajorKeyDerivationMode::EmvOptionB
    };

    let emv_common = match SessionKeyEmvCommon::builder()
        .application_transaction_counter(&fields.atc)
        .pan_sequence_number(&fields.pan_seq)
        .primary_account_number(&fields.pan)
        .build()
        .map_err(|e: aws_sdk_paymentcryptographydata::error::BuildError| {
            ProxyError::ApcError(e.to_string())
        }) {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    // KNOWN GAP: same EmvCommon limitation as KQ — see kq_arqc.rs for details.
    // KW adds CVN14/CVN18/CVN22 and M/Chip SKD variants (via the Derivation Method byte),
    // but the command does not carry enough information to auto-select the correct APC
    // SessionKeyDerivation variant (Visa, Mastercard, or EmvCommon).
    let session_key_attrs = SessionKeyDerivation::EmvCommon(emv_common);

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
        deriv = if fields.deriv_mode_a { "EmvOptionA" } else { "EmvOptionB" },
        "KW: verify_auth_request_cryptogram"
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
                warn!("KW: ARQC mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "KW: verify_auth_request_cryptogram failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_key() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec() // 16H single-length
    }

    // PAN: 123456789012, Seq: 01 → BCD: 12 34 56 78 90 12 | 01 FF
    fn pan_bcd() -> [u8; 8] {
        [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x01, 0xFF]
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
        assert!(f.deriv_mode_a);
        assert_eq!(f.pan, "123456789012");
        assert_eq!(f.pan_seq, "01");
        assert_eq!(f.atc, "0001");
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
    fn kw_parse_mastercard_scheme() {
        let payload = kw_prefix(b'0', b'1', b'B', &single_key(), &[]);
        let f = parse_kw(&payload).unwrap();
        assert!(!f.deriv_mode_a);
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
