use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_legacy_key;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield International ARQC verify / ARPC generate: KQ/KR.
///
/// KQ — Verify ARQC/TC/AAC and optionally generate ARPC
///     → APC verify_auth_request_cryptogram (E0 key)
///
/// FIELD LAYOUT SOURCE: EFTlab reference quality. Official Thales International
/// Host Commands PDF unavailable — validate field positions before production.
///
/// KQ field layout:
///   Cryptogram Type:  1N  '0'=ARQC (only supported; '1'=TC '2'=AAC → error 15)
///   Key Type:         3H  consumed (e.g. '00E' for IMK-AC)
///   IMK:              variable  (16H | 'U'+32H | 'T'+48H; APC key type E0 / TR31_E0)
///   ARPC Method:      1N  '0'=Method1 (Auth Resp Code), '1'=Method2 (CSU), '9'=No ARPC
///   Derivation Mode:  1N  'A'=EMV_OPTION_A (Visa/Amex), 'B'=EMV_OPTION_B (Mastercard)
///   PAN:             12N  rightmost 12 digits of PAN, excluding check digit
///   PAN Seq Num:      2N  '00'–'99'
///   ATC:              4H  Application Transaction Counter (tag 9F36, 2 bytes)
///   Txn Data Length:  4H  hex-encoded byte count of transaction data
///   Transaction Data: variable hex (EMV terminal-side data for ARQC recomputation)
///   ARQC:            16H  Authorization Request Cryptogram from chip card
///   [Method '0']:     4H  Auth Response Code (e.g. '0010')
///   [Method '1']:     8H  Card Status Update
///                     2N  Proprietary Auth Data length (decimal byte count)
///                     var Proprietary Auth Data hex
///
/// KR response payload:
///   [ARPC requested]: ARPC 16H
///   [No ARPC]:        empty
///
/// APC requirement: TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS; AES-256 only (AES-128 E0
/// keys are rejected by APC at call time with an access denied error).
///
/// ARQC mismatch (VerificationFailedException) → error 01.
pub struct KqArqcHandler;

const CRYPTOGRAM_TYPE_LEN: usize = 1;
const KEY_TYPE_LEN: usize = 3;
const ARPC_METHOD_LEN: usize = 1;
const DERIV_MODE_LEN: usize = 1;
const PAN_LEN: usize = 12;
const PAN_SEQ_LEN: usize = 2;
const ATC_LEN: usize = 4;
const TXN_LEN_FIELD: usize = 4;
const ARQC_LEN: usize = 16;
const AUTH_RESP_CODE_LEN: usize = 4; // Method '0' only
const CSU_LEN: usize = 8; // Method '1' only
const PAD_LEN_FIELD: usize = 2; // Method '1' only: decimal byte count of proprietary auth data

enum ArpcParams {
    Method1 { auth_response_code: String },
    Method2 { card_status_update: String, proprietary_auth_data: String },
}

struct KqFields {
    key_id: String,
    arpc_method: u8,
    deriv_mode_a: bool, // true=EMV_OPTION_A, false=EMV_OPTION_B
    pan: String,        // 12N — rightmost 12 PAN digits excl. check digit
    pan_seq: String,    // 2N
    atc: String,        // 4H
    txn_data: Zeroizing<String>,
    arqc: String,       // 16H
    arpc_params: Option<ArpcParams>,
}

fn parse_kq(payload: &[u8]) -> Result<KqFields, ProxyError> {
    let mut pos = 0;

    // Cryptogram Type (1N): only ARQC ('0') supported
    if payload.len() < pos + CRYPTOGRAM_TYPE_LEN {
        return Err(ProxyError::MalformedPayload("KQ: cryptogram type missing".into()));
    }
    if payload[pos] != b'0' {
        return Err(ProxyError::MalformedPayload(format!(
            "KQ: cryptogram type '{}' not supported (ARQC '0' only)",
            payload[pos] as char
        )));
    }
    pos += CRYPTOGRAM_TYPE_LEN;

    // Key Type (3H) — consumed
    if payload.len() < pos + KEY_TYPE_LEN {
        return Err(ProxyError::MalformedPayload("KQ: key type missing".into()));
    }
    pos += KEY_TYPE_LEN;

    // IMK (variable)
    let (key_id, key_consumed) = parse_legacy_key(payload, pos)?;
    pos += key_consumed;

    // ARPC Method (1N)
    if payload.len() < pos + ARPC_METHOD_LEN {
        return Err(ProxyError::MalformedPayload("KQ: ARPC method flag missing".into()));
    }
    let arpc_method = payload[pos];
    if !matches!(arpc_method, b'0' | b'1' | b'9') {
        return Err(ProxyError::MalformedPayload(format!(
            "KQ: ARPC method '{}' not supported (0/1/9 only)",
            arpc_method as char
        )));
    }
    pos += ARPC_METHOD_LEN;

    // Derivation Mode (1N): 'A'=EMV_OPTION_A, 'B'=EMV_OPTION_B
    if payload.len() < pos + DERIV_MODE_LEN {
        return Err(ProxyError::MalformedPayload("KQ: derivation mode missing".into()));
    }
    let deriv_mode_a = match payload[pos] {
        b'A' => true,
        b'B' => false,
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "KQ: derivation mode '{}' invalid ('A' or 'B')",
                other as char
            )))
        }
    };
    pos += DERIV_MODE_LEN;

    // PAN (12N)
    if payload.len() < pos + PAN_LEN {
        return Err(ProxyError::MalformedPayload("KQ: PAN field missing".into()));
    }
    let pan = String::from_utf8_lossy(&payload[pos..pos + PAN_LEN]).to_string();
    pos += PAN_LEN;

    // PAN Seq Num (2N)
    if payload.len() < pos + PAN_SEQ_LEN {
        return Err(ProxyError::MalformedPayload("KQ: PAN sequence number missing".into()));
    }
    let pan_seq = String::from_utf8_lossy(&payload[pos..pos + PAN_SEQ_LEN]).to_string();
    pos += PAN_SEQ_LEN;

    // ATC (4H)
    if payload.len() < pos + ATC_LEN {
        return Err(ProxyError::MalformedPayload("KQ: ATC missing".into()));
    }
    let atc = String::from_utf8_lossy(&payload[pos..pos + ATC_LEN]).to_string();
    pos += ATC_LEN;

    // Transaction Data Length (4H)
    if payload.len() < pos + TXN_LEN_FIELD {
        return Err(ProxyError::MalformedPayload("KQ: transaction data length missing".into()));
    }
    let len_hex = std::str::from_utf8(&payload[pos..pos + TXN_LEN_FIELD])
        .map_err(|_| ProxyError::MalformedPayload("KQ: txn length not ASCII".into()))?;
    let txn_byte_len = usize::from_str_radix(len_hex, 16)
        .map_err(|_| ProxyError::MalformedPayload(format!("KQ: invalid txn length '{len_hex}'")))?;
    pos += TXN_LEN_FIELD;

    // Transaction Data (2 × txn_byte_len hex chars)
    let txn_hex_chars = txn_byte_len * 2;
    if payload.len() < pos + txn_hex_chars {
        return Err(ProxyError::MalformedPayload(format!(
            "KQ: transaction data too short: need {txn_hex_chars} hex chars"
        )));
    }
    let txn_data = Zeroizing::new(
        String::from_utf8_lossy(&payload[pos..pos + txn_hex_chars]).to_string(),
    );
    pos += txn_hex_chars;

    // ARQC (16H)
    if payload.len() < pos + ARQC_LEN {
        return Err(ProxyError::MalformedPayload("KQ: ARQC missing".into()));
    }
    let arqc = String::from_utf8_lossy(&payload[pos..pos + ARQC_LEN]).to_string();
    pos += ARQC_LEN;

    // ARPC params (method-dependent)
    let arpc_params = match arpc_method {
        b'0' => {
            // Method 1: Auth Response Code (4H)
            if payload.len() < pos + AUTH_RESP_CODE_LEN {
                return Err(ProxyError::MalformedPayload(
                    "KQ Method1: auth response code missing".into(),
                ));
            }
            let arc = String::from_utf8_lossy(&payload[pos..pos + AUTH_RESP_CODE_LEN]).to_string();
            Some(ArpcParams::Method1 { auth_response_code: arc })
        }
        b'1' => {
            // Method 2: CSU (8H) + PAD length (2N) + PAD data
            if payload.len() < pos + CSU_LEN + PAD_LEN_FIELD {
                return Err(ProxyError::MalformedPayload(
                    "KQ Method2: CSU/PAD fields missing".into(),
                ));
            }
            let csu = String::from_utf8_lossy(&payload[pos..pos + CSU_LEN]).to_string();
            pos += CSU_LEN;
            let pad_len_str = std::str::from_utf8(&payload[pos..pos + PAD_LEN_FIELD])
                .map_err(|_| ProxyError::MalformedPayload("KQ Method2: PAD length not ASCII".into()))?;
            let pad_byte_len: usize = pad_len_str
                .trim()
                .parse()
                .map_err(|_| ProxyError::MalformedPayload(format!("KQ Method2: invalid PAD length '{pad_len_str}'")))?;
            pos += PAD_LEN_FIELD;
            let pad_hex_chars = pad_byte_len * 2;
            if payload.len() < pos + pad_hex_chars {
                return Err(ProxyError::MalformedPayload("KQ Method2: PAD data truncated".into()));
            }
            let pad = String::from_utf8_lossy(&payload[pos..pos + pad_hex_chars]).to_string();
            Some(ArpcParams::Method2 { card_status_update: csu, proprietary_auth_data: pad })
        }
        _ => None, // b'9' — no ARPC
    };

    Ok(KqFields {
        key_id,
        arpc_method,
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
impl Handler for KqArqcHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["KQ"]
    }

    async fn handle(&self, _command_code: &[u8], payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
        handle_kq(payload, state).await
    }
}

async fn handle_kq(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_kq(payload) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let key_arn = match state.key_map.resolve(&fields.key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        CryptogramAuthResponse, CryptogramVerificationArpcMethod1, CryptogramVerificationArpcMethod2,
        MajorKeyDerivationMode, SessionKeyDerivation, SessionKeyEmvCommon,
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
        .map_err(|e: aws_sdk_paymentcryptographydata::error::BuildError| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let session_key_attrs = SessionKeyDerivation::EmvCommon(emv_common);

    let auth_response_attrs: Option<CryptogramAuthResponse> = match fields.arpc_params {
        Some(ArpcParams::Method1 { ref auth_response_code }) => {
            match CryptogramVerificationArpcMethod1::builder()
                .auth_response_code(auth_response_code)
                .build()
                .map_err(|e: aws_sdk_paymentcryptographydata::error::BuildError| ProxyError::ApcError(e.to_string()))
            {
                Ok(m1) => Some(CryptogramAuthResponse::ArpcMethod1(m1)),
                Err(e) => return HandlerResult::from_proxy_error(&e),
            }
        }
        Some(ArpcParams::Method2 { ref card_status_update, ref proprietary_auth_data }) => {
            let mut m2_b = CryptogramVerificationArpcMethod2::builder()
                .card_status_update(card_status_update);
            if !proprietary_auth_data.is_empty() {
                m2_b = m2_b.proprietary_authentication_data(proprietary_auth_data);
            }
            match m2_b
                .build()
                .map_err(|e: aws_sdk_paymentcryptographydata::error::BuildError| ProxyError::ApcError(e.to_string()))
            {
                Ok(m2) => Some(CryptogramAuthResponse::ArpcMethod2(m2)),
                Err(e) => return HandlerResult::from_proxy_error(&e),
            }
        }
        None => None,
    };

    debug!(
        key = %key_arn,
        arpc_method = %(fields.arpc_method as char),
        deriv = if fields.deriv_mode_a { "EMV_OPTION_A" } else { "EMV_OPTION_B" },
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
                .map(|s| s.is_verification_failed_exception())
                .unwrap_or(false)
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

    fn imk_single() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec() // 16H
    }

    /// Build a KQ payload prefix through ARQC (no ARPC params appended yet).
    fn kq_prefix(imk: &[u8], arpc_method: u8, deriv: u8, txn_hex: &[u8]) -> Vec<u8> {
        let mut v = vec![b'0'];       // ARQC type
        v.extend_from_slice(b"00E"); // key type
        v.extend_from_slice(imk);
        v.push(arpc_method);
        v.push(deriv);
        v.extend_from_slice(b"123456789012"); // PAN 12N
        v.extend_from_slice(b"01");           // PAN seq
        v.extend_from_slice(b"0001");          // ATC 4H
        let byte_count = txn_hex.len() / 2;
        v.extend_from_slice(format!("{:04X}", byte_count).as_bytes());
        v.extend_from_slice(txn_hex);
        v.extend_from_slice(b"AABBCCDDEEFF0011"); // ARQC 16H
        v
    }

    #[test]
    fn kq_parse_arqc_no_arpc() {
        let payload = kq_prefix(&imk_single(), b'9', b'A', b"AABBCCDD");
        let result = parse_kq(&payload).unwrap();
        assert_eq!(result.key_id, "1234567890ABCDEF");
        assert_eq!(result.arpc_method, b'9');
        assert!(result.deriv_mode_a);
        assert_eq!(result.pan, "123456789012");
        assert_eq!(result.pan_seq, "01");
        assert_eq!(result.atc, "0001");
        assert_eq!(result.txn_data.as_str(), "AABBCCDD");
        assert_eq!(result.arqc, "AABBCCDDEEFF0011");
        assert!(result.arpc_params.is_none());
    }

    #[test]
    fn kq_parse_method1_arpc() {
        let mut payload = kq_prefix(&imk_single(), b'0', b'A', b"AABBCCDD");
        payload.extend_from_slice(b"0010"); // auth response code
        let result = parse_kq(&payload).unwrap();
        assert!(matches!(
            result.arpc_params,
            Some(ArpcParams::Method1 { ref auth_response_code }) if auth_response_code == "0010"
        ));
    }

    #[test]
    fn kq_parse_method2_arpc_no_pad() {
        let mut payload = kq_prefix(&imk_single(), b'1', b'B', b"AABBCCDD");
        payload.extend_from_slice(b"00000000"); // CSU 8H
        payload.extend_from_slice(b"00");       // PAD length 0 bytes
        let result = parse_kq(&payload).unwrap();
        assert!(!result.deriv_mode_a);
        assert!(matches!(
            result.arpc_params,
            Some(ArpcParams::Method2 { ref card_status_update, ref proprietary_auth_data })
                if card_status_update == "00000000" && proprietary_auth_data.is_empty()
        ));
    }

    #[test]
    fn kq_rejects_tc_type() {
        let mut payload = vec![b'1']; // TC — unsupported
        payload.extend_from_slice(b"00E1234567890ABCDEF9A12345678901201000100001234567890ABCDEF");
        assert!(matches!(parse_kq(&payload), Err(ProxyError::MalformedPayload(_))));
    }

    #[test]
    fn kq_rejects_invalid_deriv_mode() {
        let mut payload = vec![b'0'];
        payload.extend_from_slice(b"00E");
        payload.extend_from_slice(&imk_single());
        payload.push(b'9'); // ARPC method
        payload.push(b'C'); // invalid derivation mode
        assert!(matches!(parse_kq(&payload), Err(ProxyError::MalformedPayload(_))));
    }

    #[test]
    fn kq_parse_double_length_key() {
        let mut imk = vec![b'U'];
        imk.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = kq_prefix(&imk, b'9', b'A', b"AABBCCDD");
        let result = parse_kq(&payload).unwrap();
        assert_eq!(result.key_id, "U1234567890ABCDEF1234567890ABCDEF");
    }
}
