use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{bytes_to_hex, decode_bcd_pan_seq, emv_pad, parse_key_32};
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield JS — ARQC Verification and/or ARPC Generation (UnionPay / CUP).
///
/// Source: PUGD0538-003 §7 pp.122-123. Response code: JT.
/// License: PS10-LIC-LEGACY.
///
/// Wire format (binary, Modes 0 and 1):
///
///   Mode Flag    1N ASCII  '0'=verify only
///                          '1'=verify + ARPC Method 1 (ARC)
///                          '2'=ARPC-only (reject: APC requires transaction data)
///   Scheme ID    1N ASCII  always '1' (CUP Card Key Derivation ver4.2) — consumed
///   Key          var       32H | 'U'+32H | 'T'+48H  (parse_key_32; no key-type prefix)
///   PAN+Seq      8B binary BCD — 12 PAN digits + 2 seq + 2 padding nibbles (0xFF)
///   ATC          2B binary Application Transaction Counter
///   Padding Flag 1N ASCII  '0'=none, '1'=CUP 0x80-pad applied — consumed
///   TxnLen       2H ASCII  byte count of TxnData (max 0xFF = 255 bytes)
///   TxnData      nB binary EMV terminal transaction data
///   0x3B         1B        delimiter
///   ARQC         8B binary Authorization Request Cryptogram
///   Mode '1' only:
///     ARC        2B binary Authorization Response Code
///
/// APC: verify_auth_request_cryptogram with TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS,
///      SessionKeyDerivation::Emv2000, MajorKeyDerivationMode::EmvOptionA.
/// No ARPC Method 2 (CSU) — JS has no CSU field.
pub struct UnionPayArqcHandler;

enum JsMode {
    VerifyOnly,
    VerifyWithArpc,
}

struct JsFields {
    key_id: KeyDescriptor,
    pan: String,
    pan_seq: String,
    atc: String,
    txn_data: Zeroizing<String>,
    arqc: String,
    arc: Option<String>,
}

fn parse_js(payload: &[u8]) -> Result<JsFields, ProxyError> {
    let mut pos = 0;

    // Mode Flag (1N)
    if payload.is_empty() {
        return Err(ProxyError::MalformedPayload("JS: mode flag missing".into()));
    }
    let mode = match payload[pos] {
        b'0' => JsMode::VerifyOnly,
        b'1' => JsMode::VerifyWithArpc,
        b'2' => {
            return Err(ProxyError::MalformedPayload(
                "JS: mode '2' (ARPC-only) not supported — APC requires transaction data".into(),
            ))
        }
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "JS: unknown mode '{}'",
                other as char
            )))
        }
    };
    pos += 1;

    // Scheme ID (1N) — always '1' for CUP; consume and discard
    if payload.len() < pos + 1 {
        return Err(ProxyError::MalformedPayload("JS: scheme ID missing".into()));
    }
    pos += 1;

    // Key (32H baseline; no key-type prefix in JS)
    let (key_id, key_consumed) = parse_key_32(payload, pos)?;
    pos += key_consumed;

    // PAN+Seq (8B binary BCD)
    const PAN_SEQ_BYTES: usize = 8;
    if payload.len() < pos + PAN_SEQ_BYTES {
        return Err(ProxyError::MalformedPayload("JS: PAN+Seq missing".into()));
    }
    let pan_seq_arr: [u8; 8] = payload[pos..pos + PAN_SEQ_BYTES]
        .try_into()
        .map_err(|_| ProxyError::MalformedPayload("JS: PAN+Seq slice error".into()))?;
    let (pan, pan_seq) = decode_bcd_pan_seq(pan_seq_arr);
    pos += PAN_SEQ_BYTES;

    // ATC (2B binary)
    if payload.len() < pos + 2 {
        return Err(ProxyError::MalformedPayload("JS: ATC missing".into()));
    }
    let atc = bytes_to_hex(&payload[pos..pos + 2]);
    pos += 2;

    // Padding Flag (1N) — consumed
    if payload.len() < pos + 1 {
        return Err(ProxyError::MalformedPayload(
            "JS: padding flag missing".into(),
        ));
    }
    pos += 1;

    // TxnLen (2H ASCII hex — 2 chars, value = byte count)
    if payload.len() < pos + 2 {
        return Err(ProxyError::MalformedPayload("JS: TxnLen missing".into()));
    }
    let len_hex = std::str::from_utf8(&payload[pos..pos + 2])
        .map_err(|_| ProxyError::MalformedPayload("JS: TxnLen not ASCII".into()))?;
    let txn_byte_len = usize::from_str_radix(len_hex, 16)
        .map_err(|_| ProxyError::MalformedPayload(format!("JS: invalid TxnLen '{len_hex}'")))?;
    pos += 2;

    // TxnData (nB binary)
    if payload.len() < pos + txn_byte_len {
        return Err(ProxyError::MalformedPayload(format!(
            "JS: TxnData truncated: need {txn_byte_len}B"
        )));
    }
    // APC does not pad; forward EMV (ISO 9797-1 method 2) padded transaction data.
    let txn_data = Zeroizing::new(bytes_to_hex(&emv_pad(&payload[pos..pos + txn_byte_len])));
    pos += txn_byte_len;

    // 0x3B delimiter
    if payload.get(pos) != Some(&0x3B) {
        return Err(ProxyError::MalformedPayload(format!(
            "JS: expected 0x3B delimiter at offset {pos}, got {:?}",
            payload.get(pos)
        )));
    }
    pos += 1;

    // ARQC (8B binary)
    if payload.len() < pos + 8 {
        return Err(ProxyError::MalformedPayload("JS: ARQC missing".into()));
    }
    let arqc = bytes_to_hex(&payload[pos..pos + 8]);
    pos += 8;

    // ARC (2B binary) — Mode '1' only
    let arc = if matches!(mode, JsMode::VerifyWithArpc) {
        if payload.len() < pos + 2 {
            return Err(ProxyError::MalformedPayload("JS Mode1: ARC missing".into()));
        }
        Some(bytes_to_hex(&payload[pos..pos + 2]))
    } else {
        None
    };

    Ok(JsFields {
        key_id,
        pan,
        pan_seq,
        atc,
        txn_data,
        arqc,
        arc,
    })
}

#[async_trait]
impl Handler for UnionPayArqcHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["JS"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision: "JS verifies a UnionPay (CUP) Authorisation Request Cryptogram → APC \
                       verify_auth_request_cryptogram. Response code JT.",
            because: "PUGD0538-003 §7 p.122. Verified live end-to-end: APC mints a valid ARQC via \
                      generate_auth_request_cryptogram (Emv2000, Option A) under a created IMK-AC \
                      (E0, DeriveKey mode), the proxy's JS handler verifies it through APC and \
                      ACCEPTS (00), and a one-bit-corrupted ARQC is REJECTED (01), across \
                      randomized PAN / PSN / ATC / txn length.",
            wire: WireGrounding::DiffXprov,
            crypto: CryptoGrounding::Apc,
            proof: Proof::LiveTest("arqc_verify_js_differential"),
        }]
    }

    async fn handle(
        &self,
        _command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        handle_js(payload, state).await
    }
}

async fn handle_js(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_js(payload) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let key_arn = match state.key_map.resolve_descriptor(&fields.key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        CryptogramAuthResponse, CryptogramVerificationArpcMethod1, MajorKeyDerivationMode,
        SessionKeyDerivation, SessionKeyEmv2000,
    };

    let emv2000 = match SessionKeyEmv2000::builder()
        .primary_account_number(&fields.pan)
        .pan_sequence_number(&fields.pan_seq)
        .application_transaction_counter(&fields.atc)
        .build()
        .map_err(|e: aws_sdk_paymentcryptographydata::error::BuildError| {
            ProxyError::ApcError(e.to_string())
        }) {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let auth_response_attrs: Option<CryptogramAuthResponse> = match fields.arc {
        Some(ref arc) => {
            match CryptogramVerificationArpcMethod1::builder()
                .auth_response_code(arc)
                .build()
                .map_err(|e: aws_sdk_paymentcryptographydata::error::BuildError| {
                    ProxyError::ApcError(e.to_string())
                }) {
                Ok(m1) => Some(CryptogramAuthResponse::ArpcMethod1(m1)),
                Err(e) => return HandlerResult::from_proxy_error(&e),
            }
        }
        None => None,
    };

    debug!(key = %key_arn, "JS: verify_auth_request_cryptogram (UnionPay/CUP Emv2000)");

    let mut req = state
        .data
        .verify_auth_request_cryptogram()
        .key_identifier(&key_arn)
        .transaction_data(fields.txn_data.as_str())
        .auth_request_cryptogram(&fields.arqc)
        .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
        .session_key_derivation_attributes(SessionKeyDerivation::Emv2000(emv2000));

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
                warn!("JS: ARQC mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "JS: verify_auth_request_cryptogram failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // EMV pre-formatted (rightmost 16 of PAN||PSN) "1234567890123401" -> PAN 12345678901234, Seq 01
    const PAN_SEQ_BCD: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x01];

    fn double_key() -> Vec<u8> {
        b"1234567890ABCDEF1234567890ABCDEF".to_vec() // 32H baseline
    }

    /// Build a JS payload. TxnData is 4 raw binary bytes.
    fn build_payload(mode: u8, key: &[u8], include_arc: bool) -> Vec<u8> {
        let txn: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let mut v = Vec::new();
        v.push(mode); // Mode Flag
        v.push(b'1'); // Scheme ID (CUP = '1')
        v.extend_from_slice(key); // Key
        v.extend_from_slice(&PAN_SEQ_BCD); // PAN+Seq 8B BCD
        v.extend_from_slice(&[0x00, 0x01]); // ATC 2B binary
        v.push(b'0'); // Padding Flag
        v.extend_from_slice(b"04"); // TxnLen 2H = 4 bytes
        v.extend_from_slice(txn); // TxnData 4B binary
        v.push(0x3B); // delimiter
        v.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]); // ARQC 8B
        if include_arc {
            v.extend_from_slice(&[0x00, 0x10]); // ARC 2B binary
        }
        v
    }

    #[test]
    fn js_parse_verify_only() {
        let payload = build_payload(b'0', &double_key(), false);
        let f = parse_js(&payload).unwrap();
        assert_eq!(f.key_id.raw, "1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.pan, "12345678901234");
        assert_eq!(f.pan_seq, "01");
        assert_eq!(f.atc, "0001");
        assert_eq!(f.txn_data.as_str(), "DEADBEEF80000000"); // EMV method-2 padded for APC
        assert_eq!(f.arqc, "AABBCCDDEEFF0011");
        assert!(f.arc.is_none());
    }

    #[test]
    fn js_parse_with_arpc() {
        let payload = build_payload(b'1', &double_key(), true);
        let f = parse_js(&payload).unwrap();
        assert_eq!(f.arc, Some("0010".to_string()));
    }

    #[test]
    fn js_parse_u_prefix_key() {
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = build_payload(b'0', &key, false);
        let f = parse_js(&payload).unwrap();
        assert_eq!(f.key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
    }

    #[test]
    fn js_rejects_mode_2() {
        let payload = build_payload(b'2', &double_key(), false);
        assert!(matches!(
            parse_js(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn js_rejects_missing_arc_for_mode1() {
        let payload = build_payload(b'1', &double_key(), false); // no ARC appended
        assert!(matches!(
            parse_js(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn js_rejects_bad_delimiter() {
        let mut payload = build_payload(b'0', &double_key(), false);
        let del_pos = payload.iter().rposition(|&b| b == 0x3B).unwrap();
        payload[del_pos] = 0x00;
        assert!(matches!(
            parse_js(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }
}
