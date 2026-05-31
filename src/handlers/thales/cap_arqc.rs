use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{bytes_to_hex, decode_bcd_pan_seq, parse_legacy_key};
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield K2 — Verify Mastercard CAP / Dynamic CAP cryptogram.
/// payShield KS — Verify EMV 3.1.1 Dynamic Data Authentication Code.
///
/// K2 (→ K3) wire format per PUGD0537-004 (binary, not ASCII hex):
///   Key Type    3H ASCII  consumed (E0 — IMK-AC)
///   Key         var       16H | 'U'+32H | 'T'+48H
///   PAN+Seq     8B binary BCD — 12 PAN digits + 2 seq digits, right-padded 0xFF
///   ATC         2B binary Application Transaction Counter
///   UN          4B binary Unpredictable Number (required by Mastercard M/Chip)
///   TxnLen      2B binary big-endian byte count of transaction data
///   TxnData     nB binary
///   0x3B        1B        delimiter
///   Cryptogram  8B binary
///
/// K2 → APC verify_auth_request_cryptogram, SessionKeyDerivation::Mastercard
///       (PAN + PanSeq + ATC + UN), MajorKeyDerivationMode::EmvOptionB, verify-only.
///
/// KS (→ KT) wire format per PUGD0537-004:
///   Key Type    3H ASCII  consumed (E0 — IMK-AC)
///   Key         var       16H | 'U'+32H | 'T'+48H
///   PAN+Seq     8B binary BCD
///   ATC         2B binary
///   TxnLen      2B binary big-endian
///   TxnData     nB binary
///   0x3B        1B        delimiter
///   Cryptogram  8B binary
///
/// KS → APC verify_auth_request_cryptogram, SessionKeyDerivation::Emv2000
///       (PAN + PanSeq + ATC, no UN), MajorKeyDerivationMode::EmvOptionA, verify-only.
///
/// Cryptogram mismatch → error 01.
pub struct CapArqcHandler;

struct CapFields {
    key_id: KeyDescriptor,
    pan: String,
    pan_seq: String,
    atc: String,
    unpredictable_number: Option<String>,
    txn_data: Zeroizing<String>,
    cryptogram: String,
}

fn parse_cap(payload: &[u8], is_k2: bool) -> Result<CapFields, ProxyError> {
    let cmd = if is_k2 { "K2" } else { "KS" };
    let mut pos = 0;

    // Key Type (3H ASCII) — consumed
    if payload.len() < pos + 3 {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: key type missing"
        )));
    }
    pos += 3;

    // Key (variable ASCII hex)
    let (key_id, key_consumed) = parse_legacy_key(payload, pos)?;
    pos += key_consumed;

    // PAN+Seq (8B binary BCD)
    if payload.len() < pos + 8 {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: PAN+seq field missing"
        )));
    }
    let pan_seq_bytes: [u8; 8] = payload[pos..pos + 8]
        .try_into()
        .expect("length checked above");
    let (pan, pan_seq) = decode_bcd_pan_seq(pan_seq_bytes);
    pos += 8;

    // ATC (2B binary)
    if payload.len() < pos + 2 {
        return Err(ProxyError::MalformedPayload(format!("{cmd}: ATC missing")));
    }
    let atc = bytes_to_hex(&payload[pos..pos + 2]);
    pos += 2;

    // UN (4B binary, K2 only)
    let unpredictable_number = if is_k2 {
        if payload.len() < pos + 4 {
            return Err(ProxyError::MalformedPayload("K2: UN missing".into()));
        }
        let un = bytes_to_hex(&payload[pos..pos + 4]);
        pos += 4;
        Some(un)
    } else {
        None
    };

    // TxnLen (2B binary big-endian)
    if payload.len() < pos + 2 {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: transaction data length missing"
        )));
    }
    let txn_byte_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    // TxnData
    if payload.len() < pos + txn_byte_len {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: transaction data too short: need {txn_byte_len} bytes"
        )));
    }
    let txn_data = Zeroizing::new(bytes_to_hex(&payload[pos..pos + txn_byte_len]));
    pos += txn_byte_len;

    // Delimiter 0x3B
    if payload.len() < pos + 1 || payload[pos] != 0x3B {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: missing 0x3B delimiter"
        )));
    }
    pos += 1;

    // Cryptogram (8B binary)
    if payload.len() < pos + 8 {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: cryptogram missing"
        )));
    }
    let cryptogram = bytes_to_hex(&payload[pos..pos + 8]);

    Ok(CapFields {
        key_id,
        pan,
        pan_seq,
        atc,
        unpredictable_number,
        txn_data,
        cryptogram,
    })
}

#[async_trait]
impl Handler for CapArqcHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["K2", "KS"]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"KS" => handle_cap(payload, false, state).await,
            _ => handle_cap(payload, true, state).await,
        }
    }
}

async fn handle_cap(payload: &[u8], is_k2: bool, state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_cap(payload, is_k2) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let key_arn = match state.key_map.resolve_descriptor(&fields.key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        MajorKeyDerivationMode, SessionKeyDerivation, SessionKeyEmv2000, SessionKeyMastercard,
    };

    let session_key_attrs = if is_k2 {
        let un = fields.unpredictable_number.as_deref().unwrap_or("");
        match SessionKeyMastercard::builder()
            .primary_account_number(&fields.pan)
            .pan_sequence_number(&fields.pan_seq)
            .application_transaction_counter(&fields.atc)
            .unpredictable_number(un)
            .build()
            .map_err(|e: aws_sdk_paymentcryptographydata::error::BuildError| {
                ProxyError::ApcError(e.to_string())
            }) {
            Ok(mc) => SessionKeyDerivation::Mastercard(mc),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        }
    } else {
        match SessionKeyEmv2000::builder()
            .primary_account_number(&fields.pan)
            .pan_sequence_number(&fields.pan_seq)
            .application_transaction_counter(&fields.atc)
            .build()
            .map_err(|e: aws_sdk_paymentcryptographydata::error::BuildError| {
                ProxyError::ApcError(e.to_string())
            }) {
            Ok(e2k) => SessionKeyDerivation::Emv2000(e2k),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        }
    };

    let deriv_mode = if is_k2 {
        MajorKeyDerivationMode::EmvOptionB
    } else {
        MajorKeyDerivationMode::EmvOptionA
    };

    debug!(
        key = %key_arn,
        cmd = if is_k2 { "K2" } else { "KS" },
        "verify_auth_request_cryptogram"
    );

    match state
        .data
        .verify_auth_request_cryptogram()
        .key_identifier(&key_arn)
        .transaction_data(fields.txn_data.as_str())
        .auth_request_cryptogram(&fields.cryptogram)
        .major_key_derivation_mode(deriv_mode)
        .session_key_derivation_attributes(session_key_attrs)
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error()
                .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_auth_request_cryptogram::VerifyAuthRequestCryptogramError::is_verification_failed_exception)
            {
                warn!(cmd = if is_k2 { "K2" } else { "KS" }, "cryptogram mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(
                ?e,
                cmd = if is_k2 { "K2" } else { "KS" },
                "verify_auth_request_cryptogram failed"
            );
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_key() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec()
    }

    // PAN: 123456789012, Seq: 01 → BCD: 12 34 56 78 90 12 | 01 FF
    fn pan_bcd() -> [u8; 8] {
        [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x01, 0xFF]
    }

    fn k2_payload(key: &[u8], txn: &[u8]) -> Vec<u8> {
        let mut v = b"00E".to_vec();
        v.extend_from_slice(key);
        v.extend_from_slice(&pan_bcd());
        v.extend_from_slice(&[0x00, 0x01]); // ATC 2B
        v.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // UN 4B
        let len = txn.len() as u16;
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(txn);
        v.push(0x3B);
        v.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]);
        v
    }

    fn ks_payload(key: &[u8], txn: &[u8]) -> Vec<u8> {
        let mut v = b"00E".to_vec();
        v.extend_from_slice(key);
        v.extend_from_slice(&pan_bcd());
        v.extend_from_slice(&[0x00, 0x01]); // ATC 2B (no UN)
        let len = txn.len() as u16;
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(txn);
        v.push(0x3B);
        v.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]);
        v
    }

    #[test]
    fn k2_parse_ok() {
        let payload = k2_payload(&single_key(), &[0xDE, 0xAD]);
        let f = parse_cap(&payload, true).unwrap();
        assert_eq!(f.key_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pan, "123456789012");
        assert_eq!(f.pan_seq, "01");
        assert_eq!(f.atc, "0001");
        assert_eq!(f.unpredictable_number, Some("DEADBEEF".to_string()));
        assert_eq!(f.txn_data.as_str(), "DEAD");
        assert_eq!(f.cryptogram, "AABBCCDDEEFF0011");
    }

    #[test]
    fn ks_parse_ok() {
        let payload = ks_payload(&single_key(), &[0xCA, 0xFE]);
        let f = parse_cap(&payload, false).unwrap();
        assert_eq!(f.key_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pan, "123456789012");
        assert_eq!(f.atc, "0001");
        assert!(f.unpredictable_number.is_none());
        assert_eq!(f.txn_data.as_str(), "CAFE");
        assert_eq!(f.cryptogram, "AABBCCDDEEFF0011");
    }

    #[test]
    fn k2_rejects_missing_un() {
        // Build a payload that stops before UN
        let mut v = b"00E".to_vec();
        v.extend_from_slice(&single_key());
        v.extend_from_slice(&pan_bcd());
        v.extend_from_slice(&[0x00, 0x01]); // ATC only — no UN
        assert!(matches!(
            parse_cap(&v, true),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn ks_rejects_missing_delimiter() {
        let mut payload = ks_payload(&single_key(), &[0xDE]);
        let delim_pos = payload.len() - 9;
        payload[delim_pos] = 0x00;
        assert!(matches!(
            parse_cap(&payload, false),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn k2_parse_double_key() {
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = k2_payload(&key, &[0xAB]);
        let f = parse_cap(&payload, true).unwrap();
        assert_eq!(f.key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
    }
}
