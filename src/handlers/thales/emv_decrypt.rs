use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{bytes_to_hex, decode_bcd_pan_seq, parse_legacy_key};
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield K0 — Decrypt EMV-encrypted counters / application data.
///
/// Decrypts data encrypted on-card using an EMV session key derived from an
/// IMK-ENC (E1 usage). Typical use: decrypting Application Unblock Data or
/// encrypted counters during EMV de-personalization.
///
/// K0 (→ K1) wire format per PUGD0537-004:
///   Key Type    3H ASCII    consumed (E1 — IMK-ENC)
///   Key         var         16H | 'U'+32H | 'T'+48H
///   PAN+Seq     8B binary   BCD — pre-formatted PAN‖PSN, EMV Option A (16 digits, left zero-pad)
///   ATC         2B binary   Application Transaction Counter
///   DataLen     2B binary   big-endian byte count of encrypted data
///   EncData     nB binary   ciphertext
///
/// K0 → APC decrypt_data with EncryptionDecryptionAttributes::Emv
///   major_key_derivation_mode = EmvOptionA
///   session_derivation_data   = ATC (4H) + "000000000000" (12 zero hex chars) = 16H
///   mode                      = Cbc
///
/// K1 response:
///   [2H] error code
///   [nH] decrypted plaintext hex
pub struct EmvDecryptHandler;

struct K0Fields {
    key_id: KeyDescriptor,
    pan: String,
    pan_seq: String,
    atc: String,
    cipher_text: Zeroizing<String>,
}

fn parse_k0(payload: &[u8]) -> Result<K0Fields, ProxyError> {
    let mut pos = 0;

    // Key Type (3H ASCII) — consumed
    if payload.len() < 3 {
        return Err(ProxyError::MalformedPayload("K0: key type missing".into()));
    }
    pos += 3;

    // Key (variable ASCII hex)
    let (key_id, key_consumed) = parse_legacy_key(payload, pos)?;
    pos += key_consumed;

    // PAN+Seq (8B binary BCD)
    if payload.len() < pos + 8 {
        return Err(ProxyError::MalformedPayload(
            "K0: PAN+seq field missing".into(),
        ));
    }
    let pan_seq_bytes: [u8; 8] = payload[pos..pos + 8]
        .try_into()
        .expect("length checked above");
    let (pan, pan_seq) = decode_bcd_pan_seq(pan_seq_bytes);
    pos += 8;

    // ATC (2B binary)
    if payload.len() < pos + 2 {
        return Err(ProxyError::MalformedPayload("K0: ATC missing".into()));
    }
    let atc = bytes_to_hex(&payload[pos..pos + 2]);
    pos += 2;

    // DataLen (2B binary big-endian)
    if payload.len() < pos + 2 {
        return Err(ProxyError::MalformedPayload(
            "K0: encrypted data length missing".into(),
        ));
    }
    let data_byte_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    // EncData (nB binary)
    if payload.len() < pos + data_byte_len {
        return Err(ProxyError::MalformedPayload(format!(
            "K0: ciphertext too short: need {data_byte_len} bytes"
        )));
    }
    let cipher_text = Zeroizing::new(bytes_to_hex(&payload[pos..pos + data_byte_len]));

    Ok(K0Fields {
        key_id,
        pan,
        pan_seq,
        atc,
        cipher_text,
    })
}

#[async_trait]
impl Handler for EmvDecryptHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["K0"]
    }

    async fn handle(
        &self,
        _command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        handle_k0(payload, state).await
    }
}

async fn handle_k0(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_k0(payload) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let key_arn = match state.key_map.resolve_descriptor(&fields.key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        EmvEncryptionAttributes, EmvEncryptionMode, EmvMajorKeyDerivationMode,
        EncryptionDecryptionAttributes,
    };

    // session_derivation_data: ATC (4 hex chars) padded to 8 bytes = ATC + 12 zero hex chars
    let session_derivation_data = format!("{}000000000000", fields.atc);

    let emv_attrs = match EmvEncryptionAttributes::builder()
        .major_key_derivation_mode(EmvMajorKeyDerivationMode::EmvOptionA)
        .primary_account_number(&fields.pan)
        .pan_sequence_number(&fields.pan_seq)
        .session_derivation_data(&session_derivation_data)
        .mode(EmvEncryptionMode::Cbc)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(key = %key_arn, "K0: decrypt_data EMV-CBC");

    match state
        .data
        .decrypt_data()
        .key_identifier(&key_arn)
        .cipher_text(fields.cipher_text.as_str())
        .decryption_attributes(EncryptionDecryptionAttributes::Emv(emv_attrs))
        .send()
        .await
    {
        Ok(resp) => HandlerResult {
            error_code: *b"00",
            payload: Zeroizing::new(resp.plain_text().as_bytes().to_vec()),
        },
        Err(e) => {
            warn!(?e, "K0: decrypt_data failed");
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

    // PAN 123456789012, Seq 01 → EMV Option A pre-format (rightmost-16(PAN‖PSN),
    // left zero-padded): "0012345678901201".
    fn pan_bcd() -> [u8; 8] {
        [0x00, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x01]
    }

    fn k0_payload(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut v = b"00E".to_vec(); // key type
        v.extend_from_slice(key);
        v.extend_from_slice(&pan_bcd());
        v.extend_from_slice(&[0x00, 0x2A]); // ATC = 0x002A
        let len = data.len() as u16;
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn k0_parse_ok() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01];
        let payload = k0_payload(&single_key(), &data);
        let f = parse_k0(&payload).unwrap();
        assert_eq!(f.key_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pan, "123456789012");
        assert_eq!(f.pan_seq, "01");
        assert_eq!(f.atc, "002A");
        assert_eq!(f.cipher_text.as_str(), "DEADBEEFCAFE0001");
    }

    #[test]
    fn k0_session_derivation_data() {
        let data = [0xAB, 0xCD];
        let payload = k0_payload(&single_key(), &data);
        let f = parse_k0(&payload).unwrap();
        // ATC 002A + 12 zero hex chars = 16 chars total
        let sdd = format!("{}000000000000", f.atc);
        assert_eq!(sdd, "002A000000000000");
        assert_eq!(sdd.len(), 16);
    }

    #[test]
    fn k0_parse_double_key() {
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = k0_payload(&key, &[0x01, 0x02]);
        let f = parse_k0(&payload).unwrap();
        assert_eq!(f.key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
    }

    #[test]
    fn k0_rejects_truncated_data() {
        let mut payload = k0_payload(&single_key(), &[0xDE, 0xAD]);
        // Corrupt the data length to claim 8 bytes but only 2 present
        let data_len_pos = 3 + 16 + 8 + 2; // key_type + single_key + pan_seq + atc
        payload[data_len_pos] = 0x00;
        payload[data_len_pos + 1] = 0x08;
        payload.truncate(data_len_pos + 2 + 2); // keep only 2 data bytes
        assert!(matches!(
            parse_k0(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }
}
