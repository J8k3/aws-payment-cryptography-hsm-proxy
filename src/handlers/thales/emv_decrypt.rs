use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{decode_bcd_pan_seq, parse_legacy_key};
use crate::handlers::thales::reader::FieldReader;
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield K0 — Decrypt EMV-encrypted counters / application data.
///
/// Decrypts data encrypted on-card using an EMV session key derived from an
/// IMK-ENC (E1 usage). Typical use: decrypting Application Unblock Data or
/// encrypted counters during EMV de-personalization.
///
/// K0 (→ K1) wire format per PUGD0537-004 Rev A p.490
/// ("Decrypt Encrypted Counters (EMV 4.x)"):
///   Key Type    3H ASCII    consumed (E1 — IMK-ENC)
///   Key         var         16H | 'U'+32H | 'T'+48H
///   PAN+Seq     8B binary   BCD — rightmost 16 of PAN||PSN, EMV Option A left-0-pad (last 2 digits = PSN)
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
///
/// Evidence for the wire layout and APC mapping: see `Handler::grounding()`.
pub struct EmvDecryptHandler;

struct K0Fields {
    key_id: KeyDescriptor,
    pan: String,
    pan_seq: String,
    atc: String,
    cipher_text: Zeroizing<String>,
}

fn parse_k0(payload: &[u8]) -> Result<K0Fields, ProxyError> {
    let mut r = FieldReader::new(payload, "K0");

    r.take(3, "key type")?; // Key Type (3H ASCII) — consumed
    let key_id = r.parse_with(parse_legacy_key)?; // Key (16H | U+32H | T+48H)

    // PAN+Seq (8B binary BCD)
    let (pan, pan_seq) = decode_bcd_pan_seq(r.take_array::<8>("PAN+seq")?);
    let atc = r.take_hex(2, "ATC")?;

    // Encrypted data: length (2B BE) then that many bytes.
    let data_byte_len = r.u16_be("encrypted data length")?;
    let cipher_text = Zeroizing::new(r.take_hex(data_byte_len, "encrypted data")?);

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

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision: "K0 decrypts EMV-encrypted counters / application data under an IMK-ENC (E1) \
                       master key. APC derives an EMV session key (Option A) from the master key + \
                       PAN/PSN + ATC, then CBC-decrypts. Wire PAN+Seq is 8B BCD (Option-A \
                       pre-format); ATC and DataLen are 2B binary; ciphertext is binary and \
                       hex-encoded before the APC call. SessionDerivationData = ATC(4H) + 12 zero \
                       hex chars.",
            because: "PUGD0537-004 Rev A p.490. Verified live via round-trip: APC encrypt_data (EMV-CBC, built \
                      from the same field values) mints the ciphertext, and the proxy's K0 recovers \
                      the original plaintext across randomized PAN/PSN/ATC and 1..4 cipher blocks. \
                      A wrong PAN/PSN/ATC offset derives a different session key, so the round-trip \
                      would not close.",
            wire: WireGrounding::DiffXprov,
            crypto: CryptoGrounding::Apc,
            proof: Proof::LiveTest("emv_decrypt_k0_differential"),
        }]
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

    // EMV pre-formatted (rightmost 16 of PAN||PSN) "1234567890123401" -> PAN 12345678901234, Seq 01
    fn pan_bcd() -> [u8; 8] {
        [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x01]
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
        assert_eq!(f.pan, "12345678901234");
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
