use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_legacy_key;
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield JA (→ JB) — Generate a Random PIN.
///
/// Generates a random PIN of the requested length using the IBM 3624 algorithm,
/// returns it encrypted under the ZPK and also returns the IBM PIN offset so the
/// issuer can store it for later verification (via DA/EA).
///
/// Wire layout (International API; field order inferred from analogous IBM 3624
/// commands — GA, DE, EE — and confirmed by KB note "PAN (12N), PIN length (2N)"):
///   ZPK:         var   (parse_legacy_key; P0 — encrypts output PIN block)
///   PVK:         var   (parse_legacy_key; V1 IBM3624 — offset computation)
///   PIN Length:  2N    ASCII decimal "04"–"12"
///   Account:    12N    rightmost 12 PAN digits excl. check digit
///   Decim:      16H    IBM 3624 decimalization table
///   Val Data:   12A    PIN validation data
///   Pad Char:    1A    padding character (IBM standard: 'F')
///
/// JB response (proxy):
///   [16H] PIN block encrypted under ZPK  (from encrypted_pin_block)
///   [12H] IBM PIN offset                 (from pin_data PinOffset)
///
/// KNOWN LIMITATION: payShield JB also returns an LMK-encrypted PIN block as
/// the first data field. APC has no LMK concept — that field is omitted.
/// Consumers that address JB fields by fixed byte offset will see a shifted
/// response; consumers that parse by field semantics are unaffected.
pub struct RandomPinHandler;

const PIN_LEN_FIELD: usize = 2;
const ACCOUNT_LEN: usize = 12;
const DECIM_TABLE_LEN: usize = 16;
const VAL_DATA_LEN: usize = 12;
const PAD_CHAR_LEN: usize = 1;
const IBM_OFFSET_LEN: usize = 12;

struct JaFields {
    zpk_id: KeyDescriptor,
    pvk_id: KeyDescriptor,
    pin_length: i32,
    account: String,
    decim_table: String,
    val_data: String,
    pad_char: String,
}

fn parse_ja(payload: &[u8]) -> Result<JaFields, ProxyError> {
    let mut pos = 0;

    let (zpk_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;
    let (pvk_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;

    let pinlen_end = pos + PIN_LEN_FIELD;
    let acct_end = pinlen_end + ACCOUNT_LEN;
    let decim_end = acct_end + DECIM_TABLE_LEN;
    let val_end = decim_end + VAL_DATA_LEN;
    let pad_end = val_end + PAD_CHAR_LEN;

    if payload.len() < pad_end {
        return Err(ProxyError::MalformedPayload(format!(
            "JA payload too short: {} < {}",
            payload.len(),
            pad_end
        )));
    }

    let pin_len_str = std::str::from_utf8(&payload[pos..pinlen_end])
        .map_err(|_| ProxyError::MalformedPayload("JA: PIN length not ASCII".into()))?;
    let pin_length = pin_len_str.parse::<i32>().map_err(|_| {
        ProxyError::MalformedPayload(format!("JA: invalid PIN length '{pin_len_str}'"))
    })?;
    if !(4..=12).contains(&pin_length) {
        return Err(ProxyError::MalformedPayload(format!(
            "JA: PIN length {pin_length} out of range (4–12)"
        )));
    }

    Ok(JaFields {
        zpk_id,
        pvk_id,
        pin_length,
        account: String::from_utf8_lossy(&payload[pinlen_end..acct_end]).to_string(),
        decim_table: String::from_utf8_lossy(&payload[acct_end..decim_end]).to_string(),
        val_data: String::from_utf8_lossy(&payload[decim_end..val_end]).to_string(),
        pad_char: String::from_utf8_lossy(&payload[val_end..pad_end]).to_string(),
    })
}

#[async_trait]
impl Handler for RandomPinHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["JA"]
    }

    async fn handle(
        &self,
        _command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        let fields = match parse_ja(payload) {
            Ok(f) => f,
            Err(e) => {
                warn!(?e, "JA parse error");
                return HandlerResult::from_proxy_error(&e);
            }
        };

        let zpk_arn = match state.key_map.resolve_descriptor(&fields.zpk_id) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };
        let pvk_arn = match state.key_map.resolve_descriptor(&fields.pvk_id) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };

        use aws_sdk_paymentcryptographydata::types::{
            Ibm3624RandomPin, PinBlockFormatForPinData, PinData, PinGenerationAttributes,
        };

        let ibm_attrs = match Ibm3624RandomPin::builder()
            .decimalization_table(&fields.decim_table)
            .pin_validation_data_pad_character(&fields.pad_char)
            .pin_validation_data(&fields.val_data)
            .build()
            .map_err(|e| ProxyError::ApcError(e.to_string()))
        {
            Ok(a) => a,
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };

        debug!(
            zpk = %zpk_arn,
            pvk = %pvk_arn,
            pin_len = fields.pin_length,
            "JA: generate_pin_data random IBM3624"
        );

        match state
            .data
            .generate_pin_data()
            .generation_key_identifier(&pvk_arn)
            .encryption_key_identifier(&zpk_arn)
            .generation_attributes(PinGenerationAttributes::Ibm3624RandomPin(ibm_attrs))
            .pin_data_length(fields.pin_length)
            .primary_account_number(&fields.account)
            .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
            .send()
            .await
        {
            Ok(resp) => {
                let pin_block = resp.encrypted_pin_block().as_bytes();
                let offset = match resp.pin_data() {
                    Some(PinData::PinOffset(o)) => o.as_bytes().to_vec(),
                    other => {
                        warn!(?other, "JA: unexpected pin_data variant");
                        return HandlerResult::from_proxy_error(&ProxyError::ApcError(
                            "JA: generate_pin_data returned unexpected pin_data variant".into(),
                        ));
                    }
                };
                // JB: 16H encrypted PIN block + 12H IBM offset
                // (LMK-encrypted block omitted — APC has no LMK)
                let mut out = Vec::with_capacity(pin_block.len() + IBM_OFFSET_LEN);
                out.extend_from_slice(pin_block);
                out.extend_from_slice(&offset);
                HandlerResult::success(out)
            }
            Err(e) => {
                warn!(?e, "JA: generate_pin_data failed");
                HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_key() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec()
    }

    fn build_ja_payload(zpk: &[u8], pvk: &[u8], pin_len: &[u8]) -> Vec<u8> {
        let mut v = zpk.to_vec();
        v.extend_from_slice(pvk);
        v.extend_from_slice(pin_len); // PIN length 2N
        v.extend_from_slice(b"123456789012"); // account 12N
        v.extend_from_slice(b"0123456789012345"); // decim table 16H
        v.extend_from_slice(b"NNNNNNNNNNNN"); // val data 12A
        v.extend_from_slice(b"F"); // pad char
        v
    }

    #[test]
    fn ja_parse_single_keys() {
        let payload = build_ja_payload(&single_key(), &single_key(), b"06");
        let f = parse_ja(&payload).unwrap();
        assert_eq!(f.zpk_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pvk_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pin_length, 6);
        assert_eq!(f.account, "123456789012");
        assert_eq!(f.decim_table, "0123456789012345");
        assert_eq!(f.val_data, "NNNNNNNNNNNN");
        assert_eq!(f.pad_char, "F");
    }

    #[test]
    fn ja_parse_double_length_zpk() {
        let mut zpk = vec![b'U'];
        zpk.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = build_ja_payload(&zpk, &single_key(), b"04");
        let f = parse_ja(&payload).unwrap();
        assert_eq!(f.zpk_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.pvk_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pin_length, 4);
    }

    #[test]
    fn ja_parse_min_and_max_lengths() {
        let payload_min = build_ja_payload(&single_key(), &single_key(), b"04");
        assert_eq!(parse_ja(&payload_min).unwrap().pin_length, 4);

        let payload_max = build_ja_payload(&single_key(), &single_key(), b"12");
        assert_eq!(parse_ja(&payload_max).unwrap().pin_length, 12);
    }

    #[test]
    fn ja_rejects_pin_length_too_short() {
        let payload = build_ja_payload(&single_key(), &single_key(), b"03");
        assert!(matches!(
            parse_ja(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn ja_rejects_pin_length_too_long() {
        let payload = build_ja_payload(&single_key(), &single_key(), b"13");
        assert!(matches!(
            parse_ja(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn ja_rejects_short_payload() {
        assert!(matches!(
            parse_ja(b"tooshort"),
            Err(ProxyError::MalformedPayload(_))
        ));
    }
}
