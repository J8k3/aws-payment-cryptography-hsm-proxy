use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_legacy_key;
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield Diebold PIN generation commands.
///
/// GA (→ GB) — Derive a PIN Using the Diebold Method.
/// CE (→ CF) — Generate a Diebold PIN Offset.
///
/// The Diebold PIN algorithm is structurally identical to IBM 3624 but uses a
/// configurable pad character (typically '0') rather than IBM's fixed 'F', and
/// specific validation data formats. APC's Ibm3624NaturalPin and Ibm3624PinOffset
/// cover both with the appropriate pad character.
///
/// GA field layout (PUGD0537-004 Rev A, p.213 — AUTHORITATIVE; field order
/// inferred from Diebold algorithm requirements and analogous IBM 3624 commands):
///   ZPK:             var   (parse_legacy_key; P0 key — encrypts output PIN block)
///   PDK:             var   (parse_legacy_key; V1 IBM3624 key — PIN derivation)
///   Account Number:  12N   rightmost 12 PAN digits excl. check digit
///   PIN Length:       1N   ASCII digit, length of derived PIN (4–12)
///   Decimalization:  16H   natural PIN decimalization table
///   Validation Data: 12A   selection data for PIN computation
///   Pad Character:    1A   padding character for validation data (Diebold: '0')
///
/// GB response:
///   [2H]  error code
///   [16H] derived PIN block encrypted under ZPK/PEK
///
/// KNOWN LIMITATION: payShield EE (IBM 3624 natural PIN) returns an additional
/// LMK-encrypted PIN block in the response that APC cannot produce. GA (Diebold)
/// is expected to omit this field because the Diebold workflow stores a PIN offset
/// (via CE) rather than an LMK-encrypted PIN. If a deployment's GB consumer expects
/// an LMK-encrypted field at a fixed offset, this handler will produce an incomplete
/// response. Verify against PUGD0537-004 p.213 GB response layout.
///
/// CE field layout (PUGD0537-004 Rev A, p.224 — AUTHORITATIVE; field order
/// inferred from Diebold algorithm requirements):
///   ZPK:             var   (parse_legacy_key; P0 key — decrypts customer PIN block)
///   PDK:             var   (parse_legacy_key; V1 IBM3624 key)
///   Account Number:  12N
///   Cust PIN Block:  16H   customer-selected PIN encrypted under ZPK
///   PIN Block Fmt:    2N   consumed (proxy hardcodes IsoFormat0)
///   Decimalization:  16H
///   Validation Data: 12A
///   Pad Character:    1A
///
/// CF response:
///   [2H]  error code
///   [12H] Diebold PIN offset (left-justified, F-padded to 12 chars)
pub struct DieboldPinHandler;

const ACCOUNT_LEN: usize = 12;
const PIN_LEN_FIELD: usize = 1;
const DECIM_TABLE_LEN: usize = 16;
const VAL_DATA_LEN: usize = 12;
const PAD_CHAR_LEN: usize = 1;
const PIN_BLOCK_LEN: usize = 16;
const PIN_FMT_LEN: usize = 2;

struct GaFields {
    zpk_id: KeyDescriptor,
    pdk_id: KeyDescriptor,
    account: String,
    pin_length: i32,
    decim_table: String,
    val_data: String,
    pad_char: String,
}

struct CeFields {
    zpk_id: KeyDescriptor,
    pdk_id: KeyDescriptor,
    account: String,
    cust_pin_block: Zeroizing<String>,
    decim_table: String,
    val_data: String,
    pad_char: String,
}

fn parse_ga(payload: &[u8]) -> Result<GaFields, ProxyError> {
    let mut pos = 0;

    let (zpk_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;
    let (pdk_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;

    let acct_end = pos + ACCOUNT_LEN;
    let pinlen_end = acct_end + PIN_LEN_FIELD;
    let decim_end = pinlen_end + DECIM_TABLE_LEN;
    let val_end = decim_end + VAL_DATA_LEN;
    let pad_end = val_end + PAD_CHAR_LEN;

    if payload.len() < pad_end {
        return Err(ProxyError::MalformedPayload(format!(
            "GA payload too short: {} < {}",
            payload.len(),
            pad_end
        )));
    }

    let pin_len_str = std::str::from_utf8(&payload[acct_end..pinlen_end])
        .map_err(|_| ProxyError::MalformedPayload("GA: PIN length not ASCII".into()))?;
    let pin_length = pin_len_str.parse::<i32>().map_err(|_| {
        ProxyError::MalformedPayload(format!("GA: invalid PIN length '{pin_len_str}'"))
    })?;
    if !(4..=12).contains(&pin_length) {
        return Err(ProxyError::MalformedPayload(format!(
            "GA: PIN length {pin_length} out of range (4–12)"
        )));
    }

    Ok(GaFields {
        zpk_id,
        pdk_id,
        account: String::from_utf8_lossy(&payload[pos..acct_end]).to_string(),
        pin_length,
        decim_table: String::from_utf8_lossy(&payload[pinlen_end..decim_end]).to_string(),
        val_data: String::from_utf8_lossy(&payload[decim_end..val_end]).to_string(),
        pad_char: String::from_utf8_lossy(&payload[val_end..pad_end]).to_string(),
    })
}

fn parse_ce(payload: &[u8]) -> Result<CeFields, ProxyError> {
    let mut pos = 0;

    let (zpk_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;
    let (pdk_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;

    let acct_end = pos + ACCOUNT_LEN;
    let pin_end = acct_end + PIN_BLOCK_LEN;
    let fmt_end = pin_end + PIN_FMT_LEN;
    let decim_end = fmt_end + DECIM_TABLE_LEN;
    let val_end = decim_end + VAL_DATA_LEN;
    let pad_end = val_end + PAD_CHAR_LEN;

    if payload.len() < pad_end {
        return Err(ProxyError::MalformedPayload(format!(
            "CE payload too short: {} < {}",
            payload.len(),
            pad_end
        )));
    }

    Ok(CeFields {
        zpk_id,
        pdk_id,
        account: String::from_utf8_lossy(&payload[pos..acct_end]).to_string(),
        cust_pin_block: Zeroizing::new(
            String::from_utf8_lossy(&payload[acct_end..pin_end]).to_string(),
        ),
        // PIN block format at pin_end..fmt_end consumed
        decim_table: String::from_utf8_lossy(&payload[fmt_end..decim_end]).to_string(),
        val_data: String::from_utf8_lossy(&payload[decim_end..val_end]).to_string(),
        pad_char: String::from_utf8_lossy(&payload[val_end..pad_end]).to_string(),
    })
}

#[async_trait]
impl Handler for DieboldPinHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["CE", "GA"]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"CE" => handle_ce(payload, state).await,
            _ => handle_ga(payload, state).await,
        }
    }
}

async fn handle_ga(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_ga(payload) {
        Ok(f) => f,
        Err(e) => {
            warn!(?e, "GA parse error");
            return HandlerResult::from_proxy_error(&e);
        }
    };

    let zpk_arn = match state.key_map.resolve_descriptor(&fields.zpk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pdk_arn = match state.key_map.resolve_descriptor(&fields.pdk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        Ibm3624NaturalPin, PinBlockFormatForPinData, PinGenerationAttributes,
    };

    let ibm_attrs = match Ibm3624NaturalPin::builder()
        .decimalization_table(&fields.decim_table)
        .pin_validation_data_pad_character(&fields.pad_char)
        .pin_validation_data(&fields.val_data)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(zpk = %zpk_arn, pdk = %pdk_arn, pin_len = fields.pin_length, "GA: generate_pin_data Diebold natural PIN");

    match state
        .data
        .generate_pin_data()
        .generation_key_identifier(&pdk_arn)
        .encryption_key_identifier(&zpk_arn)
        .generation_attributes(PinGenerationAttributes::Ibm3624NaturalPin(ibm_attrs))
        .pin_data_length(fields.pin_length)
        .primary_account_number(&fields.account)
        .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
        .send()
        .await
    {
        Ok(resp) => HandlerResult::success(resp.encrypted_pin_block().as_bytes().to_vec()),
        Err(e) => {
            warn!(?e, "GA: generate_pin_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_ce(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_ce(payload) {
        Ok(f) => f,
        Err(e) => {
            warn!(?e, "CE parse error");
            return HandlerResult::from_proxy_error(&e);
        }
    };

    let zpk_arn = match state.key_map.resolve_descriptor(&fields.zpk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pdk_arn = match state.key_map.resolve_descriptor(&fields.pdk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        Ibm3624PinOffset, PinBlockFormatForPinData, PinGenerationAttributes,
    };

    let ibm_attrs = match Ibm3624PinOffset::builder()
        .encrypted_pin_block(fields.cust_pin_block.as_str())
        .decimalization_table(&fields.decim_table)
        .pin_validation_data_pad_character(&fields.pad_char)
        .pin_validation_data(&fields.val_data)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(zpk = %zpk_arn, pdk = %pdk_arn, "CE: generate_pin_data Diebold offset");

    match state
        .data
        .generate_pin_data()
        .generation_key_identifier(&pdk_arn)
        .encryption_key_identifier(&zpk_arn)
        .generation_attributes(PinGenerationAttributes::Ibm3624PinOffset(ibm_attrs))
        .primary_account_number(&fields.account)
        .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
        .send()
        .await
    {
        Ok(resp) => {
            use aws_sdk_paymentcryptographydata::types::PinData;
            match resp.pin_data() {
                Some(PinData::PinOffset(offset)) => {
                    HandlerResult::success(offset.as_bytes().to_vec())
                }
                other => {
                    warn!(?other, "CE: unexpected pin_data variant");
                    HandlerResult::from_proxy_error(&ProxyError::ApcError(
                        "CE: generate_pin_data returned unexpected pin_data variant".into(),
                    ))
                }
            }
        }
        Err(e) => {
            warn!(?e, "CE: generate_pin_data failed");
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

    fn build_ga_payload(zpk: &[u8], pdk: &[u8]) -> Vec<u8> {
        let mut v = zpk.to_vec();
        v.extend_from_slice(pdk);
        v.extend_from_slice(b"123456789012"); // account 12N
        v.extend_from_slice(b"4"); // pin length
        v.extend_from_slice(b"0123456789012345"); // decim table 16H
        v.extend_from_slice(b"NNNNNNNNNNNN"); // val data 12A
        v.extend_from_slice(b"0"); // pad char
        v
    }

    fn build_ce_payload(zpk: &[u8], pdk: &[u8]) -> Vec<u8> {
        let mut v = zpk.to_vec();
        v.extend_from_slice(pdk);
        v.extend_from_slice(b"123456789012"); // account 12N
        v.extend_from_slice(b"1234567890ABCDEF"); // cust PIN block 16H
        v.extend_from_slice(b"01"); // pin block fmt
        v.extend_from_slice(b"0123456789012345"); // decim table 16H
        v.extend_from_slice(b"NNNNNNNNNNNN"); // val data 12A
        v.extend_from_slice(b"0"); // pad char
        v
    }

    #[test]
    fn ga_parse_single_keys() {
        let payload = build_ga_payload(&single_key(), &single_key());
        let f = parse_ga(&payload).unwrap();
        assert_eq!(f.zpk_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pdk_id.raw, "1234567890ABCDEF");
        assert_eq!(f.account, "123456789012");
        assert_eq!(f.pin_length, 4);
        assert_eq!(f.decim_table, "0123456789012345");
        assert_eq!(f.val_data, "NNNNNNNNNNNN");
        assert_eq!(f.pad_char, "0");
    }

    #[test]
    fn ga_parse_double_zpk() {
        let mut zpk = vec![b'U'];
        zpk.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = build_ga_payload(&zpk, &single_key());
        let f = parse_ga(&payload).unwrap();
        assert_eq!(f.zpk_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.pdk_id.raw, "1234567890ABCDEF");
    }

    #[test]
    fn ga_rejects_pin_length_out_of_range() {
        let mut payload = build_ga_payload(&single_key(), &single_key());
        // Pin length byte is at offset: 16 + 16 + 12 = 44
        let pin_len_pos = 16 + 16 + 12;
        payload[pin_len_pos] = b'3'; // 3 is below min 4
        assert!(matches!(
            parse_ga(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn ga_rejects_short_payload() {
        let payload = b"tooshort".to_vec();
        assert!(matches!(
            parse_ga(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn ce_parse_single_keys() {
        let payload = build_ce_payload(&single_key(), &single_key());
        let f = parse_ce(&payload).unwrap();
        assert_eq!(f.zpk_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pdk_id.raw, "1234567890ABCDEF");
        assert_eq!(f.account, "123456789012");
        assert_eq!(f.cust_pin_block.as_str(), "1234567890ABCDEF");
        assert_eq!(f.decim_table, "0123456789012345");
        assert_eq!(f.val_data, "NNNNNNNNNNNN");
        assert_eq!(f.pad_char, "0");
    }

    #[test]
    fn ce_parse_double_pdk() {
        let mut pdk = vec![b'U'];
        pdk.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = build_ce_payload(&single_key(), &pdk);
        let f = parse_ce(&payload).unwrap();
        assert_eq!(f.zpk_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pdk_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.cust_pin_block.as_str(), "1234567890ABCDEF");
    }

    #[test]
    fn ce_rejects_short_payload() {
        let payload = b"tooshort".to_vec();
        assert!(matches!(
            parse_ce(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }
}
