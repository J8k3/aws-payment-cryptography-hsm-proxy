use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{map_pin_block_format, parse_key_32, parse_legacy_key};
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield non-DUKPT PIN verification: DA/DC (TPK) and EA/EC (ZPK).
///
/// DA — Verify Terminal PIN Block, IBM 3624 method  (TPK; p.269)
/// DC — Verify Terminal PIN Block, Visa PVV method  (TPK; p.277)
/// EA — Verify PIN, IBM 3624 method                 (ZPK; p.279)
/// EC — Verify PIN, Visa PVV method                 (ZPK; p.281)
///
/// All four map to APC verify_pin_data without dukpt_attributes.
/// TPK and ZPK both become the encryption_key_identifier (P0 key type).
///
/// DA/EA field layout (PUGD0537-004 p.269/279):
///   Enc Key (TPK/ZPK):  16H | 'U'+32H | 'T'+48H  (parse_legacy_key)
///   PVK:                16H | 'U'+32H | 'T'+48H  (parse_legacy_key; IBM single-length)
///   Max PIN Length:     2N  consumed
///   Min PIN Length:     2N  consumed
///   PIN Block:         16H
///   PIN Block Format:   2N  consumed (proxy hardcodes IsoFormat0)
///   Account Number:    12N  rightmost 12 PAN digits excl. check digit
///   Decimalization Table: 16H
///   PIN Validation Data:  12A
///   Offset:            12H  IBM PIN offset, left-justified, F-padded
///
/// DC/EC field layout (PUGD0537-004 p.277/281):
///   Enc Key (TPK/ZPK):  16H | 'U'+32H | 'T'+48H  (parse_legacy_key)
///   PVK-Pair:           32H | 'U'+32H | 'T'+48H  (parse_key_32; Visa double-length)
///   Max PIN Length:     2N  consumed
///   Min PIN Length:     2N  consumed
///   PIN Block:         16H
///   PIN Block Format:   2N  consumed
///   Account Number:    12N
///   PVKI:               1N  PIN Verification Key Indicator
///   PVV:                4N  PIN Verification Value from card/database
pub struct PinVerifyNonDukptHandler;

const MAX_PIN_LEN_FIELD: usize = 2;
const MIN_PIN_LEN_FIELD: usize = 2;
const PIN_BLOCK_LEN: usize = 16;
const PIN_FMT_FIELD: usize = 2;
const ACCOUNT_LEN: usize = 12;
const DECIM_TABLE_LEN: usize = 16;
const PIN_VAL_DATA_LEN: usize = 12;
const IBM_OFFSET_LEN: usize = 12;
const PVKI_LEN: usize = 1;
const PVV_LEN: usize = 4;

struct IbmFields {
    enc_key_id: KeyDescriptor,
    pvk_id: KeyDescriptor,
    pin_block: Zeroizing<String>,
    pin_block_format: String,
    account: String,
    decim_table: String,
    pin_val_data: String,
    offset: String,
}

struct VisaFields {
    enc_key_id: KeyDescriptor,
    pvk_id: KeyDescriptor,
    pin_block: Zeroizing<String>,
    pin_block_format: String,
    account: String,
    pvki: i32,
    pvv: String,
}

fn parse_ibm(payload: &[u8]) -> Result<IbmFields, ProxyError> {
    let mut pos = 0;

    let (enc_key_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;
    let (pvk_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;

    pos += MAX_PIN_LEN_FIELD + MIN_PIN_LEN_FIELD;

    let pin_end = pos + PIN_BLOCK_LEN;
    let fmt_end = pin_end + PIN_FMT_FIELD;
    let acct_end = fmt_end + ACCOUNT_LEN;
    let decim_end = acct_end + DECIM_TABLE_LEN;
    let pvdata_end = decim_end + PIN_VAL_DATA_LEN;
    let offset_end = pvdata_end + IBM_OFFSET_LEN;

    if payload.len() < offset_end {
        return Err(ProxyError::MalformedPayload(format!(
            "DA/EA payload too short: {} < {}",
            payload.len(),
            offset_end
        )));
    }

    Ok(IbmFields {
        enc_key_id,
        pvk_id,
        pin_block: Zeroizing::new(String::from_utf8_lossy(&payload[pos..pin_end]).to_string()),
        pin_block_format: String::from_utf8_lossy(&payload[pin_end..fmt_end]).to_string(),
        account: String::from_utf8_lossy(&payload[fmt_end..acct_end]).to_string(),
        decim_table: String::from_utf8_lossy(&payload[acct_end..decim_end]).to_string(),
        pin_val_data: String::from_utf8_lossy(&payload[decim_end..pvdata_end]).to_string(),
        offset: String::from_utf8_lossy(&payload[pvdata_end..offset_end]).to_string(),
    })
}

fn parse_visa(payload: &[u8]) -> Result<VisaFields, ProxyError> {
    let mut pos = 0;

    let (enc_key_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;
    let (pvk_id, n) = parse_key_32(payload, pos)?;
    pos += n;

    pos += MAX_PIN_LEN_FIELD + MIN_PIN_LEN_FIELD;

    let pin_end = pos + PIN_BLOCK_LEN;
    let fmt_end = pin_end + PIN_FMT_FIELD;
    let acct_end = fmt_end + ACCOUNT_LEN;
    let pvki_end = acct_end + PVKI_LEN;
    let pvv_end = pvki_end + PVV_LEN;

    if payload.len() < pvv_end {
        return Err(ProxyError::MalformedPayload(format!(
            "DC/EC payload too short: {} < {}",
            payload.len(),
            pvv_end
        )));
    }

    let pvki_str = std::str::from_utf8(&payload[acct_end..pvki_end])
        .map_err(|_| ProxyError::MalformedPayload("DC/EC: PVKI not ASCII".into()))?;
    let pvki = pvki_str
        .parse::<i32>()
        .map_err(|_| ProxyError::MalformedPayload(format!("DC/EC: invalid PVKI '{pvki_str}'")))?;

    Ok(VisaFields {
        enc_key_id,
        pvk_id,
        pin_block: Zeroizing::new(String::from_utf8_lossy(&payload[pos..pin_end]).to_string()),
        pin_block_format: String::from_utf8_lossy(&payload[pin_end..fmt_end]).to_string(),
        account: String::from_utf8_lossy(&payload[fmt_end..acct_end]).to_string(),
        pvki,
        pvv: String::from_utf8_lossy(&payload[pvki_end..pvv_end]).to_string(),
    })
}

#[async_trait]
impl Handler for PinVerifyNonDukptHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["DA", "DC", "EA", "EC"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision: "DA/EA verify an IBM 3624 PIN and DC/EC a Visa PVV, all via APC \
                           verify_pin_data with no DUKPT. DA/DC carry a TPK and EA/EC a ZPK; both \
                           are P0 encryption keys in APC, so each pair shares one code path. The \
                           IBM 12H offset is F-padded on the wire and trimmed to APC's ^[0-9]+$ \
                           before the call (same handling as GO/CK).",
            because: "PUGD0537-004 p.269/277/279/281. Verified live: the proxy's verify verdict \
                          matches a direct APC verify_pin_data verdict across randomized PAN, both \
                          methods, and all four command codes. A valid PIN is minted via \
                          generate_pin_data (IBM3624 natural PIN offset 0, or Visa PVV read back \
                          from PinData::VerificationValue); a wrong field offset would feed APC a \
                          different block, which it rejects, so proxy and oracle verdicts diverge.",
            wire: WireGrounding::DiffXprov,
            crypto: CryptoGrounding::Apc,
            proof: Proof::LiveTest("pin_verify_non_dukpt_differential"),
        }]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"DA" | b"EA" => handle_ibm(payload, state).await,
            b"DC" | b"EC" => handle_visa(payload, state).await,
            _ => HandlerResult::err(*b"68"),
        }
    }
}

async fn handle_ibm(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_ibm(payload) {
        Ok(f) => f,
        Err(e) => {
            warn!(?e, "DA/EA parse error");
            return HandlerResult::from_proxy_error(&e);
        }
    };

    let enc_arn = match state.key_map.resolve_descriptor(&fields.enc_key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pvk_arn = match state.key_map.resolve_descriptor(&fields.pvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        Ibm3624PinVerification, PinVerificationAttributes,
    };

    // payShield left-justifies the offset and right-pads with 'F' to 12H.
    // APC requires only the significant decimal digits (^[0-9]+$), no F padding.
    let offset_trimmed = fields.offset.trim_end_matches('F').to_string();

    let ibm_attrs = match Ibm3624PinVerification::builder()
        .decimalization_table(&fields.decim_table)
        .pin_validation_data_pad_character("F")
        .pin_validation_data(&fields.pin_val_data)
        .pin_offset(&offset_trimmed)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let pin_format = match map_pin_block_format(&fields.pin_block_format) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(enc = %enc_arn, pvk = %pvk_arn, "DA/EA: verify_pin_data IBM3624");

    match state
        .data
        .verify_pin_data()
        .encryption_key_identifier(&enc_arn)
        .verification_key_identifier(&pvk_arn)
        .encrypted_pin_block(fields.pin_block.as_str())
        .primary_account_number(&fields.account)
        .pin_block_format(pin_format)
        .verification_attributes(PinVerificationAttributes::Ibm3624Pin(ibm_attrs))
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error()
                .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_pin_data::VerifyPinDataError::is_verification_failed_exception)
            {
                warn!("DA/EA: PIN mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "DA/EA: verify_pin_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_visa(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_visa(payload) {
        Ok(f) => f,
        Err(e) => {
            warn!(?e, "DC/EC parse error");
            return HandlerResult::from_proxy_error(&e);
        }
    };

    let enc_arn = match state.key_map.resolve_descriptor(&fields.enc_key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pvk_arn = match state.key_map.resolve_descriptor(&fields.pvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{PinVerificationAttributes, VisaPinVerification};

    let visa_attrs = match VisaPinVerification::builder()
        .pin_verification_key_index(fields.pvki)
        .verification_value(&fields.pvv)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let pin_format = match map_pin_block_format(&fields.pin_block_format) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(enc = %enc_arn, pvk = %pvk_arn, pvki = fields.pvki, "DC/EC: verify_pin_data VisaPVV");

    match state
        .data
        .verify_pin_data()
        .encryption_key_identifier(&enc_arn)
        .verification_key_identifier(&pvk_arn)
        .encrypted_pin_block(fields.pin_block.as_str())
        .primary_account_number(&fields.account)
        .pin_block_format(pin_format)
        .verification_attributes(PinVerificationAttributes::VisaPin(visa_attrs))
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error()
                .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_pin_data::VerifyPinDataError::is_verification_failed_exception)
            {
                warn!("DC/EC: PIN mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "DC/EC: verify_pin_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_key() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec() // 16H
    }

    fn double_key() -> Vec<u8> {
        b"1234567890ABCDEF1234567890ABCDEF".to_vec() // 32H
    }

    fn build_ibm_payload(enc_key: &[u8], pvk: &[u8]) -> Vec<u8> {
        let mut v = enc_key.to_vec();
        v.extend_from_slice(pvk);
        v.extend_from_slice(b"04"); // max pin len
        v.extend_from_slice(b"04"); // min pin len
        v.extend_from_slice(b"1234567890ABCDEF"); // PIN block 16H
        v.extend_from_slice(b"01"); // pin block format
        v.extend_from_slice(b"123456789012"); // account 12N
        v.extend_from_slice(b"1234567890123456"); // decim table 16H
        v.extend_from_slice(b"NNNNNNNNNNNN"); // pin val data 12A
        v.extend_from_slice(b"123456FFFFFF"); // offset 12H
        v
    }

    fn build_visa_payload(enc_key: &[u8], pvk: &[u8]) -> Vec<u8> {
        let mut v = enc_key.to_vec();
        v.extend_from_slice(pvk);
        v.extend_from_slice(b"04"); // max pin len
        v.extend_from_slice(b"04"); // min pin len
        v.extend_from_slice(b"1234567890ABCDEF"); // PIN block 16H
        v.extend_from_slice(b"01"); // pin block format
        v.extend_from_slice(b"123456789012"); // account 12N
        v.extend_from_slice(b"1"); // PVKI
        v.extend_from_slice(b"1234"); // PVV 4N
        v
    }

    #[test]
    fn da_parse_single_keys() {
        let payload = build_ibm_payload(&single_key(), &single_key());
        let f = parse_ibm(&payload).unwrap();
        assert_eq!(f.enc_key_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pvk_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pin_block_format, "01"); // mapped to APC IsoFormat0
        assert_eq!(f.account, "123456789012");
        assert_eq!(f.decim_table, "1234567890123456");
        assert_eq!(f.pin_val_data, "NNNNNNNNNNNN");
        assert_eq!(f.offset, "123456FFFFFF");
    }

    #[test]
    fn da_parse_double_enc_key() {
        // parse_legacy_key requires 'U' prefix for double-length keys
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = build_ibm_payload(&key, &single_key());
        let f = parse_ibm(&payload).unwrap();
        assert_eq!(f.enc_key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.pvk_id.raw, "1234567890ABCDEF");
    }

    #[test]
    fn dc_parse_single_enc_double_pvk() {
        let payload = build_visa_payload(&single_key(), &double_key());
        let f = parse_visa(&payload).unwrap();
        assert_eq!(f.enc_key_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pvk_id.raw, "1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.account, "123456789012");
        assert_eq!(f.pvki, 1);
        assert_eq!(f.pvv, "1234");
    }

    #[test]
    fn dc_parse_u_prefix_pvk() {
        let mut pvk = vec![b'U'];
        pvk.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = build_visa_payload(&single_key(), &pvk);
        let f = parse_visa(&payload).unwrap();
        assert_eq!(f.pvk_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
    }

    #[test]
    fn ibm_rejects_short_payload() {
        let payload = b"tooshort".to_vec();
        assert!(matches!(
            parse_ibm(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn visa_rejects_short_payload() {
        let payload = b"tooshort".to_vec();
        assert!(matches!(
            parse_visa(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }
}
