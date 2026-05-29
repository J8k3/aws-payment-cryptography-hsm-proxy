use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{
    parse_bdk, parse_key_32, parse_ksn_with_descriptor, parse_legacy_key,
};
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield 3DES & AES DUKPT PIN verification (PUGD0537-004 p.349/352/355/358).
///
/// GO — Verify PIN, IBM 3624 method  → APC verify_pin_data (Ibm3624PinVerification)
/// GQ — Verify PIN, Visa PVV method  → APC verify_pin_data (VisaPinVerification)
/// GS — Verify PIN, Diebold method   → 68 (Diebold table in HSM user storage)
/// GU — Verify PIN, Encrypted PIN    → 68 (LMK reference PIN, no APC equivalent)
///
/// Both 3DES (X9.24-1) and AES (X9.24-3) DUKPT are supported. The derivation
/// type is read from the KSN descriptor: 20H KSN → Tdes2Key, 24H KSN → Aes128.
///
/// GO field layout (p.349):
///   BDK:             32H | 'U'+32H  (AES-128 BDK is also 32H — same width as 3DES)
///   PVK:             16H | 'U'+32H | 'T'+48H  (IBM single-length baseline)
///   KSN Descriptor + KSN: parse_ksn_with_descriptor (3H + 20H or 24H)
///   PIN Block:       16H
///   Check Length:     2N  consumed
///   Account Number:  12N
///   Decimalization Table: 16H
///   PIN Validation Data:  12A
///   Offset:          12H  IBM PIN offset, left-justified, F-padded
///
/// GQ field layout (p.352):
///   BDK:             32H | 'U'+32H
///   PVK-Pair:        32H | 'U'+32H | 'T'+48H  (Visa double-length baseline)
///   KSN Descriptor + KSN: parse_ksn_with_descriptor
///   PIN Block:       16H
///   Account Number:  12N
///   PVKI:             1N
///   PVV:              4N
pub struct DukptPinVerifyAesHandler;

const PIN_BLOCK_LEN: usize = 16;
const CHECK_LEN: usize = 2;
const ACCOUNT_LEN: usize = 12;
const DECIM_TABLE_LEN: usize = 16;
const PIN_VAL_DATA_LEN: usize = 12;
const IBM_OFFSET_LEN: usize = 12;
const PVKI_LEN: usize = 1;
const PVV_LEN: usize = 4;

struct GoFields {
    bdk_id: String,
    pvk_id: String,
    deriv_type: aws_sdk_paymentcryptographydata::types::DukptDerivationType,
    ksn: String,
    pin_block: Zeroizing<String>,
    account: String,
    decim_table: String,
    pin_val_data: String,
    offset: String,
}

struct GqFields {
    bdk_id: String,
    pvk_id: String,
    deriv_type: aws_sdk_paymentcryptographydata::types::DukptDerivationType,
    ksn: String,
    pin_block: Zeroizing<String>,
    account: String,
    pvki: i32,
    pvv: String,
}

fn parse_go(payload: &[u8]) -> Result<GoFields, ProxyError> {
    let (bdk_id, bdk_len) = parse_bdk(payload, 0)?;
    let (pvk_id, pvk_len) = parse_legacy_key(payload, bdk_len)?;

    let ksn_offset = bdk_len + pvk_len;
    let (ksn, ksn_consumed, deriv_type) = parse_ksn_with_descriptor(payload, ksn_offset)?;

    let pin_start = ksn_offset + ksn_consumed;
    let check_start = pin_start + PIN_BLOCK_LEN;
    let account_start = check_start + CHECK_LEN;
    let decim_start = account_start + ACCOUNT_LEN;

    if let Some(&b'K' | &b'L') = payload.get(decim_start) {
        warn!("GO: user-storage/AES-encrypted decimalization table not supported");
        return Err(ProxyError::MalformedPayload(
            "GO: K/L prefix decim table not supported".into(),
        ));
    }

    let pin_val_start = decim_start + DECIM_TABLE_LEN;

    if payload.get(pin_val_start) == Some(&b'P') {
        warn!("GO: 'P'-prefix PIN validation data (16H) not supported");
        return Err(ProxyError::MalformedPayload(
            "GO: P-prefix PIN validation data not supported".into(),
        ));
    }

    let offset_start = pin_val_start + PIN_VAL_DATA_LEN;
    let min_len = offset_start + IBM_OFFSET_LEN;

    if payload.len() < min_len {
        return Err(ProxyError::MalformedPayload(format!(
            "GO payload too short: {} < {}",
            payload.len(),
            min_len
        )));
    }

    Ok(GoFields {
        bdk_id,
        pvk_id,
        deriv_type,
        ksn,
        pin_block: Zeroizing::new(
            String::from_utf8_lossy(&payload[pin_start..pin_start + PIN_BLOCK_LEN]).to_string(),
        ),
        account: String::from_utf8_lossy(&payload[account_start..account_start + ACCOUNT_LEN])
            .to_string(),
        decim_table: String::from_utf8_lossy(&payload[decim_start..decim_start + DECIM_TABLE_LEN])
            .to_string(),
        pin_val_data: String::from_utf8_lossy(
            &payload[pin_val_start..pin_val_start + PIN_VAL_DATA_LEN],
        )
        .to_string(),
        offset: String::from_utf8_lossy(&payload[offset_start..offset_start + IBM_OFFSET_LEN])
            .to_string(),
    })
}

fn parse_gq(payload: &[u8]) -> Result<GqFields, ProxyError> {
    let (bdk_id, bdk_len) = parse_bdk(payload, 0)?;
    let (pvk_id, pvk_len) = parse_key_32(payload, bdk_len)?;

    let ksn_offset = bdk_len + pvk_len;
    let (ksn, ksn_consumed, deriv_type) = parse_ksn_with_descriptor(payload, ksn_offset)?;

    let pin_start = ksn_offset + ksn_consumed;
    let pan_start = pin_start + PIN_BLOCK_LEN;
    let pvki_start = pan_start + ACCOUNT_LEN;
    let pvv_start = pvki_start + PVKI_LEN;
    let min_len = pvv_start + PVV_LEN;

    if payload.len() < min_len {
        return Err(ProxyError::MalformedPayload(format!(
            "GQ payload too short: {} < {}",
            payload.len(),
            min_len
        )));
    }

    if payload.get(pvki_start) == Some(&b';') {
        warn!("GQ: Token mode (';' delimiter) not supported");
        return Err(ProxyError::MalformedPayload(
            "GQ: token mode not supported".into(),
        ));
    }

    let pvki_str = std::str::from_utf8(&payload[pvki_start..=pvki_start])
        .map_err(|_| ProxyError::MalformedPayload("GQ: PVKI not ASCII".into()))?;
    let pvki = pvki_str
        .parse::<i32>()
        .map_err(|_| ProxyError::MalformedPayload(format!("GQ: invalid PVKI '{pvki_str}'")))?;

    Ok(GqFields {
        bdk_id,
        pvk_id,
        deriv_type,
        ksn,
        pin_block: Zeroizing::new(
            String::from_utf8_lossy(&payload[pin_start..pin_start + PIN_BLOCK_LEN]).to_string(),
        ),
        account: String::from_utf8_lossy(&payload[pan_start..pan_start + ACCOUNT_LEN]).to_string(),
        pvki,
        pvv: String::from_utf8_lossy(&payload[pvv_start..pvv_start + PVV_LEN]).to_string(),
    })
}

#[async_trait]
impl Handler for DukptPinVerifyAesHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["GO", "GQ", "GS", "GU"]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"GO" => handle_go(payload, state).await,
            b"GQ" => handle_gq(payload, state).await,
            b"GS" | b"GU" => {
                warn!(cmd = %String::from_utf8_lossy(command_code), "no APC equivalent; returning 68");
                HandlerResult::err(*b"68")
            }
            _ => HandlerResult::err(*b"68"),
        }
    }
}

async fn handle_go(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_go(payload) {
        Ok(f) => f,
        Err(e) => {
            warn!(?e, "GO parse error");
            return HandlerResult::from_proxy_error(&e);
        }
    };

    let bdk_arn = match state.key_map.resolve(&fields.bdk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pvk_arn = match state.key_map.resolve(&fields.pvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        DukptAttributes, Ibm3624PinVerification, PinBlockFormatForPinData,
        PinVerificationAttributes,
    };

    let dukpt_attrs = match DukptAttributes::builder()
        .key_serial_number(&fields.ksn)
        .dukpt_derivation_type(fields.deriv_type)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let ibm_attrs = match Ibm3624PinVerification::builder()
        .decimalization_table(&fields.decim_table)
        .pin_validation_data_pad_character("F")
        .pin_validation_data(&fields.pin_val_data)
        .pin_offset(&fields.offset)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(bdk = %bdk_arn, pvk = %pvk_arn, ksn_len = fields.ksn.len(), "GO: verify_pin_data IBM3624 DUKPT");

    match state
        .data
        .verify_pin_data()
        .verification_key_identifier(&pvk_arn)
        .encryption_key_identifier(&bdk_arn)
        .encrypted_pin_block(fields.pin_block.as_str())
        .primary_account_number(&fields.account)
        // KNOWN GAP: the 2N PIN block format field is consumed rather than forwarded. APC supports
        // IsoFormat0/1/3/4. To fix: read the field, map payShield's 2N value to the APC enum, pass it here.
        .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
        .verification_attributes(PinVerificationAttributes::Ibm3624Pin(ibm_attrs))
        .dukpt_attributes(dukpt_attrs)
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error()
                .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_pin_data::VerifyPinDataError::is_verification_failed_exception)
            {
                warn!("GO: PIN mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "GO: verify_pin_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_gq(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_gq(payload) {
        Ok(f) => f,
        Err(e) => {
            warn!(?e, "GQ parse error");
            return HandlerResult::from_proxy_error(&e);
        }
    };

    let bdk_arn = match state.key_map.resolve(&fields.bdk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pvk_arn = match state.key_map.resolve(&fields.pvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        DukptAttributes, PinBlockFormatForPinData, PinVerificationAttributes, VisaPinVerification,
    };

    let dukpt_attrs = match DukptAttributes::builder()
        .key_serial_number(&fields.ksn)
        .dukpt_derivation_type(fields.deriv_type)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let visa_attrs = match VisaPinVerification::builder()
        .pin_verification_key_index(fields.pvki)
        .verification_value(&fields.pvv)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(bdk = %bdk_arn, pvk = %pvk_arn, pvki = fields.pvki, ksn_len = fields.ksn.len(), "GQ: verify_pin_data VisaPVV DUKPT");

    match state
        .data
        .verify_pin_data()
        .verification_key_identifier(&pvk_arn)
        .encryption_key_identifier(&bdk_arn)
        .encrypted_pin_block(fields.pin_block.as_str())
        .primary_account_number(&fields.account)
        // KNOWN GAP: the 2N PIN block format field is consumed rather than forwarded. APC supports
        // IsoFormat0/1/3/4. To fix: read the field, map payShield's 2N value to the APC enum, pass it here.
        .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
        .verification_attributes(PinVerificationAttributes::VisaPin(visa_attrs))
        .dukpt_attributes(dukpt_attrs)
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error()
                .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_pin_data::VerifyPinDataError::is_verification_failed_exception)
            {
                warn!("GQ: PIN mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "GQ: verify_pin_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bdk_32() -> Vec<u8> {
        b"12345678901234561234567890123456".to_vec()
    }
    fn pvk_16() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec()
    }
    fn pvk_32() -> Vec<u8> {
        b"1234567890ABCDEF1234567890ABCDEF".to_vec()
    }

    // 3DES KSN descriptor: nibbles = 0x14 = 20 → 20H KSN
    fn ksn_tdes() -> Vec<u8> {
        let mut v = b"014".to_vec();
        v.extend_from_slice(b"12345678901234567890");
        v
    }

    // AES KSN descriptor: nibbles = 0x18 = 24 → 24H KSN
    fn ksn_aes() -> Vec<u8> {
        let mut v = b"018".to_vec();
        v.extend_from_slice(b"123456789012345678901234");
        v
    }

    fn build_go(bdk: &[u8], pvk: &[u8], ksn_block: &[u8]) -> Vec<u8> {
        let mut v = bdk.to_vec();
        v.extend_from_slice(pvk);
        v.extend_from_slice(ksn_block);
        v.extend_from_slice(b"1234567890ABCDEF"); // PIN block
        v.extend_from_slice(b"04"); // check length
        v.extend_from_slice(b"123456789012"); // account
        v.extend_from_slice(b"1234567890123456"); // decim table
        v.extend_from_slice(b"NNNNNNNNNNNN"); // pin val data
        v.extend_from_slice(b"123456FFFFFF"); // offset
        v
    }

    fn build_gq(bdk: &[u8], pvk: &[u8], ksn_block: &[u8]) -> Vec<u8> {
        let mut v = bdk.to_vec();
        v.extend_from_slice(pvk);
        v.extend_from_slice(ksn_block);
        v.extend_from_slice(b"1234567890ABCDEF"); // PIN block
        v.extend_from_slice(b"123456789012"); // account
        v.extend_from_slice(b"1"); // PVKI
        v.extend_from_slice(b"1234"); // PVV
        v
    }

    #[test]
    fn go_parse_tdes_ksn() {
        let p = build_go(&bdk_32(), &pvk_16(), &ksn_tdes());
        let f = parse_go(&p).unwrap();
        assert_eq!(f.ksn, "12345678901234567890");
        assert!(matches!(
            f.deriv_type,
            aws_sdk_paymentcryptographydata::types::DukptDerivationType::Tdes2Key
        ));
        assert_eq!(f.account, "123456789012");
        assert_eq!(f.offset, "123456FFFFFF");
    }

    #[test]
    fn go_parse_aes_ksn() {
        let p = build_go(&bdk_32(), &pvk_16(), &ksn_aes());
        let f = parse_go(&p).unwrap();
        assert_eq!(f.ksn.len(), 24);
        assert!(matches!(
            f.deriv_type,
            aws_sdk_paymentcryptographydata::types::DukptDerivationType::Aes128
        ));
    }

    #[test]
    fn gq_parse_tdes() {
        let p = build_gq(&bdk_32(), &pvk_32(), &ksn_tdes());
        let f = parse_gq(&p).unwrap();
        assert_eq!(f.pvki, 1);
        assert_eq!(f.pvv, "1234");
        assert!(matches!(
            f.deriv_type,
            aws_sdk_paymentcryptographydata::types::DukptDerivationType::Tdes2Key
        ));
    }

    #[test]
    fn gq_parse_aes() {
        let p = build_gq(&bdk_32(), &pvk_32(), &ksn_aes());
        let f = parse_gq(&p).unwrap();
        assert!(matches!(
            f.deriv_type,
            aws_sdk_paymentcryptographydata::types::DukptDerivationType::Aes128
        ));
    }

    #[test]
    fn go_rejects_k_prefix_decim() {
        let mut p = bdk_32();
        p.extend_from_slice(&pvk_16());
        p.extend_from_slice(&ksn_tdes());
        p.extend_from_slice(b"1234567890ABCDEF"); // PIN block
        p.extend_from_slice(b"04"); // check length
        p.extend_from_slice(b"123456789012"); // account
        p.push(b'K');
        assert!(matches!(parse_go(&p), Err(ProxyError::MalformedPayload(_))));
    }
}
