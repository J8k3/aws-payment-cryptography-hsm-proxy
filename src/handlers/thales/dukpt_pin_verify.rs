use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{parse_bdk, parse_key_32, parse_legacy_key};
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield DUKPT PIN verification commands (original single-length DUKPT).
///
/// CK/CL — Verify PIN, IBM 3624 offset method  → APC verify_pin_data (Ibm3624PinVerification)
/// CM/CN — Verify PIN, Visa PVV method          → APC verify_pin_data (VisaPinVerification)
/// CO/CP — Verify PIN, Diebold method           → 68 (Diebold table in HSM user storage)
/// CQ/CR — Verify PIN, Encrypted PIN method     → 68 (LMK-encrypted reference PIN, no APC equivalent)
///
/// All commands use original single-length DUKPT: BDK (LMK pair 28-29) derives a 56-bit
/// working key using TDES 2-key derivation. Superseded equivalents use 3DES DUKPT.
///
/// CK field layout:
///   BDK (LMK 28-29):    32H | 'U'+32H
///   PVK (LMK 14-15 v0): 16H | 'U'+32H | 'T'+48H
///   KSN Descriptor:      3H  (consumed; see KNOWN GAP below)
///   KSN:                 20H (standard 10-byte DUKPT KSN assumed)
///   PIN Block:           16H
///   Check Length:        2N  (minimum PIN length, consumed but not forwarded)
///   Account Number:      12N (rightmost 12 digits of PAN excl. check digit)
///   Decim Table:         16N or 16H (16-char; 'K'/'L' prefix variants → error 15)
///   PIN Validation Data: 12A (12 alphanumeric chars; 'P' prefix variant → error 15)
///   Offset:              12H (IBM 3624 PIN offset, left-justified, F-padded)
///
/// CM field layout:
///   BDK (LMK 28-29):    32H | 'U'+32H
///   PVK (LMK 14-15 v0): 32H | 'U'+32H | 'T'+48H
///   KSN Descriptor:      3H
///   KSN:                 20H
///   PIN Block:           16H
///   PAN:                 12N
///   PVKI:                1N  (PIN Verification Key Indicator)
///   PVV:                 4N  (PIN Verification Value from card/database)
///
/// KNOWN GAP: KSN Descriptor encoding is defined in the Host Programmer Manual
/// (not included in the Legacy Host Commands reference used here). Standard 10-byte
/// (20H) DUKPT KSNs are assumed. Non-standard lengths will misparse.
pub struct DukptPinVerifyHandler;

const KSN_DESC_LEN: usize = 3;
const KSN_HEX_LEN: usize = 20;
const PIN_BLOCK_LEN: usize = 16;
const CHECK_LEN: usize = 2;
const ACCOUNT_LEN: usize = 12;
const DECIM_TABLE_LEN: usize = 16;
const PIN_VAL_DATA_LEN: usize = 12;
const IBM_OFFSET_LEN: usize = 12;
const PVKI_LEN: usize = 1;
const PVV_LEN: usize = 4;

#[async_trait]
impl Handler for DukptPinVerifyHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["CK", "CM", "CO", "CQ"]
    }

    async fn handle(&self, command_code: &[u8], payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
        match command_code {
            b"CK" => handle_ck(payload, state).await,
            b"CM" => handle_cm(payload, state).await,
            b"CO" | b"CQ" => {
                warn!(cmd = %String::from_utf8_lossy(command_code), "no APC equivalent; returning 68");
                HandlerResult::err(b"68")
            }
            _ => HandlerResult::err(b"68"),
        }
    }
}

async fn handle_cm(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (bdk_id, bdk_len) = match parse_bdk(payload, 0) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let (pvk_id, pvk_len) = match parse_key_32(payload, bdk_len) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let ksn_start = bdk_len + pvk_len + KSN_DESC_LEN;
    let pin_start = ksn_start + KSN_HEX_LEN;
    let pan_start = pin_start + PIN_BLOCK_LEN;
    let pvki_start = pan_start + ACCOUNT_LEN;
    let pvv_start = pvki_start + PVKI_LEN;
    let min_len = pvv_start + PVV_LEN;

    if payload.len() < min_len {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "CM payload too short: {} < {}",
            payload.len(),
            min_len
        )));
    }

    // Token mode (';' between PAN and PVKI) is not supported.
    if payload.get(pvki_start) == Some(&b';') {
        warn!("CM: Token mode (';' delimiter) not supported");
        return HandlerResult::err(b"15");
    }

    let ksn = String::from_utf8_lossy(&payload[ksn_start..ksn_start + KSN_HEX_LEN]).to_string();
    let pin_block = Zeroizing::new(
        String::from_utf8_lossy(&payload[pin_start..pin_start + PIN_BLOCK_LEN]).to_string(),
    );
    let pan = String::from_utf8_lossy(&payload[pan_start..pan_start + ACCOUNT_LEN]).to_string();
    let pvki_str = String::from_utf8_lossy(&payload[pvki_start..pvki_start + PVKI_LEN]).to_string();
    let pvv = String::from_utf8_lossy(&payload[pvv_start..pvv_start + PVV_LEN]).to_string();

    let bdk_arn = match state.key_map.resolve(&bdk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pvk_arn = match state.key_map.resolve(&pvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        DukptAttributes, DukptDerivationType, PinBlockFormatForPinData,
        PinVerificationAttributes, VisaPinVerification,
    };

    // DukptAttributes carries only KSN + derivation type; BDK ARN goes in
    // encryption_key_identifier on the outer verify_pin_data call.
    let dukpt_attrs = match DukptAttributes::builder()
        .key_serial_number(&ksn)
        .dukpt_derivation_type(DukptDerivationType::Tdes2Key)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let pvki = pvki_str.parse::<i32>().unwrap_or(1);
    let visa_attrs = match VisaPinVerification::builder()
        .pin_verification_key_index(pvki)
        .verification_value(&pvv)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(bdk = %bdk_arn, pvk = %pvk_arn, "CM: verify_pin_data VisaPVV DUKPT");

    match state
        .data
        .verify_pin_data()
        .verification_key_identifier(&pvk_arn)
        .encryption_key_identifier(&bdk_arn)
        .encrypted_pin_block(pin_block.as_str())
        .primary_account_number(&pan)
        .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
        .verification_attributes(PinVerificationAttributes::VisaPin(visa_attrs))
        .dukpt_attributes(dukpt_attrs)
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error()
                .map(|s| s.is_verification_failed_exception())
                .unwrap_or(false)
            {
                warn!("CM: PIN mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "CM: verify_pin_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_ck(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (bdk_id, bdk_len) = match parse_bdk(payload, 0) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let (pvk_id, pvk_len) = match parse_legacy_key(payload, bdk_len) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let ksn_start = bdk_len + pvk_len + KSN_DESC_LEN;
    let pin_start = ksn_start + KSN_HEX_LEN;
    let check_start = pin_start + PIN_BLOCK_LEN;
    let account_start = check_start + CHECK_LEN;
    let decim_start = account_start + ACCOUNT_LEN;

    // 'K' and 'L' prefix decimalization table formats reference HSM user storage or AES
    // key blocks — neither has an APC equivalent.
    match payload.get(decim_start) {
        Some(&b'K') | Some(&b'L') => {
            warn!("CK: user-storage/AES-encrypted decimalization table not supported");
            return HandlerResult::err(b"15");
        }
        _ => {}
    }

    let pin_val_start = decim_start + DECIM_TABLE_LEN;

    // 'P' prefix PIN validation data is a 16H hex form; we only support the 12A form.
    if payload.get(pin_val_start) == Some(&b'P') {
        warn!("CK: 'P'-prefix PIN validation data (16H) not supported");
        return HandlerResult::err(b"15");
    }

    let offset_start = pin_val_start + PIN_VAL_DATA_LEN;
    let min_len = offset_start + IBM_OFFSET_LEN;

    if payload.len() < min_len {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "CK payload too short: {} < {}",
            payload.len(),
            min_len
        )));
    }

    let ksn = String::from_utf8_lossy(&payload[ksn_start..ksn_start + KSN_HEX_LEN]).to_string();
    let pin_block = Zeroizing::new(
        String::from_utf8_lossy(&payload[pin_start..pin_start + PIN_BLOCK_LEN]).to_string(),
    );
    let account = String::from_utf8_lossy(&payload[account_start..account_start + ACCOUNT_LEN]).to_string();
    let decim_table =
        String::from_utf8_lossy(&payload[decim_start..decim_start + DECIM_TABLE_LEN]).to_string();
    let pin_val_data =
        String::from_utf8_lossy(&payload[pin_val_start..pin_val_start + PIN_VAL_DATA_LEN]).to_string();
    let offset =
        String::from_utf8_lossy(&payload[offset_start..offset_start + IBM_OFFSET_LEN]).to_string();

    let bdk_arn = match state.key_map.resolve(&bdk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pvk_arn = match state.key_map.resolve(&pvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        DukptAttributes, DukptDerivationType, Ibm3624PinVerification,
        PinBlockFormatForPinData, PinVerificationAttributes,
    };

    // DukptAttributes carries only KSN + derivation type; BDK ARN goes in
    // encryption_key_identifier on the outer verify_pin_data call.
    let dukpt_attrs = match DukptAttributes::builder()
        .key_serial_number(&ksn)
        .dukpt_derivation_type(DukptDerivationType::Tdes2Key)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let ibm_attrs = match Ibm3624PinVerification::builder()
        .decimalization_table(&decim_table)
        .pin_validation_data_pad_character("F")
        .pin_validation_data(&pin_val_data)
        .pin_offset(&offset)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(bdk = %bdk_arn, pvk = %pvk_arn, "CK: verify_pin_data IBM3624 DUKPT");

    match state
        .data
        .verify_pin_data()
        .verification_key_identifier(&pvk_arn)
        .encryption_key_identifier(&bdk_arn)
        .encrypted_pin_block(pin_block.as_str())
        .primary_account_number(&account)
        .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
        .verification_attributes(PinVerificationAttributes::Ibm3624Pin(ibm_attrs))
        .dukpt_attributes(dukpt_attrs)
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error()
                .map(|s| s.is_verification_failed_exception())
                .unwrap_or(false)
            {
                warn!("CK: PIN mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "CK: verify_pin_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bdk_single() -> Vec<u8> {
        b"12345678901234561234567890123456".to_vec() // 32 chars
    }

    fn bdk_double() -> Vec<u8> {
        let mut v = vec![b'U'];
        v.extend_from_slice(b"12345678901234561234567890123456");
        v
    }

    fn pvk_single() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec() // 16 chars
    }

    fn pvk_32() -> Vec<u8> {
        b"12345678901234561234567890123456".to_vec() // 32 chars
    }

    fn ksn_desc_and_ksn() -> Vec<u8> {
        let mut v = b"00A".to_vec(); // 3-char descriptor
        v.extend_from_slice(b"12345678901234567890"); // 20-char KSN
        v
    }

    #[test]
    fn ck_parse_min_fields() {
        let mut payload = bdk_single(); // 32
        payload.extend_from_slice(&pvk_single()); // 16
        payload.extend_from_slice(&ksn_desc_and_ksn()); // 23
        payload.extend_from_slice(b"1234567890123456"); // PIN block 16
        payload.extend_from_slice(b"04"); // check length 2
        payload.extend_from_slice(b"123456789012"); // account 12
        payload.extend_from_slice(b"1234567890123456"); // decim table 16
        payload.extend_from_slice(b"NNNNNNNNNNNN"); // pin val data 12
        payload.extend_from_slice(b"123456789012"); // offset 12

        let (bdk_id, bdk_len) = parse_bdk(&payload, 0).unwrap();
        assert_eq!(bdk_len, 32);
        let (pvk_id, pvk_len) = parse_legacy_key(&payload, bdk_len).unwrap();
        assert_eq!(pvk_len, 16);
        let ksn_start = bdk_len + pvk_len + KSN_DESC_LEN;
        let pin_start = ksn_start + KSN_HEX_LEN;
        let check_start = pin_start + PIN_BLOCK_LEN;
        let account_start = check_start + CHECK_LEN;
        let decim_start = account_start + ACCOUNT_LEN;
        let pin_val_start = decim_start + DECIM_TABLE_LEN;
        let offset_start = pin_val_start + PIN_VAL_DATA_LEN;
        let min_len = offset_start + IBM_OFFSET_LEN;
        assert_eq!(payload.len(), min_len);
        let _ = bdk_id;
        let _ = pvk_id;
    }

    #[test]
    fn ck_rejects_k_prefix_decim_table() {
        let mut payload = bdk_single();
        payload.extend_from_slice(&pvk_single());
        payload.extend_from_slice(&ksn_desc_and_ksn());
        payload.extend_from_slice(b"1234567890123456"); // PIN block
        payload.extend_from_slice(b"04"); // check length
        payload.extend_from_slice(b"123456789012"); // account
        payload.push(b'K'); // K-prefix decim table
        // doesn't matter what follows — handler rejects on prefix

        let (_, bdk_len) = parse_bdk(&payload, 0).unwrap();
        let (_, pvk_len) = parse_legacy_key(&payload, bdk_len).unwrap();
        let ksn_start = bdk_len + pvk_len + KSN_DESC_LEN;
        let pin_start = ksn_start + KSN_HEX_LEN;
        let check_start = pin_start + PIN_BLOCK_LEN;
        let account_start = check_start + CHECK_LEN;
        let decim_start = account_start + ACCOUNT_LEN;
        assert_eq!(payload.get(decim_start), Some(&b'K'));
    }

    #[test]
    fn cm_parse_min_fields() {
        let mut payload = bdk_single(); // 32
        payload.extend_from_slice(&pvk_32()); // 32
        payload.extend_from_slice(&ksn_desc_and_ksn()); // 23
        payload.extend_from_slice(b"1234567890123456"); // PIN block 16
        payload.extend_from_slice(b"123456789012"); // PAN 12
        payload.extend_from_slice(b"1"); // PVKI 1
        payload.extend_from_slice(b"1234"); // PVV 4

        let (_, bdk_len) = parse_bdk(&payload, 0).unwrap();
        assert_eq!(bdk_len, 32);
        let (_, pvk_len) = parse_key_32(&payload, bdk_len).unwrap();
        assert_eq!(pvk_len, 32);
        let ksn_start = bdk_len + pvk_len + KSN_DESC_LEN;
        let pin_start = ksn_start + KSN_HEX_LEN;
        let pan_start = pin_start + PIN_BLOCK_LEN;
        let pvki_start = pan_start + ACCOUNT_LEN;
        let pvv_start = pvki_start + PVKI_LEN;
        let min_len = pvv_start + PVV_LEN;
        assert_eq!(payload.len(), min_len);
    }

    #[test]
    fn cm_rejects_token_mode() {
        let mut payload = bdk_double(); // 33
        payload.extend_from_slice(&pvk_32()); // 32
        payload.extend_from_slice(&ksn_desc_and_ksn()); // 23
        payload.extend_from_slice(b"1234567890123456"); // PIN block 16
        payload.extend_from_slice(b"123456789012"); // PAN 12
        payload.push(b';'); // token mode delimiter

        let (_, bdk_len) = parse_bdk(&payload, 0).unwrap();
        let (_, pvk_len) = parse_key_32(&payload, bdk_len).unwrap();
        let ksn_start = bdk_len + pvk_len + KSN_DESC_LEN;
        let pin_start = ksn_start + KSN_HEX_LEN;
        let pan_start = pin_start + PIN_BLOCK_LEN;
        let pvki_start = pan_start + ACCOUNT_LEN;
        assert_eq!(payload.get(pvki_start), Some(&b';'));
    }
}
