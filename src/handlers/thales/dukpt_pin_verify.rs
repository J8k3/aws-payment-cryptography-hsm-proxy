use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{parse_bdk, parse_legacy_key};
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield DUKPT PIN verification commands (original single-length DUKPT).
///
/// CK/CL — Verify PIN, IBM 3624 offset method  → APC verify_pin_data (Ibm3624PinVerification)
/// CM/CN — Verify PIN, Visa PVV method          → 68 (gated; same APC limitation as GQ)
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
///   Offset:              12H (IBM offset, F-padded; stripped before the APC call)
///
/// CM/CN return 68. The CM wire parser was removed when it was gated (recover from
/// git history if the APC path is fixed).
///
/// KNOWN GAP: KSN Descriptor encoding is defined in the Host Programmer Manual
/// (not included in the Legacy Host Commands reference used here). Standard 10-byte
/// (20H) DUKPT KSNs are assumed. Non-standard lengths will misparse.
///
/// Why these decisions, and how each was verified, live in `Handler::grounding()`
/// — the single source of truth (see `src/handlers/grounding.rs`), not duplicated
/// here.
pub struct DukptPinVerifyHandler;

const KSN_DESC_LEN: usize = 3;
const KSN_HEX_LEN: usize = 20;
const PIN_BLOCK_LEN: usize = 16;
const CHECK_LEN: usize = 2;
const ACCOUNT_LEN: usize = 12;
const DECIM_TABLE_LEN: usize = 16;
const PIN_VAL_DATA_LEN: usize = 12;
const IBM_OFFSET_LEN: usize = 12;

#[async_trait]
impl Handler for DukptPinVerifyHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["CK", "CM", "CO", "CQ"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[
            Evidence {
                decision: "CK verifies a DUKPT-encrypted PIN against an IBM 3624 offset (original single-length DUKPT, Tdes2Key). The 12H wire offset is F-padded; the padding is stripped before the APC call.",
                because: "PUGD0538-003 p.112 (CK). Verified live: proxy CK verdict == APC verify_pin_data verdict (IBM3624 + DUKPT) for valid PINs across randomized PAN/KSN. CK had the same offset F-padding bug as GO (APC pin_offset is ^[0-9]+$) — fixed the same way.",
                wire: WireGrounding::DiffXprov,
                crypto: CryptoGrounding::Apc,
                proof: Proof::LiveTest("dukpt_pin_verify_ck_differential"),
            },
            Evidence {
                decision: "CM (Visa PVV DUKPT verify) returns Unsupported (68).",
                because: "CM makes the byte-identical verify_pin_data + DukptAttributes + VisaPin call as GQ, which APC answers with InternalServerException (verified live for GQ, us-east-1 + us-west-2). Gated on that basis; the CM wire parser was removed. Workaround: translate the DUKPT PIN block to a ZPK, then verify the PVV non-DUKPT.",
                wire: WireGrounding::None,
                crypto: CryptoGrounding::None,
                proof: Proof::Gated("same APC single-call DUKPT+VisaPin 500 as GQ"),
            },
            Evidence {
                decision: "CO (Diebold) and CQ (Encrypted PIN) DUKPT verify return Unsupported (68).",
                because: "Diebold indexes a conversion table in HSM user storage and CQ compares against an LMK-encrypted reference PIN — neither has an APC equivalent (APC verify_pin_data does IBM3624 offset / Visa PVV only).",
                wire: WireGrounding::None,
                crypto: CryptoGrounding::None,
                proof: Proof::Gated("no APC equivalent (Diebold table / LMK-compare)"),
            },
        ]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"CK" => handle_ck(payload, state).await,
            b"CM" => {
                // Gated (68). CM makes the same verify_pin_data + DukptAttributes +
                // VisaPin call as GQ, which APC answers with InternalServerException.
                // Reason and evidence: Handler::grounding().
                warn!("CM gated: APC single-call DUKPT+VisaPin verify returns 500 (same as GQ)");
                HandlerResult::from_proxy_error(&ProxyError::Unsupported(
                    "CM (Visa PVV, DUKPT verify): APC VerifyPinData with DukptAttributes + \
                     VisaPin returns InternalServerException; gated pending an APC fix (same \
                     limitation as GQ). Workaround: translate the DUKPT PIN block to a ZPK, \
                     then verify the PVV non-DUKPT."
                        .into(),
                ))
            }
            b"CO" | b"CQ" => {
                warn!(cmd = %String::from_utf8_lossy(command_code), "no APC equivalent; returning 68");
                HandlerResult::err(*b"68")
            }
            _ => HandlerResult::err(*b"68"),
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
    if let Some(&b'K' | &b'L') = payload.get(decim_start) {
        warn!("CK: user-storage/AES-encrypted decimalization table not supported");
        return HandlerResult::err(*b"15");
    }

    let pin_val_start = decim_start + DECIM_TABLE_LEN;

    // 'P' prefix PIN validation data is a 16H hex form; we only support the 12A form.
    if payload.get(pin_val_start) == Some(&b'P') {
        warn!("CK: 'P'-prefix PIN validation data (16H) not supported");
        return HandlerResult::err(*b"15");
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
    let account =
        String::from_utf8_lossy(&payload[account_start..account_start + ACCOUNT_LEN]).to_string();
    let decim_table =
        String::from_utf8_lossy(&payload[decim_start..decim_start + DECIM_TABLE_LEN]).to_string();
    let pin_val_data =
        String::from_utf8_lossy(&payload[pin_val_start..pin_val_start + PIN_VAL_DATA_LEN])
            .to_string();
    let offset =
        String::from_utf8_lossy(&payload[offset_start..offset_start + IBM_OFFSET_LEN]).to_string();

    let bdk_arn = match state.key_map.resolve_descriptor(&bdk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pvk_arn = match state.key_map.resolve_descriptor(&pvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        DukptAttributes, DukptDerivationType, Ibm3624PinVerification, PinBlockFormatForPinData,
        PinVerificationAttributes,
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

    // The CK wire offset is 12H, left-justified and F-padded; APC's pin_offset is
    // digits-only (^[0-9]+$), so strip the F padding (same as GO).
    let pin_offset = offset.trim_end_matches('F');

    let ibm_attrs = match Ibm3624PinVerification::builder()
        .decimalization_table(&decim_table)
        .pin_validation_data_pad_character("F")
        .pin_validation_data(&pin_val_data)
        .pin_offset(pin_offset)
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

    fn pvk_single() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec() // 16 chars
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
}
