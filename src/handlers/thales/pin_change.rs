use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{map_pin_block_format, parse_key_32, parse_legacy_key};
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield PIN-change commands: verify current PIN + generate new verification data.
///
/// DU (→ DV) — Verify IBM 3624 PIN and generate new IBM PIN offset.
/// CU (→ CV) — Verify Visa PVV and generate new Visa PVV.
///
/// Both commands are atomic: the current PIN is verified first, and only if it
/// matches is the new verification datum generated. On mismatch the response is
/// error 01 and no generation data is returned.
///
/// DU field layout (PUGD0537-004 Rev A p.255 — AUTHORITATIVE):
///   ZPK:              16H | 'U'+32H | 'T'+48H  (parse_legacy_key; P0 key)
///   PVK:              16H | 'U'+32H | 'T'+48H  (parse_legacy_key; V1 IBM key)
///   Max PIN Length:    2N  consumed
///   Min PIN Length:    2N  consumed
///   Current PIN Block: 16H (current PIN encrypted under ZPK)
///   PIN Block Format:  2N  read and mapped to APC IsoFormat (covers both PIN blocks)
///   Account Number:   12N  rightmost 12 PAN digits excl. check digit
///   Decimalization Table: 16H
///   PIN Validation Data:  12A
///   Current Offset:   12H  IBM PIN offset for verification (F-padded)
///   New PIN Block:    16H  new customer-selected PIN encrypted under ZPK
///
/// DV response:
///   [2H]  error code
///   [12H] new IBM PIN offset (F-padded)
///
/// CU field layout (PUGD0537-004 Rev A p.259 — AUTHORITATIVE):
///   ZPK:              16H | 'U'+32H | 'T'+48H  (parse_legacy_key; P0 key)
///   PVK-Pair:         32H | 'U'+32H | 'T'+48H  (parse_key_32; V2 Visa double-length key)
///   Max PIN Length:    2N  consumed
///   Min PIN Length:    2N  consumed
///   Current PIN Block: 16H (current PIN encrypted under ZPK)
///   PIN Block Format:  2N  read and mapped to APC IsoFormat (covers both PIN blocks)
///   Account Number:   12N
///   PVKI:              1N  PIN Verification Key Indicator (1–6)
///   Current PVV:       4N  current Visa PVV for verification
///   New PIN Block:    16H  new customer-selected PIN encrypted under ZPK
///
/// CV response:
///   [2H] error code
///   [4N] new Visa PVV
pub struct PinChangeHandler;

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

struct DuFields {
    enc_key_id: KeyDescriptor,
    pvk_id: KeyDescriptor,
    cur_pin_block: Zeroizing<String>,
    pin_block_format: String,
    account: String,
    decim_table: String,
    pin_val_data: String,
    cur_offset: String,
    new_pin_block: Zeroizing<String>,
}

struct CuFields {
    enc_key_id: KeyDescriptor,
    pvk_id: KeyDescriptor,
    cur_pin_block: Zeroizing<String>,
    pin_block_format: String,
    account: String,
    pvki: i32,
    cur_pvv: String,
    new_pin_block: Zeroizing<String>,
}

fn parse_du(payload: &[u8]) -> Result<DuFields, ProxyError> {
    let mut pos = 0;

    let (enc_key_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;
    let (pvk_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;

    pos += MAX_PIN_LEN_FIELD + MIN_PIN_LEN_FIELD;

    let cur_pin_end = pos + PIN_BLOCK_LEN;
    let fmt_end = cur_pin_end + PIN_FMT_FIELD;
    let acct_end = fmt_end + ACCOUNT_LEN;
    let decim_end = acct_end + DECIM_TABLE_LEN;
    let pvdata_end = decim_end + PIN_VAL_DATA_LEN;
    let offset_end = pvdata_end + IBM_OFFSET_LEN;
    let new_pin_end = offset_end + PIN_BLOCK_LEN;

    if payload.len() < new_pin_end {
        return Err(ProxyError::MalformedPayload(format!(
            "DU payload too short: {} < {}",
            payload.len(),
            new_pin_end
        )));
    }

    Ok(DuFields {
        enc_key_id,
        pvk_id,
        cur_pin_block: Zeroizing::new(
            String::from_utf8_lossy(&payload[pos..cur_pin_end]).to_string(),
        ),
        pin_block_format: String::from_utf8_lossy(&payload[cur_pin_end..fmt_end]).to_string(),
        account: String::from_utf8_lossy(&payload[fmt_end..acct_end]).to_string(),
        decim_table: String::from_utf8_lossy(&payload[acct_end..decim_end]).to_string(),
        pin_val_data: String::from_utf8_lossy(&payload[decim_end..pvdata_end]).to_string(),
        cur_offset: String::from_utf8_lossy(&payload[pvdata_end..offset_end]).to_string(),
        new_pin_block: Zeroizing::new(
            String::from_utf8_lossy(&payload[offset_end..new_pin_end]).to_string(),
        ),
    })
}

fn parse_cu(payload: &[u8]) -> Result<CuFields, ProxyError> {
    let mut pos = 0;

    let (enc_key_id, n) = parse_legacy_key(payload, pos)?;
    pos += n;
    let (pvk_id, n) = parse_key_32(payload, pos)?;
    pos += n;

    pos += MAX_PIN_LEN_FIELD + MIN_PIN_LEN_FIELD;

    let cur_pin_end = pos + PIN_BLOCK_LEN;
    let fmt_end = cur_pin_end + PIN_FMT_FIELD;
    let acct_end = fmt_end + ACCOUNT_LEN;
    let pvki_end = acct_end + PVKI_LEN;
    let pvv_end = pvki_end + PVV_LEN;
    let new_pin_end = pvv_end + PIN_BLOCK_LEN;

    if payload.len() < new_pin_end {
        return Err(ProxyError::MalformedPayload(format!(
            "CU payload too short: {} < {}",
            payload.len(),
            new_pin_end
        )));
    }

    let pvki_str = std::str::from_utf8(&payload[acct_end..pvki_end])
        .map_err(|_| ProxyError::MalformedPayload("CU: PVKI not ASCII".into()))?;
    let pvki = pvki_str
        .parse::<i32>()
        .map_err(|_| ProxyError::MalformedPayload(format!("CU: invalid PVKI '{pvki_str}'")))?;

    Ok(CuFields {
        enc_key_id,
        pvk_id,
        cur_pin_block: Zeroizing::new(
            String::from_utf8_lossy(&payload[pos..cur_pin_end]).to_string(),
        ),
        pin_block_format: String::from_utf8_lossy(&payload[cur_pin_end..fmt_end]).to_string(),
        account: String::from_utf8_lossy(&payload[fmt_end..acct_end]).to_string(),
        pvki,
        cur_pvv: String::from_utf8_lossy(&payload[pvki_end..pvv_end]).to_string(),
        new_pin_block: Zeroizing::new(
            String::from_utf8_lossy(&payload[pvv_end..new_pin_end]).to_string(),
        ),
    })
}

#[async_trait]
impl Handler for PinChangeHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["CU", "DU"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision: "DU verifies the current PIN by IBM 3624 offset and generates a new offset; \
                       CU does the same by Visa PVV. Each is atomic: the current PIN is verified \
                       first (APC verify_pin_data), and only on a match is the new datum generated \
                       (APC generate_pin_data with Ibm3624PinOffset / VisaPinVerificationValue for \
                       the new PIN block). On mismatch the response is error 01 and no datum is \
                       returned. The IBM 12H current offset is F-padded and trimmed to APC's \
                       ^[0-9]+$ before the verify call.",
            because: "PUGD0537-004 Rev A p.255 (DU) / p.259 (CU). Verified live end-to-end: for \
                      both methods the proxy verifies a valid current PIN and returns a new \
                      offset/PVV that a direct APC verify_pin_data then confirms against the new \
                      PIN block, across randomized PAN. The live differential caught two DU offset \
                      bugs: the F-padded current offset was passed to APC's pin_offset (which \
                      requires ^[0-9]+$) so every valid current PIN was rejected — fixed by \
                      stripping the padding (as GO/CK/DA do); and the generated New Offset was \
                      returned unpadded, but the DV response field is 12H left-justified F-padded \
                      (p.255) — fixed by re-padding.",
            wire: WireGrounding::DiffXprov,
            crypto: CryptoGrounding::Apc,
            proof: Proof::LiveTest("pin_change_du_cu_differential"),
        }, Evidence {
            decision: "The Visa PVV primitive — APC's generate_pin_data VisaPinVerificationValue, \
                       the exact call CU makes to mint a new PVV, and the same algorithm APC uses \
                       to verify a PVV (DC/EC) — is additionally cross-validated against a second \
                       implementation (2impl), beyond agreement with APC alone.",
            because: "APC's generate_pin_data VisaPinVerificationValue agrees with CyberChef \
                      Payments — a purpose-built, inspectable payment-cryptography implementation, \
                      a separate codebase in a different language — over randomized PAN / PVKI / \
                      PIN with a shared clear PVK: both derive the same 4-digit PVV (verified live, \
                      8/8). The PIN is carried to APC as an ISO-0 block encrypted under a shared \
                      PEK, so a match also confirms the PIN-block encoding round-trips through \
                      APC. Combined with the proxy==APC differential above, the proxy's Visa PVV \
                      agrees with a second implementation. Honest strength: CyberChef Payments \
                      shares an author with this proxy, so it cross-checks the implementation \
                      (catching coding-level divergence) rather than being a neutral third-party \
                      oracle, and it is less battle-tested than APC — so this is corroboration; \
                      APC (AWS) is the independent reference. Run separately from this \
                      repository's automated tests.",
            wire: WireGrounding::None,
            crypto: CryptoGrounding::TwoImpl,
            proof: Proof::ManualCite(
                "cross-validated against CyberChef Payments (a second implementation by the same \
                 author); run separately",
            ),
        }]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"CU" => handle_cu(payload, state).await,
            _ => handle_du(payload, state).await,
        }
    }
}

async fn handle_du(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_du(payload) {
        Ok(f) => f,
        Err(e) => {
            warn!(?e, "DU parse error");
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
        Ibm3624PinOffset, Ibm3624PinVerification, PinGenerationAttributes,
        PinVerificationAttributes,
    };

    // One PIN Block Format Code covers both the current and new PIN blocks (same key).
    let pin_format = match map_pin_block_format(&fields.pin_block_format) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    // Step 1: verify current PIN. The wire offset is 12H left-justified and
    // F-padded; APC's pin_offset requires only the significant digits (^[0-9]+$),
    // no padding — strip it (same handling as GO/CK/DA).
    let cur_offset_trimmed = fields.cur_offset.trim_end_matches('F');
    let ibm_verify = match Ibm3624PinVerification::builder()
        .decimalization_table(&fields.decim_table)
        .pin_validation_data_pad_character("F")
        .pin_validation_data(&fields.pin_val_data)
        .pin_offset(cur_offset_trimmed)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(enc = %enc_arn, pvk = %pvk_arn, "DU: verify_pin_data IBM3624 (step 1)");

    match state
        .data
        .verify_pin_data()
        .encryption_key_identifier(&enc_arn)
        .verification_key_identifier(&pvk_arn)
        .encrypted_pin_block(fields.cur_pin_block.as_str())
        .primary_account_number(&fields.account)
        .pin_block_format(pin_format.clone())
        .verification_attributes(PinVerificationAttributes::Ibm3624Pin(ibm_verify))
        .send()
        .await
    {
        Ok(_) => {}
        Err(e) => {
            if e.as_service_error()
                .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_pin_data::VerifyPinDataError::is_verification_failed_exception)
            {
                warn!("DU: current PIN mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "DU: verify_pin_data failed");
            return HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()));
        }
    }

    // Step 2: generate new IBM offset from new customer-selected PIN
    let ibm_gen = match Ibm3624PinOffset::builder()
        .encrypted_pin_block(fields.new_pin_block.as_str())
        .decimalization_table(&fields.decim_table)
        .pin_validation_data_pad_character("F")
        .pin_validation_data(&fields.pin_val_data)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(enc = %enc_arn, pvk = %pvk_arn, "DU: generate_pin_data IBM3624 offset (step 2)");

    match state
        .data
        .generate_pin_data()
        .generation_key_identifier(&pvk_arn)
        .encryption_key_identifier(&enc_arn)
        .generation_attributes(PinGenerationAttributes::Ibm3624PinOffset(ibm_gen))
        .primary_account_number(&fields.account)
        .pin_block_format(pin_format)
        .send()
        .await
    {
        Ok(resp) => {
            use aws_sdk_paymentcryptographydata::types::PinData;
            match resp.pin_data() {
                Some(PinData::PinOffset(offset)) => {
                    // DV response: New Offset is 12H, left-justified and F-padded
                    // (PUGD0537-004 Rev A p.255). APC returns only the significant
                    // digits, so re-pad to the 12H field width.
                    let padded = format!("{offset:F<12}");
                    HandlerResult::success(padded.into_bytes())
                }
                other => {
                    warn!(?other, "DU: unexpected pin_data variant");
                    HandlerResult::from_proxy_error(&ProxyError::ApcError(
                        "DU: generate_pin_data returned unexpected pin_data variant".into(),
                    ))
                }
            }
        }
        Err(e) => {
            warn!(?e, "DU: generate_pin_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_cu(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_cu(payload) {
        Ok(f) => f,
        Err(e) => {
            warn!(?e, "CU parse error");
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
        PinGenerationAttributes, PinVerificationAttributes, VisaPinVerification,
        VisaPinVerificationValue,
    };

    // One PIN Block Format Code covers both the current and new PIN blocks (same key).
    let pin_format = match map_pin_block_format(&fields.pin_block_format) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    // Step 1: verify current Visa PVV
    let visa_verify = match VisaPinVerification::builder()
        .pin_verification_key_index(fields.pvki)
        .verification_value(&fields.cur_pvv)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(enc = %enc_arn, pvk = %pvk_arn, pvki = fields.pvki, "CU: verify_pin_data VisaPVV (step 1)");

    match state
        .data
        .verify_pin_data()
        .encryption_key_identifier(&enc_arn)
        .verification_key_identifier(&pvk_arn)
        .encrypted_pin_block(fields.cur_pin_block.as_str())
        .primary_account_number(&fields.account)
        .pin_block_format(pin_format.clone())
        .verification_attributes(PinVerificationAttributes::VisaPin(visa_verify))
        .send()
        .await
    {
        Ok(_) => {}
        Err(e) => {
            if e.as_service_error()
                .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_pin_data::VerifyPinDataError::is_verification_failed_exception)
            {
                warn!("CU: current PIN mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "CU: verify_pin_data failed");
            return HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()));
        }
    }

    // Step 2: generate new Visa PVV from new customer-selected PIN
    let visa_gen = match VisaPinVerificationValue::builder()
        .encrypted_pin_block(fields.new_pin_block.as_str())
        .pin_verification_key_index(fields.pvki)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(enc = %enc_arn, pvk = %pvk_arn, pvki = fields.pvki, "CU: generate_pin_data VisaPVV (step 2)");

    match state
        .data
        .generate_pin_data()
        .generation_key_identifier(&pvk_arn)
        .encryption_key_identifier(&enc_arn)
        .generation_attributes(PinGenerationAttributes::VisaPinVerificationValue(visa_gen))
        .primary_account_number(&fields.account)
        .pin_block_format(pin_format)
        .send()
        .await
    {
        Ok(resp) => {
            use aws_sdk_paymentcryptographydata::types::PinData;
            match resp.pin_data() {
                Some(PinData::VerificationValue(pvv)) => {
                    HandlerResult::success(pvv.as_bytes().to_vec())
                }
                other => {
                    warn!(?other, "CU: unexpected pin_data variant");
                    HandlerResult::from_proxy_error(&ProxyError::ApcError(
                        "CU: generate_pin_data returned unexpected pin_data variant".into(),
                    ))
                }
            }
        }
        Err(e) => {
            warn!(?e, "CU: generate_pin_data failed");
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

    fn double_key() -> Vec<u8> {
        b"1234567890ABCDEF1234567890ABCDEF".to_vec()
    }

    fn build_du_payload(enc_key: &[u8], pvk: &[u8]) -> Vec<u8> {
        let mut v = enc_key.to_vec();
        v.extend_from_slice(pvk);
        v.extend_from_slice(b"04"); // max pin len
        v.extend_from_slice(b"04"); // min pin len
        v.extend_from_slice(b"1234567890ABCDEF"); // current PIN block 16H
        v.extend_from_slice(b"01"); // pin block format
        v.extend_from_slice(b"123456789012"); // account 12N
        v.extend_from_slice(b"1234567890123456"); // decim table 16H
        v.extend_from_slice(b"NNNNNNNNNNNN"); // pin val data 12A
        v.extend_from_slice(b"123456FFFFFF"); // current offset 12H
        v.extend_from_slice(b"FEDCBA9876543210"); // new PIN block 16H
        v
    }

    fn build_cu_payload(enc_key: &[u8], pvk: &[u8]) -> Vec<u8> {
        let mut v = enc_key.to_vec();
        v.extend_from_slice(pvk);
        v.extend_from_slice(b"04"); // max pin len
        v.extend_from_slice(b"04"); // min pin len
        v.extend_from_slice(b"1234567890ABCDEF"); // current PIN block 16H
        v.extend_from_slice(b"01"); // pin block format
        v.extend_from_slice(b"123456789012"); // account 12N
        v.extend_from_slice(b"1"); // PVKI
        v.extend_from_slice(b"1234"); // current PVV 4N
        v.extend_from_slice(b"FEDCBA9876543210"); // new PIN block 16H
        v
    }

    #[test]
    fn du_parse_single_keys() {
        let payload = build_du_payload(&single_key(), &single_key());
        let f = parse_du(&payload).unwrap();
        assert_eq!(f.enc_key_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pvk_id.raw, "1234567890ABCDEF");
        assert_eq!(f.cur_pin_block.as_str(), "1234567890ABCDEF");
        assert_eq!(f.account, "123456789012");
        assert_eq!(f.decim_table, "1234567890123456");
        assert_eq!(f.pin_val_data, "NNNNNNNNNNNN");
        assert_eq!(f.cur_offset, "123456FFFFFF");
        assert_eq!(f.new_pin_block.as_str(), "FEDCBA9876543210");
    }

    #[test]
    fn du_parse_double_enc_key() {
        let mut key = vec![b'U'];
        key.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = build_du_payload(&key, &single_key());
        let f = parse_du(&payload).unwrap();
        assert_eq!(f.enc_key_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.pvk_id.raw, "1234567890ABCDEF");
        assert_eq!(f.new_pin_block.as_str(), "FEDCBA9876543210");
    }

    #[test]
    fn du_rejects_short_payload() {
        let payload = b"tooshort".to_vec();
        assert!(matches!(
            parse_du(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn cu_parse_single_enc_double_pvk() {
        let payload = build_cu_payload(&single_key(), &double_key());
        let f = parse_cu(&payload).unwrap();
        assert_eq!(f.enc_key_id.raw, "1234567890ABCDEF");
        assert_eq!(f.pvk_id.raw, "1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.cur_pin_block.as_str(), "1234567890ABCDEF");
        assert_eq!(f.account, "123456789012");
        assert_eq!(f.pvki, 1);
        assert_eq!(f.cur_pvv, "1234");
        assert_eq!(f.new_pin_block.as_str(), "FEDCBA9876543210");
    }

    #[test]
    fn cu_parse_u_prefix_pvk() {
        let mut pvk = vec![b'U'];
        pvk.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let payload = build_cu_payload(&single_key(), &pvk);
        let f = parse_cu(&payload).unwrap();
        assert_eq!(f.pvk_id.raw, "U1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.new_pin_block.as_str(), "FEDCBA9876543210");
    }

    #[test]
    fn cu_rejects_invalid_pvki() {
        let mut payload = build_cu_payload(&single_key(), &double_key());
        // The PVKI byte is at: single_key(16) + double_key(32) + 4(len) + 16(pin) + 2(fmt) + 12(acct) = 82
        let pvki_pos = 16 + 32 + 4 + 16 + 2 + 12;
        payload[pvki_pos] = b'X';
        assert!(matches!(
            parse_cu(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn cu_rejects_short_payload() {
        let payload = b"tooshort".to_vec();
        assert!(matches!(
            parse_cu(&payload),
            Err(ProxyError::MalformedPayload(_))
        ));
    }
}
