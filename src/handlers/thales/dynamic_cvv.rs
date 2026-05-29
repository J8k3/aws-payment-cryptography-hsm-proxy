use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield International Host Commands — Dynamic CVV generation and verification.
///
/// QY (→ QZ): Generate a Dynamic Card Verification Value (dCVV)
/// PM (→ PN): Verify a Dynamic CVV/CVC
///
/// Source: PUGD0537-004 Rev A, p.306 (QY) and p.308 (PM). AUTHORITATIVE per apc-agent.
/// Wire format inferred from the CW/CY commands and the APC DynamicCardVerificationValue
/// structure — treat field positions as reference-quality until PUGD0537 is available.
///
/// ## Inferred QY field layout
///   [32H] CVK — double-length CVK encrypted under LMK pair 14-15
///   [16N] PAN — 16 decimal digits
///   [4N]  Expiry — card expiry date as MMYY
///   [3N]  Service Code
///   [4H]  ATC — Application Transaction Counter (2 bytes hex)
///   [2N]  PAN Sequence Number — 2 decimal digits
///
/// QZ response (after header):
///   [2H] Error Code
///   [3N] dCVV value (3 decimal digits)
///
/// ## Inferred PM field layout (verify path)
///   [32H] CVK
///   [3N]  dCVV to verify
///   [16N] PAN
///   [4N]  Expiry
///   [3N]  Service Code
///   [4H]  ATC
///   [2N]  PAN Sequence Number
///
/// PN response:
///   [2H] Error Code (00=success, 01=mismatch)
///
/// ## APC mapping
///   QY → generate_card_validation_data with DynamicCardVerificationValue + TR31_C0 key
///   PM → verify_card_validation_data with DynamicCardVerificationValue + TR31_C0 key
pub struct DynamicCvvHandler;

const CVK_LEN: usize = 32;
const PAN_LEN: usize = 16;
const EXPIRY_LEN: usize = 4;
const SERVICE_CODE_LEN: usize = 3;
const ATC_LEN: usize = 4;
const PAN_SEQ_LEN: usize = 2;
const DCVV_LEN: usize = 3;

const QY_MIN_LEN: usize = CVK_LEN + PAN_LEN + EXPIRY_LEN + SERVICE_CODE_LEN + ATC_LEN + PAN_SEQ_LEN;
const PM_MIN_LEN: usize =
    CVK_LEN + DCVV_LEN + PAN_LEN + EXPIRY_LEN + SERVICE_CODE_LEN + ATC_LEN + PAN_SEQ_LEN;

struct QyFields {
    cvk_id: String,
    pan: String,
    expiry: String,
    service_code: String,
    atc: String,
    pan_seq: String,
}

fn parse_qy_fields(payload: &[u8]) -> Result<QyFields, ProxyError> {
    if payload.len() < QY_MIN_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "QY payload too short: {} < {}",
            payload.len(),
            QY_MIN_LEN
        )));
    }
    let mut pos = 0;
    let cvk_id = String::from_utf8_lossy(&payload[pos..pos + CVK_LEN]).to_string();
    pos += CVK_LEN;
    let pan = String::from_utf8_lossy(&payload[pos..pos + PAN_LEN]).to_string();
    pos += PAN_LEN;
    let expiry = String::from_utf8_lossy(&payload[pos..pos + EXPIRY_LEN]).to_string();
    pos += EXPIRY_LEN;
    let service_code = String::from_utf8_lossy(&payload[pos..pos + SERVICE_CODE_LEN]).to_string();
    pos += SERVICE_CODE_LEN;
    let atc = String::from_utf8_lossy(&payload[pos..pos + ATC_LEN]).to_string();
    pos += ATC_LEN;
    let pan_seq = String::from_utf8_lossy(&payload[pos..pos + PAN_SEQ_LEN]).to_string();
    Ok(QyFields {
        cvk_id,
        pan,
        expiry,
        service_code,
        atc,
        pan_seq,
    })
}

struct PmFields {
    cvk_id: String,
    dcvv: String,
    pan: String,
    expiry: String,
    service_code: String,
    atc: String,
    pan_seq: String,
}

fn parse_pm_fields(payload: &[u8]) -> Result<PmFields, ProxyError> {
    if payload.len() < PM_MIN_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "PM payload too short: {} < {}",
            payload.len(),
            PM_MIN_LEN
        )));
    }
    let mut pos = 0;
    let cvk_id = String::from_utf8_lossy(&payload[pos..pos + CVK_LEN]).to_string();
    pos += CVK_LEN;
    let dcvv = String::from_utf8_lossy(&payload[pos..pos + DCVV_LEN]).to_string();
    pos += DCVV_LEN;
    let pan = String::from_utf8_lossy(&payload[pos..pos + PAN_LEN]).to_string();
    pos += PAN_LEN;
    let expiry = String::from_utf8_lossy(&payload[pos..pos + EXPIRY_LEN]).to_string();
    pos += EXPIRY_LEN;
    let service_code = String::from_utf8_lossy(&payload[pos..pos + SERVICE_CODE_LEN]).to_string();
    pos += SERVICE_CODE_LEN;
    let atc = String::from_utf8_lossy(&payload[pos..pos + ATC_LEN]).to_string();
    pos += ATC_LEN;
    let pan_seq = String::from_utf8_lossy(&payload[pos..pos + PAN_SEQ_LEN]).to_string();
    Ok(PmFields {
        cvk_id,
        dcvv,
        pan,
        expiry,
        service_code,
        atc,
        pan_seq,
    })
}

#[async_trait]
impl Handler for DynamicCvvHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["QY", "PM"]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"QY" => handle_qy(payload, state).await,
            b"PM" => handle_pm(payload, state).await,
            _ => HandlerResult::err(*b"68"),
        }
    }
}

async fn handle_qy(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let f = match parse_qy_fields(payload) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let cvk_arn = match state.key_map.resolve(&f.cvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        CardGenerationAttributes, DynamicCardVerificationValue,
    };
    let attrs = match DynamicCardVerificationValue::builder()
        .pan_sequence_number(&f.pan_seq)
        .card_expiry_date(&f.expiry)
        .service_code(&f.service_code)
        .application_transaction_counter(&f.atc)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => CardGenerationAttributes::DynamicCardVerificationValue(a),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(cvk = %cvk_arn, "QY: generate_card_validation_data dCVV");
    match state
        .data
        .generate_card_validation_data()
        .key_identifier(&cvk_arn)
        .primary_account_number(&f.pan)
        .generation_attributes(attrs)
        .send()
        .await
    {
        Ok(resp) => HandlerResult::success(resp.validation_data().as_bytes().to_vec()),
        Err(e) => {
            warn!(?e, "QY: generate_card_validation_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_pm(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let f = match parse_pm_fields(payload) {
        Ok(f) => f,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let cvk_arn = match state.key_map.resolve(&f.cvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        CardVerificationAttributes, DynamicCardVerificationValue,
    };
    let attrs = match DynamicCardVerificationValue::builder()
        .pan_sequence_number(&f.pan_seq)
        .card_expiry_date(&f.expiry)
        .service_code(&f.service_code)
        .application_transaction_counter(&f.atc)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => CardVerificationAttributes::DynamicCardVerificationValue(a),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(cvk = %cvk_arn, "PM: verify_card_validation_data dCVV");
    match state
        .data
        .verify_card_validation_data()
        .key_identifier(&cvk_arn)
        .primary_account_number(&f.pan)
        .validation_data(&f.dcvv)
        .verification_attributes(attrs)
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error().is_some_and(
                aws_sdk_paymentcryptographydata::operation::verify_card_validation_data::VerifyCardValidationDataError::is_verification_failed_exception,
            ) {
                warn!("PM: dCVV mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "PM: verify_card_validation_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qy_payload(atc: &[u8], pan_seq: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF"); // CVK 32H
        v.extend_from_slice(b"4111111111111111"); // PAN
        v.extend_from_slice(b"1225"); // expiry MMYY
        v.extend_from_slice(b"101"); // service code
        v.extend_from_slice(atc); // ATC 4H
        v.extend_from_slice(pan_seq); // PAN seq 2N
        v
    }

    #[test]
    fn qy_parses_all_fields() {
        let payload = qy_payload(b"0012", b"00");
        let f = parse_qy_fields(&payload).unwrap();
        assert_eq!(f.cvk_id, "1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.pan, "4111111111111111");
        assert_eq!(f.expiry, "1225");
        assert_eq!(f.service_code, "101");
        assert_eq!(f.atc, "0012");
        assert_eq!(f.pan_seq, "00");
    }

    #[test]
    fn qy_rejects_short_payload() {
        let payload = b"tooshort";
        assert!(parse_qy_fields(payload).is_err());
    }

    #[test]
    fn pm_parses_all_fields() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF"); // CVK
        payload.extend_from_slice(b"123"); // dCVV to verify
        payload.extend_from_slice(b"4111111111111111"); // PAN
        payload.extend_from_slice(b"1225"); // expiry
        payload.extend_from_slice(b"101"); // service code
        payload.extend_from_slice(b"0012"); // ATC
        payload.extend_from_slice(b"00"); // PAN seq

        let f = parse_pm_fields(&payload).unwrap();
        assert_eq!(f.cvk_id, "1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.dcvv, "123");
        assert_eq!(f.pan, "4111111111111111");
        assert_eq!(f.expiry, "1225");
        assert_eq!(f.service_code, "101");
        assert_eq!(f.atc, "0012");
        assert_eq!(f.pan_seq, "00");
    }

    #[test]
    fn pm_rejects_short_payload() {
        let payload = b"tooshort";
        assert!(parse_pm_fields(payload).is_err());
    }

    #[test]
    fn qy_min_len_constant_is_correct() {
        // CVK(32) + PAN(16) + expiry(4) + svc(3) + ATC(4) + panseq(2) = 61
        assert_eq!(QY_MIN_LEN, 61);
    }

    #[test]
    fn pm_min_len_constant_is_correct() {
        // CVK(32) + dCVV(3) + PAN(16) + expiry(4) + svc(3) + ATC(4) + panseq(2) = 64
        assert_eq!(PM_MIN_LEN, 64);
    }
}
