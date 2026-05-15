use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::handlers::{AppState, Handler, HandlerResult};
use crate::error::ProxyError;

/// payShield card verification commands: CW (generate) and CY (verify).
///
/// CW → APC GenerateCardValidationData
/// CY → APC VerifyCardValidationData
///
/// CW field layout:
///   [0]        mode         1 byte  ('0'=CVV1/CAVV, '1'=CVV2, '2'=iCVV)
///   [1..33]    CVK          32 hex chars
///   [33..49]   PAN          16 decimal chars
///   [49..53]   expiry       4 chars (MMYY)
///   [53..56]   service code 3 chars
///
/// CY field layout:
///   [0]        mode         1 byte
///   [1..33]    CVK          32 hex chars
///   [33..36]   CVV value    3 chars
///   [36..52]   PAN          16 decimal chars
///   [52..56]   expiry       4 chars
///   [56..59]   service code 3 chars
pub struct CvvHandler;

const CVK_START: usize = 1;
const CVK_END: usize = 33;
const CW_PAN_START: usize = 33;
const CW_PAN_END: usize = 49;
const CW_EXPIRY_START: usize = 49;
const CW_EXPIRY_END: usize = 53;
const CW_SVC_START: usize = 53;
const CW_SVC_END: usize = 56;
const CW_MIN_LEN: usize = 56;
const CY_CVV_START: usize = 33;
const CY_CVV_END: usize = 36;
const CY_PAN_START: usize = 36;
const CY_PAN_END: usize = 52;
const CY_EXPIRY_START: usize = 52;
const CY_EXPIRY_END: usize = 56;
const CY_SVC_START: usize = 56;
const CY_SVC_END: usize = 59;
const CY_MIN_LEN: usize = 59;

#[async_trait]
impl Handler for CvvHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["CW", "CY"]
    }

    async fn handle(&self, command_code: &[u8], payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
        if command_code == b"CY" {
            handle_cy(payload, state).await
        } else {
            handle_cw(payload, state).await
        }
    }
}

async fn handle_cw(body: &[u8], state: &Arc<AppState>) -> HandlerResult {
    if body.len() < CW_MIN_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "CW payload too short: {} < {}", body.len(), CW_MIN_LEN
        )));
    }
    let mode = body[0];
    let cvk_id = String::from_utf8_lossy(&body[CVK_START..CVK_END]).to_string();
    let pan = String::from_utf8_lossy(&body[CW_PAN_START..CW_PAN_END]).to_string();
    let expiry = String::from_utf8_lossy(&body[CW_EXPIRY_START..CW_EXPIRY_END]).to_string();
    let service_code = String::from_utf8_lossy(&body[CW_SVC_START..CW_SVC_END]).to_string();

    let cvk_arn = match state.key_map.resolve(&cvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(cvk = %cvk_arn, mode = %(mode as char), "generate_card_validation_data");

    use aws_sdk_paymentcryptographydata::types::{
        CardGenerationAttributes, CardVerificationValue1, CardVerificationValue2,
    };

    let attrs: CardGenerationAttributes = match mode {
        b'0' => match CardVerificationValue1::builder()
            .card_expiry_date(&expiry)
            .service_code(&service_code)
            .build()
            .map_err(|e| ProxyError::ApcError(e.to_string()))
        {
            Ok(a) => CardGenerationAttributes::CardVerificationValue1(a),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        },
        b'1' => match CardVerificationValue2::builder()
            .card_expiry_date(&expiry)
            .build()
            .map_err(|e| ProxyError::ApcError(e.to_string()))
        {
            Ok(a) => CardGenerationAttributes::CardVerificationValue2(a),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        },
        b'2' => match CardVerificationValue1::builder()
            .card_expiry_date(&expiry)
            .service_code("999")
            .build()
            .map_err(|e| ProxyError::ApcError(e.to_string()))
        {
            // iCVV uses CVV1 algorithm with service code 999
            Ok(a) => CardGenerationAttributes::CardVerificationValue1(a),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        },
        other => return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            format!("unknown CW mode: {}", other as char)
        )),
    };

    match state
        .data
        .generate_card_validation_data()
        .key_identifier(&cvk_arn)
        .primary_account_number(&pan)
        .generation_attributes(attrs)
        .send()
        .await
    {
        Ok(resp) => HandlerResult::success(resp.validation_data().as_bytes().to_vec()),
        Err(e) => {
            warn!(?e, "generate_card_validation_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_cy(body: &[u8], state: &Arc<AppState>) -> HandlerResult {
    if body.len() < CY_MIN_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "CY payload too short: {} < {}", body.len(), CY_MIN_LEN
        )));
    }
    let mode = body[0];
    let cvk_id = String::from_utf8_lossy(&body[CVK_START..CVK_END]).to_string();
    let cvv_value = String::from_utf8_lossy(&body[CY_CVV_START..CY_CVV_END]).to_string();
    let pan = String::from_utf8_lossy(&body[CY_PAN_START..CY_PAN_END]).to_string();
    let expiry = String::from_utf8_lossy(&body[CY_EXPIRY_START..CY_EXPIRY_END]).to_string();
    let service_code = String::from_utf8_lossy(&body[CY_SVC_START..CY_SVC_END]).to_string();

    let cvk_arn = match state.key_map.resolve(&cvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(cvk = %cvk_arn, mode = %(mode as char), "verify_card_validation_data");

    use aws_sdk_paymentcryptographydata::types::{
        CardVerificationAttributes, CardVerificationValue1, CardVerificationValue2,
    };

    let attrs_result: Result<CardVerificationAttributes, ProxyError> = match mode {
        b'0' => CardVerificationValue1::builder()
            .card_expiry_date(&expiry)
            .service_code(&service_code)
            .build()
            .map(CardVerificationAttributes::CardVerificationValue1)
            .map_err(|e| ProxyError::ApcError(e.to_string())),
        b'1' => CardVerificationValue2::builder()
            .card_expiry_date(&expiry)
            .build()
            .map(CardVerificationAttributes::CardVerificationValue2)
            .map_err(|e| ProxyError::ApcError(e.to_string())),
        b'2' => CardVerificationValue1::builder()
            .card_expiry_date(&expiry)
            .service_code("999")
            .build()
            .map(CardVerificationAttributes::CardVerificationValue1)
            .map_err(|e| ProxyError::ApcError(e.to_string())),
        other => Err(ProxyError::MalformedPayload(format!("unknown CY mode: {}", other as char))),
    };
    let attrs = match attrs_result {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    match state
        .data
        .verify_card_validation_data()
        .key_identifier(&cvk_arn)
        .primary_account_number(&pan)
        .validation_data(&cvv_value)
        .verification_attributes(attrs)
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            warn!(?e, "verify_card_validation_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}
