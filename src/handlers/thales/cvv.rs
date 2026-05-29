use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield card verification commands.
///
/// CW (→ CX) — Generate CVV/CVV2/iCVV → APC GenerateCardValidationData
/// CY (→ CZ) — Verify  CVV/CVV2/iCVV → APC VerifyCardValidationData
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
///
/// NY (→ NZ) — Generate Static CVC3 and/or IVCVC3 (Mastercard contactless)
///              → APC GenerateCardValidationData
///
/// Source: PUGD0537-004 Rev A, p.493 — AUTHORITATIVE.
/// Wire format inferred from QY (dCVV) and CW (static CVV) patterns:
///   [0]        mode         1 byte  ('1'=Static CVC3, '2'=IVCVC3, '3'=both)
///   [1..33]    CVK          32 hex chars (double-length C0 key)
///   [33..49]   PAN          16 decimal chars
///   [49..53]   expiry       4 chars (MMYY)
///   [53..56]   service code 3 chars
///   [56..60]   ATC          4 hex chars (used for IVCVC3, modes 2/3)
///   [60..62]   PAN seq      2 decimal chars (used for IVCVC3, modes 2/3)
///
/// NZ response:
///   [2H]       error code
///   [3N]       Static CVC3  — modes '1' and '3'
///   [3N]       IVCVC3       — modes '2' and '3'
///
/// RY (→ RZ) — Calculate or Verify Card Security Codes (CVV2/CVC2)
///              → APC GenerateCardValidationData or VerifyCardValidationData
///
/// Source: PUGD0537-004 Rev A, p.315-316 — AUTHORITATIVE.
/// Wire format inferred (generate vs verify selected by mode byte):
///
/// Generate (mode '0'):
///   [0]        mode         '0'
///   [1..33]    CVK          32 hex chars
///   [33..49]   PAN          16 decimal chars
///   [49..53]   expiry       4 chars (MMYY)
///
/// Verify (mode '1'):
///   [0]        mode         '1'
///   [1..33]    CVK          32 hex chars
///   [33..36]   CVV2 value   3 decimal chars
///   [36..52]   PAN          16 decimal chars
///   [52..56]   expiry       4 chars (MMYY)
///
/// KNOWN LIMITATION: RY covers Mastercard CVC2, Visa CVV2, and Amex CID.
/// This handler maps to CardVerificationValue2 (CVV2/CVC2 algorithm). Amex CID
/// requires AmexCardSecurityCodeVersion1 and is not distinguished from CVV2 by
/// the wire format alone; if the key_map routes an Amex CVK here the APC call
/// will fail with error 41 (key usage mismatch).
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

// NY field offsets (inferred wire format)
const NY_CVK_LEN: usize = 32;
const NY_PAN_LEN: usize = 16;
const NY_EXPIRY_LEN: usize = 4;
const NY_SVC_LEN: usize = 3;
const NY_ATC_LEN: usize = 4;
const NY_PANSEQ_LEN: usize = 2;
const NY_MIN_LEN: usize =
    1 + NY_CVK_LEN + NY_PAN_LEN + NY_EXPIRY_LEN + NY_SVC_LEN + NY_ATC_LEN + NY_PANSEQ_LEN; // 62

// RY field sizes (inferred wire format)
const RY_CVK_LEN: usize = 32;
const RY_PAN_LEN: usize = 16;
const RY_EXPIRY_LEN: usize = 4;
const RY_CVV_LEN: usize = 3;
const RY_GEN_MIN_LEN: usize = 1 + RY_CVK_LEN + RY_PAN_LEN + RY_EXPIRY_LEN; // 53
const RY_VER_MIN_LEN: usize = 1 + RY_CVK_LEN + RY_CVV_LEN + RY_PAN_LEN + RY_EXPIRY_LEN; // 56

#[async_trait]
impl Handler for CvvHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["CW", "CY", "NY", "RY"]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        match command_code {
            b"CY" => handle_cy(payload, state).await,
            b"NY" => handle_ny(payload, state).await,
            b"RY" => handle_ry(payload, state).await,
            _ => handle_cw(payload, state).await,
        }
    }
}

async fn handle_cw(body: &[u8], state: &Arc<AppState>) -> HandlerResult {
    if body.len() < CW_MIN_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "CW payload too short: {} < {}",
            body.len(),
            CW_MIN_LEN
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
        other => {
            return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
                "unknown CW mode: {}",
                other as char
            )))
        }
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
            "CY payload too short: {} < {}",
            body.len(),
            CY_MIN_LEN
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
        other => Err(ProxyError::MalformedPayload(format!(
            "unknown CY mode: {}",
            other as char
        ))),
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
            if e.as_service_error().is_some_and(aws_sdk_paymentcryptographydata::operation::verify_card_validation_data::VerifyCardValidationDataError::is_verification_failed_exception) {
                warn!("verify_card_validation_data: CVV mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "verify_card_validation_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

// ── NY: Generate Static CVC3 and/or IVCVC3 ──────────────────────────────────

async fn handle_ny(body: &[u8], state: &Arc<AppState>) -> HandlerResult {
    if body.len() < NY_MIN_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "NY payload too short: {} < {}",
            body.len(),
            NY_MIN_LEN
        )));
    }
    let mode = body[0];
    if !matches!(mode, b'1' | b'2' | b'3') {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "NY: invalid mode '{}' (1=Static, 2=IVCVC3, 3=both)",
            mode as char
        )));
    }

    let mut pos = 1;
    let cvk_id = String::from_utf8_lossy(&body[pos..pos + NY_CVK_LEN]).to_string();
    pos += NY_CVK_LEN;
    let pan = String::from_utf8_lossy(&body[pos..pos + NY_PAN_LEN]).to_string();
    pos += NY_PAN_LEN;
    let expiry = String::from_utf8_lossy(&body[pos..pos + NY_EXPIRY_LEN]).to_string();
    pos += NY_EXPIRY_LEN;
    let service_code = String::from_utf8_lossy(&body[pos..pos + NY_SVC_LEN]).to_string();
    pos += NY_SVC_LEN;
    let atc = String::from_utf8_lossy(&body[pos..pos + NY_ATC_LEN]).to_string();
    pos += NY_ATC_LEN;
    let pan_seq = String::from_utf8_lossy(&body[pos..pos + NY_PANSEQ_LEN]).to_string();

    let cvk_arn = match state.key_map.resolve(&cvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        CardGenerationAttributes, CardVerificationValue1, DynamicCardVerificationValue,
    };

    let mut response_payload: Vec<u8> = Vec::new();

    // Static CVC3 (modes 1 and 3): CVV1 algorithm with the card's actual service code
    if matches!(mode, b'1' | b'3') {
        let static_attrs = match CardVerificationValue1::builder()
            .card_expiry_date(&expiry)
            .service_code(&service_code)
            .build()
            .map_err(|e| ProxyError::ApcError(e.to_string()))
        {
            Ok(a) => CardGenerationAttributes::CardVerificationValue1(a),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };
        debug!(cvk = %cvk_arn, "NY: generate Static CVC3");
        match state
            .data
            .generate_card_validation_data()
            .key_identifier(&cvk_arn)
            .primary_account_number(&pan)
            .generation_attributes(static_attrs)
            .send()
            .await
        {
            Ok(resp) => response_payload.extend_from_slice(resp.validation_data().as_bytes()),
            Err(e) => {
                warn!(?e, "NY: generate Static CVC3 failed");
                return HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()));
            }
        }
    }

    // IVCVC3 (modes 2 and 3): dynamic card verification value with ATC
    if matches!(mode, b'2' | b'3') {
        let ivcvc3_attrs = match DynamicCardVerificationValue::builder()
            .pan_sequence_number(&pan_seq)
            .card_expiry_date(&expiry)
            .service_code(&service_code)
            .application_transaction_counter(&atc)
            .build()
            .map_err(|e| ProxyError::ApcError(e.to_string()))
        {
            Ok(a) => CardGenerationAttributes::DynamicCardVerificationValue(a),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };
        debug!(cvk = %cvk_arn, atc = %atc, "NY: generate IVCVC3");
        match state
            .data
            .generate_card_validation_data()
            .key_identifier(&cvk_arn)
            .primary_account_number(&pan)
            .generation_attributes(ivcvc3_attrs)
            .send()
            .await
        {
            Ok(resp) => response_payload.extend_from_slice(resp.validation_data().as_bytes()),
            Err(e) => {
                warn!(?e, "NY: generate IVCVC3 failed");
                return HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()));
            }
        }
    }

    HandlerResult::success(response_payload)
}

// ── RY: Calculate or Verify Card Security Codes (CVV2/CVC2) ─────────────────

async fn handle_ry(body: &[u8], state: &Arc<AppState>) -> HandlerResult {
    if body.is_empty() {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "RY: empty payload".into(),
        ));
    }
    let mode = body[0];
    match mode {
        b'0' => handle_ry_generate(body, state).await,
        b'1' => handle_ry_verify(body, state).await,
        other => HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "RY: invalid mode '{}' (0=generate, 1=verify)",
            other as char
        ))),
    }
}

async fn handle_ry_generate(body: &[u8], state: &Arc<AppState>) -> HandlerResult {
    if body.len() < RY_GEN_MIN_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "RY generate: payload too short: {} < {}",
            body.len(),
            RY_GEN_MIN_LEN
        )));
    }
    let mut pos = 1;
    let cvk_id = String::from_utf8_lossy(&body[pos..pos + RY_CVK_LEN]).to_string();
    pos += RY_CVK_LEN;
    let pan = String::from_utf8_lossy(&body[pos..pos + RY_PAN_LEN]).to_string();
    pos += RY_PAN_LEN;
    let expiry = String::from_utf8_lossy(&body[pos..pos + RY_EXPIRY_LEN]).to_string();

    let cvk_arn = match state.key_map.resolve(&cvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        CardGenerationAttributes, CardVerificationValue2,
    };

    let attrs = match CardVerificationValue2::builder()
        .card_expiry_date(&expiry)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => CardGenerationAttributes::CardVerificationValue2(a),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(cvk = %cvk_arn, "RY: generate_card_validation_data CVV2");
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
            warn!(?e, "RY: generate_card_validation_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_ry_verify(body: &[u8], state: &Arc<AppState>) -> HandlerResult {
    if body.len() < RY_VER_MIN_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "RY verify: payload too short: {} < {}",
            body.len(),
            RY_VER_MIN_LEN
        )));
    }
    let mut pos = 1;
    let cvk_id = String::from_utf8_lossy(&body[pos..pos + RY_CVK_LEN]).to_string();
    pos += RY_CVK_LEN;
    let cvv_value = String::from_utf8_lossy(&body[pos..pos + RY_CVV_LEN]).to_string();
    pos += RY_CVV_LEN;
    let pan = String::from_utf8_lossy(&body[pos..pos + RY_PAN_LEN]).to_string();
    pos += RY_PAN_LEN;
    let expiry = String::from_utf8_lossy(&body[pos..pos + RY_EXPIRY_LEN]).to_string();

    let cvk_arn = match state.key_map.resolve(&cvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        CardVerificationAttributes, CardVerificationValue2,
    };

    let attrs = match CardVerificationValue2::builder()
        .card_expiry_date(&expiry)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => CardVerificationAttributes::CardVerificationValue2(a),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(cvk = %cvk_arn, "RY: verify_card_validation_data CVV2");
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
            if e.as_service_error().is_some_and(
                aws_sdk_paymentcryptographydata::operation::verify_card_validation_data::VerifyCardValidationDataError::is_verification_failed_exception,
            ) {
                warn!("RY: CVV2 mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "RY: verify_card_validation_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}
