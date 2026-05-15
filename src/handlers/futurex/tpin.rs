use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::handlers::{AppState, Handler, HandlerResult};
use crate::error::ProxyError;
use crate::protocol::futurex::parse_params;

/// Futurex Excrypt TPIN — Translate PIN between two zone keys.
///
/// Maps to APC TranslatePinData.
///
/// Request parameters:
///   AW = PIN block format (see format_code_to_apc; command-scoped meaning — validate against
///        Futurex HSM Reference Manual before production use)
///   AX = inbound PEK (TR-31 key block value used as key_map lookup key, or APC ARN/alias)
///   BT = outbound PEK (same)
///   AL = encrypted PIN block (hex)  ← never logged
///   AK = account number (rightmost 12 digits of PAN excluding check digit)
///
/// Response parameters:
///   AL = translated PIN block (hex)
///   BB = status (Y = success, framed by FuturexExcrypt::frame_response)
///
/// Example (TR-31 key blocks):
///   Request:  [AOTPIN;AW1;AX<key_block>;BT<key_block>;AL<pin_block>;AK561237487695;]
///   Response: [AOTPIN;AL<pin_block>;BBY;]
///
/// MFK (3DES) is the primary live path. PMK (AES) requires AES-capable keys in APC.
pub struct TpinHandler;

#[async_trait]
impl Handler for TpinHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["TPIN"]
    }

    async fn handle(&self, _command_code: &[u8], payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
        let params = parse_params(payload);

        let aw = params.get(b"AW").and_then(|v| v.first().copied()).unwrap_or(b'0');
        let format = match format_code_to_apc(aw) {
            Ok(f) => f,
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };

        let incoming_key_raw = match params.get(b"AX") {
            Some(v) => String::from_utf8_lossy(v).to_string(),
            None => return HandlerResult::from_proxy_error(
                &ProxyError::MalformedPayload("TPIN missing AX (inbound key)".to_string())
            ),
        };
        let outgoing_key_raw = match params.get(b"BT") {
            Some(v) => String::from_utf8_lossy(v).to_string(),
            None => return HandlerResult::from_proxy_error(
                &ProxyError::MalformedPayload("TPIN missing BT (outbound key)".to_string())
            ),
        };
        let pin_block = match params.get(b"AL") {
            Some(v) => Zeroizing::new(String::from_utf8_lossy(v).to_string()),
            None => return HandlerResult::from_proxy_error(
                &ProxyError::MalformedPayload("TPIN missing AL (PIN block)".to_string())
            ),
        };
        let account_number = match params.get(b"AK") {
            Some(v) => String::from_utf8_lossy(v).to_string(),
            None => return HandlerResult::from_proxy_error(
                &ProxyError::MalformedPayload("TPIN missing AK (account number)".to_string())
            ),
        };

        let incoming_arn = match state.key_map.resolve(&incoming_key_raw) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };
        let outgoing_arn = match state.key_map.resolve(&outgoing_key_raw) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };

        debug!(
            incoming = %incoming_arn,
            outgoing = %outgoing_arn,
            fmt = %format,
            "TPIN: translate_pin_data"
        );

        let incoming_attrs = build_translation_attrs(&format, &account_number);
        let outgoing_attrs = build_translation_attrs(&format, &account_number);
        let (incoming_attrs, outgoing_attrs) = match (incoming_attrs, outgoing_attrs) {
            (Ok(i), Ok(o)) => (i, o),
            (Err(e), _) | (_, Err(e)) => return HandlerResult::from_proxy_error(&e),
        };

        match state
            .data
            .translate_pin_data()
            .incoming_key_identifier(&incoming_arn)
            .outgoing_key_identifier(&outgoing_arn)
            .encrypted_pin_block(pin_block.as_str())
            .incoming_translation_attributes(incoming_attrs)
            .outgoing_translation_attributes(outgoing_attrs)
            .send()
            .await
        {
            Ok(resp) => {
                let translated = Zeroizing::new(resp.pin_block().to_string());
                // Response payload: Futurex AL parameter carrying the output PIN block.
                // FuturexExcrypt::frame_response will wrap this in [AOTPIN;...;BBY;]
                let mut payload_out = b"AL".to_vec();
                payload_out.extend_from_slice(translated.as_bytes());
                payload_out.push(b';');
                HandlerResult::success(payload_out)
            }
            Err(e) => {
                warn!(?e, "TPIN: translate_pin_data failed");
                HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
            }
        }
    }
}

/// Map Futurex AW format byte to APC translation format name.
///
/// AW semantics are command-scoped in Excrypt. For TPIN:
///   '0' = ISO Format 0 (most common for acquiring — ANSI X9.8)
///   '1' = ISO Format 1
///   '3' = ISO Format 3
///   '4' = ISO Format 4
/// Validate mapping against Futurex HSM Reference Manual before production use.
fn format_code_to_apc(aw: u8) -> Result<String, ProxyError> {
    match aw {
        b'0' => Ok("IsoFormat0".to_string()),
        b'1' => Ok("IsoFormat1".to_string()),
        b'3' => Ok("IsoFormat3".to_string()),
        b'4' => Ok("IsoFormat4".to_string()),
        other => Err(ProxyError::UnsupportedPinFormat(
            format!("TPIN AW={}", other as char)
        )),
    }
}

fn build_translation_attrs(
    format: &str,
    account_number: &str,
) -> Result<aws_sdk_paymentcryptographydata::types::TranslationIsoFormats, ProxyError> {
    use aws_sdk_paymentcryptographydata::types::{
        TranslationIsoFormats, TranslationPinDataIsoFormat034, TranslationPinDataIsoFormat1,
    };
    match format {
        "IsoFormat0" => Ok(TranslationIsoFormats::IsoFormat0(
            TranslationPinDataIsoFormat034::builder()
                .primary_account_number(account_number)
                .build()
                .map_err(|e| ProxyError::ApcError(e.to_string()))?,
        )),
        "IsoFormat1" => Ok(TranslationIsoFormats::IsoFormat1(
            TranslationPinDataIsoFormat1::builder().build(),
        )),
        "IsoFormat3" => Ok(TranslationIsoFormats::IsoFormat3(
            TranslationPinDataIsoFormat034::builder()
                .primary_account_number(account_number)
                .build()
                .map_err(|e| ProxyError::ApcError(e.to_string()))?,
        )),
        "IsoFormat4" => Ok(TranslationIsoFormats::IsoFormat4(
            TranslationPinDataIsoFormat034::builder()
                .primary_account_number(account_number)
                .build()
                .map_err(|e| ProxyError::ApcError(e.to_string()))?,
        )),
        other => Err(ProxyError::UnsupportedPinFormat(other.to_string())),
    }
}
