use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::handlers::{AppState, Handler, HandlerResult};
use crate::error::ProxyError;

/// payShield PIN translation commands: CA, CC (static PEK) and CI, G0 (DUKPT).
///
/// All four map to APC TranslatePinData. CI/G0 additionally supply a KSN
/// for DUKPT key derivation.
///
/// Field layout:
///   [0]       source key type   1 byte  ('0'=TDES, '1'=AES)
///   [1]       dest key type     1 byte
///   [2..34]   source key        32 hex chars (LMK-encrypted key — mapped via key_map)
///   [34..66]  dest key          32 hex chars
///   [66..68]  max PIN length    2 decimal chars
///   [68..70]  source PIN format 2 chars ("00"=ISO0 … "04"=ISO4)
///   [70..72]  dest PIN format   2 chars
///   [72..88]  encrypted PIN block 16 hex chars  ← never logged
///   [88..100] account number    12 chars (rightmost 12 PAN excl check digit)
///   [100..120] KSN              20 hex chars (CI/G0 only)
///
/// NOTE: Field offsets sourced from EFTlab community reference. Validate against
/// the official Thales payShield Host Command Reference Manual before production use.
///
/// KNOWN GAP: APC TranslatePinData requires the full PAN, but payShield CA/CC
/// provide only the 12-char account number. The proxy passes this value as-is.
pub struct PinHandler;

const CA_MIN_LEN: usize = 100;
const KSN_HEX_LEN: usize = 20;

#[derive(Debug)]
struct PinFields {
    source_key_id: String,
    dest_key_id: String,
    source_format: String,
    dest_format: String,
    pin_block: Zeroizing<String>,
    account_number: String,
    ksn: Option<String>,
}

fn parse_ca_cc(payload: &[u8]) -> Result<PinFields, ProxyError> {
    if payload.len() < CA_MIN_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "CA/CC payload too short: {} < {}",
            payload.len(),
            CA_MIN_LEN
        )));
    }
    Ok(PinFields {
        source_key_id: String::from_utf8_lossy(&payload[2..34]).to_string(),
        dest_key_id: String::from_utf8_lossy(&payload[34..66]).to_string(),
        source_format: format_code_to_apc(&payload[68..70])?,
        dest_format: format_code_to_apc(&payload[70..72])?,
        pin_block: Zeroizing::new(String::from_utf8_lossy(&payload[72..88]).to_string()),
        account_number: String::from_utf8_lossy(&payload[88..100]).to_string(),
        ksn: None,
    })
}

fn parse_ci_g0(payload: &[u8]) -> Result<PinFields, ProxyError> {
    if payload.len() < CA_MIN_LEN + KSN_HEX_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "CI/G0 payload too short: {} < {}",
            payload.len(),
            CA_MIN_LEN + KSN_HEX_LEN
        )));
    }
    let mut fields = parse_ca_cc(payload)?;
    fields.ksn = Some(String::from_utf8_lossy(&payload[100..100 + KSN_HEX_LEN]).to_string());
    Ok(fields)
}

fn format_code_to_apc(code: &[u8]) -> Result<String, ProxyError> {
    match code {
        b"00" => Ok("IsoFormat0".to_string()),
        b"01" => Ok("IsoFormat1".to_string()),
        b"02" => Ok("IsoFormat2".to_string()),
        b"03" => Ok("IsoFormat3".to_string()),
        b"04" => Ok("IsoFormat4".to_string()),
        other => Err(ProxyError::UnsupportedPinFormat(
            String::from_utf8_lossy(other).to_string(),
        )),
    }
}

#[async_trait]
impl Handler for PinHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["CA", "CC", "CI", "G0"]
    }

    async fn handle(&self, command_code: &[u8], payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
        let is_dukpt = matches!(command_code, b"CI" | b"G0");

        let fields = if is_dukpt {
            match parse_ci_g0(payload) {
                Ok(f) => f,
                Err(e) => { warn!(?e, "CI/G0 parse error"); return HandlerResult::from_proxy_error(&e); }
            }
        } else {
            match parse_ca_cc(payload) {
                Ok(f) => f,
                Err(e) => { warn!(?e, "CA/CC parse error"); return HandlerResult::from_proxy_error(&e); }
            }
        };

        let incoming_arn = match state.key_map.resolve(&fields.source_key_id) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };
        let outgoing_arn = match state.key_map.resolve(&fields.dest_key_id) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };

        debug!(
            incoming = %incoming_arn,
            outgoing = %outgoing_arn,
            src_fmt = %fields.source_format,
            dst_fmt = %fields.dest_format,
            "translate_pin_data"
        );

        let incoming_attrs = build_translation_attrs(&fields.source_format, &fields.account_number);
        let outgoing_attrs = build_translation_attrs(&fields.dest_format, &fields.account_number);
        let (incoming_attrs, outgoing_attrs) = match (incoming_attrs, outgoing_attrs) {
            (Ok(i), Ok(o)) => (i, o),
            (Err(e), _) | (_, Err(e)) => return HandlerResult::from_proxy_error(&e),
        };

        let mut req = state
            .data
            .translate_pin_data()
            .incoming_key_identifier(&incoming_arn)
            .outgoing_key_identifier(&outgoing_arn)
            .encrypted_pin_block(fields.pin_block.as_str())
            .incoming_translation_attributes(incoming_attrs)
            .outgoing_translation_attributes(outgoing_attrs);

        if let Some(ksn) = &fields.ksn {
            use aws_sdk_paymentcryptographydata::types::DukptDerivationAttributes;
            req = req.incoming_dukpt_attributes(
                DukptDerivationAttributes::builder()
                    .key_serial_number(ksn)
                    .build()
                    .unwrap(),
            );
        }

        match req.send().await {
            Ok(resp) => {
                let pin_block_out = Zeroizing::new(resp.pin_block().to_string());
                let mut payload_out = pin_block_out.as_bytes().to_vec();
                payload_out.push(b'0');
                HandlerResult::success(payload_out)
            }
            Err(e) => {
                warn!(?e, "translate_pin_data failed");
                HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
            }
        }
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
