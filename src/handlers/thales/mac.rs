use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::handlers::{AppState, Handler, HandlerResult};
use crate::error::ProxyError;

/// payShield MAC commands: C2/M6 (generate) and C4/M8 (verify).
///
/// C2/C4: X9.9/X9.19/AS2805 MAC (static MAC key)
/// M6/M8: Extended MAC including CMAC (static MAC key)
///
/// All four map to APC GenerateMac / VerifyMac.
///
/// Field layout:
///   [0]        mode         1 byte
///   [1..33]    MAC key      32 hex chars (key under LMK — mapped via key_map)
///   [33..37]   message len  4 hex chars (byte count of message, big-endian hex)
///   [37..]     message data variable hex chars
///   (C4/M8 append 8 hex chars of MAC to verify after the message)
///
/// C2 modes: '0'=ISO9797_ALGORITHM1, '1'=ISO9797_ALGORITHM3, '2'/'3'=AS2805_4_1
/// M6 modes: '1'=ISO9797_ALGORITHM1, '3'=ISO9797_ALGORITHM3, '6'=CMAC
pub struct MacHandler;

const MAC_KEY_START: usize = 1;
const MAC_KEY_END: usize = 33;
const MSG_LEN_START: usize = 33;
const MSG_LEN_END: usize = 37;
const MSG_DATA_START: usize = 37;
const MAC_HEX_LEN: usize = 8;

fn algorithm_from_mode_c2(mode: u8) -> Result<String, ProxyError> {
    match mode {
        b'0' => Ok("ISO9797_ALGORITHM1".to_string()),
        b'1' => Ok("ISO9797_ALGORITHM3".to_string()),
        b'2' | b'3' => Ok("AS2805_4_1".to_string()),
        other => Err(ProxyError::UnsupportedMacMode(format!("{}", other as char))),
    }
}

fn algorithm_from_mode_m6(mode: u8) -> Result<String, ProxyError> {
    match mode {
        b'1' => Ok("ISO9797_ALGORITHM1".to_string()),
        b'3' => Ok("ISO9797_ALGORITHM3".to_string()),
        b'6' => Ok("CMAC".to_string()),
        other => Err(ProxyError::UnsupportedMacMode(format!("{}", other as char))),
    }
}

struct MacFields {
    algorithm: String,
    key_id: String,
    message_hex: String,
    mac_to_verify: Option<String>,
}

fn parse_payload(payload: &[u8], is_m_series: bool, is_verify: bool) -> Result<MacFields, ProxyError> {
    if payload.len() < MSG_DATA_START {
        return Err(ProxyError::MalformedPayload(format!(
            "MAC payload too short: {}",
            payload.len()
        )));
    }
    let mode = payload[0];
    let algorithm = if is_m_series {
        algorithm_from_mode_m6(mode)?
    } else {
        algorithm_from_mode_c2(mode)?
    };
    let key_id = String::from_utf8_lossy(&payload[MAC_KEY_START..MAC_KEY_END]).to_string();
    let msg_len_hex = String::from_utf8_lossy(&payload[MSG_LEN_START..MSG_LEN_END]);
    let msg_byte_len = usize::from_str_radix(msg_len_hex.trim(), 16)
        .map_err(|_| ProxyError::MalformedPayload("bad message length hex".to_string()))?;
    let msg_end = MSG_DATA_START + msg_byte_len * 2;
    if payload.len() < msg_end {
        return Err(ProxyError::MalformedPayload(format!(
            "payload shorter than declared message: need {} got {}",
            msg_end,
            payload.len()
        )));
    }
    let message_hex = String::from_utf8_lossy(&payload[MSG_DATA_START..msg_end]).to_string();
    let mac_to_verify = if is_verify {
        if payload.len() < msg_end + MAC_HEX_LEN {
            return Err(ProxyError::MalformedPayload("missing MAC in verify command".to_string()));
        }
        Some(String::from_utf8_lossy(&payload[msg_end..msg_end + MAC_HEX_LEN]).to_string())
    } else {
        None
    };
    Ok(MacFields { algorithm, key_id, message_hex, mac_to_verify })
}

#[async_trait]
impl Handler for MacHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["C2", "C4", "M6", "M8"]
    }

    async fn handle(&self, command_code: &[u8], payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
        let is_m_series = matches!(command_code, b"M6" | b"M8");
        let is_verify = matches!(command_code, b"C4" | b"M8");

        let fields = match parse_payload(payload, is_m_series, is_verify) {
            Ok(f) => f,
            Err(e) => {
                warn!(?e, "MAC parse error");
                return HandlerResult::from_proxy_error(&e);
            }
        };

        let key_arn = match state.key_map.resolve(&fields.key_id) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };

        debug!(key = %key_arn, algo = %fields.algorithm, verify = is_verify, "MAC operation");

        use aws_sdk_paymentcryptographydata::types::{MacAlgorithm, MacAttributes};

        let algo = match fields.algorithm.as_str() {
            "ISO9797_ALGORITHM1" => MacAlgorithm::Iso9797Algorithm1,
            "ISO9797_ALGORITHM3" => MacAlgorithm::Iso9797Algorithm3,
            "CMAC" => MacAlgorithm::Cmac,
            "AS2805_4_1" => MacAlgorithm::As280541,
            other => return HandlerResult::from_proxy_error(
                &ProxyError::UnsupportedMacMode(other.to_string())
            ),
        };

        let mac_attrs = MacAttributes::Algorithm(algo);

        if is_verify {
            let mac_val = fields.mac_to_verify.unwrap();
            match state
                .data
                .verify_mac()
                .key_identifier(&key_arn)
                .message_data(&fields.message_hex)
                .mac(&mac_val)
                .verification_attributes(mac_attrs)
                .send()
                .await
            {
                Ok(_) => HandlerResult::success(vec![]),
                Err(e) => {
                    warn!(?e, "verify_mac failed");
                    HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
                }
            }
        } else {
            match state
                .data
                .generate_mac()
                .key_identifier(&key_arn)
                .message_data(&fields.message_hex)
                .generation_attributes(mac_attrs)
                .send()
                .await
            {
                Ok(resp) => HandlerResult::success(resp.mac().as_bytes().to_vec()),
                Err(e) => {
                    warn!(?e, "generate_mac failed");
                    HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
                }
            }
        }
    }
}
