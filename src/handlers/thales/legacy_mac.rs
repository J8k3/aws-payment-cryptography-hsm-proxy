use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_legacy_key;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield legacy TAK-based MAC commands: MA/MB (generate), MC/MD (verify), ME/MF (verify+translate).
///
/// Key slot: Terminal Authentication Key (TAK) encrypted under LMK pair 16-17.
/// Algorithm: ANSI X9.9 with zero padding → APC ISO9797_ALGORITHM1.
/// These commands are superseded by M6/M8/MY but remain in wide use.
///
/// MA field layout:
///   [0..key_len]       TAK (LMK 16-17): 16H | 'U'+32H | 'T'+48H
///   [key_len..]        Data (raw bytes, terminated by '~' or end of payload)
///
/// MC field layout:
///   [0..key_len]       TAK (LMK 16-17): variable-length
///   [key_len..+8]      MAC to verify (8H)
///   [key_len+8..]      Data (raw bytes, terminated by '~' or end of payload)
///
/// ME field layout:
///   [0..src_len]       Source TAK (LMK 16-17): variable-length  — used to verify
///   [src_len..+dst_len] Destination TAK (LMK 16-17): variable-length — used to generate
///   [src+dst..+8]      MAC to verify (8H)
///   [src+dst+8..]      Data (raw bytes, terminated by '~' or end of payload)
///
/// Data is raw bytes in the payShield frame (not hex-encoded); the proxy hex-encodes
/// it before passing to APC.
///
/// KNOWN GAP: The spec states MAC response field as 8H (8 hex chars = 4 bytes).
/// X9.9 produces a full 8-byte MAC; APC returns 16 hex chars. Whether payShield truncates
/// to 4 bytes or "8H" means 8 bytes has not been validated against hardware.
pub struct LegacyTakMacHandler;

const MAC_HEX_LEN: usize = 8;

fn data_slice(payload: &[u8], start: usize) -> &[u8] {
    let end = payload[start..]
        .iter()
        .position(|&b| b == b'~')
        .map(|i| start + i)
        .unwrap_or(payload.len());
    &payload[start..end]
}

#[async_trait]
impl Handler for LegacyTakMacHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["MA", "MC", "ME"]
    }

    async fn handle(&self, command_code: &[u8], payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
        match command_code {
            b"MA" => handle_ma(payload, state).await,
            b"MC" => handle_mc(payload, state).await,
            b"ME" => handle_me(payload, state).await,
            _ => HandlerResult::err(b"68"),
        }
    }
}

async fn handle_ma(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (key_id, key_len) = match parse_legacy_key(payload, 0) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let data_hex = hex::encode(data_slice(payload, key_len));
    let key_arn = match state.key_map.resolve(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{MacAlgorithm, MacAttributes};

    debug!(key = %key_arn, "MA: generate_mac ISO9797_ALGORITHM1");

    match state
        .data
        .generate_mac()
        .key_identifier(&key_arn)
        .message_data(&data_hex)
        .generation_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm1))
        .send()
        .await
    {
        Ok(resp) => HandlerResult::success(resp.mac().as_bytes().to_vec()),
        Err(e) => {
            warn!(?e, "MA: generate_mac failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_mc(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (key_id, key_len) = match parse_legacy_key(payload, 0) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    if payload.len() < key_len + MAC_HEX_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "MC: payload too short for MAC field".to_string(),
        ));
    }
    let mac_val = String::from_utf8_lossy(&payload[key_len..key_len + MAC_HEX_LEN]).to_string();
    let data_hex = hex::encode(data_slice(payload, key_len + MAC_HEX_LEN));
    let key_arn = match state.key_map.resolve(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{MacAlgorithm, MacAttributes};

    debug!(key = %key_arn, "MC: verify_mac ISO9797_ALGORITHM1");

    match state
        .data
        .verify_mac()
        .key_identifier(&key_arn)
        .message_data(&data_hex)
        .mac(&mac_val)
        .verification_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm1))
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error()
                .map(|s| s.is_verification_failed_exception())
                .unwrap_or(false)
            {
                warn!("MC: MAC mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "MC: verify_mac failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_me(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (src_key_id, src_len) = match parse_legacy_key(payload, 0) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let (dst_key_id, dst_len) = match parse_legacy_key(payload, src_len) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let mac_start = src_len + dst_len;
    if payload.len() < mac_start + MAC_HEX_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "ME: payload too short for MAC field".to_string(),
        ));
    }
    let mac_val = String::from_utf8_lossy(&payload[mac_start..mac_start + MAC_HEX_LEN]).to_string();
    let data_hex = hex::encode(data_slice(payload, mac_start + MAC_HEX_LEN));

    let src_arn = match state.key_map.resolve(&src_key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let dst_arn = match state.key_map.resolve(&dst_key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{MacAlgorithm, MacAttributes};

    debug!(src = %src_arn, dst = %dst_arn, "ME: verify_mac then generate_mac");

    match state
        .data
        .verify_mac()
        .key_identifier(&src_arn)
        .message_data(&data_hex)
        .mac(&mac_val)
        .verification_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm1))
        .send()
        .await
    {
        Ok(_) => {}
        Err(e) => {
            if e.as_service_error()
                .map(|s| s.is_verification_failed_exception())
                .unwrap_or(false)
            {
                warn!("ME: MAC mismatch on verify step");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "ME: verify_mac failed");
            return HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()));
        }
    }

    match state
        .data
        .generate_mac()
        .key_identifier(&dst_arn)
        .message_data(&data_hex)
        .generation_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm1))
        .send()
        .await
    {
        Ok(resp) => HandlerResult::success(resp.mac().as_bytes().to_vec()),
        Err(e) => {
            warn!(?e, "ME: generate_mac failed after verify succeeded");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_single_key() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec()
    }

    fn make_double_key() -> Vec<u8> {
        let mut v = vec![b'U'];
        v.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        v
    }

    #[test]
    fn data_slice_stops_at_tilde() {
        let payload = b"KEYDATAhello~extra~stuff";
        // start at offset 3 (after "KEY")
        let slice = data_slice(payload, 3);
        assert_eq!(slice, b"DATAhello");
    }

    #[test]
    fn data_slice_returns_all_when_no_tilde() {
        let payload = b"KEYdata";
        let slice = data_slice(payload, 3);
        assert_eq!(slice, b"data");
    }

    #[test]
    fn data_slice_empty_at_tilde() {
        let payload = b"KEY~rest";
        let slice = data_slice(payload, 3);
        assert_eq!(slice, b"");
    }

    #[test]
    fn ma_parse_single_key_extracts_data() {
        let mut payload = make_single_key();
        payload.extend_from_slice(b"MESSAGEDATA");
        let (_key_id, key_len) = parse_legacy_key(&payload, 0).unwrap();
        assert_eq!(key_len, 16);
        let data = data_slice(&payload, key_len);
        assert_eq!(hex::encode(data), hex::encode(b"MESSAGEDATA"));
    }

    #[test]
    fn mc_parse_extracts_mac_and_data() {
        let mut payload = make_double_key();
        payload.extend_from_slice(b"AABBCCDD"); // 8-char MAC
        payload.extend_from_slice(b"MSGBYTES");
        let (_key_id, key_len) = parse_legacy_key(&payload, 0).unwrap();
        assert_eq!(key_len, 33);
        let mac = String::from_utf8_lossy(&payload[key_len..key_len + MAC_HEX_LEN]);
        assert_eq!(mac, "AABBCCDD");
        let data = data_slice(&payload, key_len + MAC_HEX_LEN);
        assert_eq!(data, b"MSGBYTES");
    }

    #[test]
    fn mc_too_short_for_mac() {
        let payload = make_single_key(); // no MAC field after key
        let (_key_id, key_len) = parse_legacy_key(&payload, 0).unwrap();
        assert!(payload.len() < key_len + MAC_HEX_LEN);
    }

    #[test]
    fn me_parse_two_keys_then_mac_and_data() {
        let mut payload = make_single_key(); // src TAK
        payload.extend_from_slice(&make_single_key()); // dst TAK
        payload.extend_from_slice(b"11223344"); // MAC
        payload.extend_from_slice(b"PAYLOAD");
        let (_src, src_len) = parse_legacy_key(&payload, 0).unwrap();
        let (_dst, dst_len) = parse_legacy_key(&payload, src_len).unwrap();
        let mac_start = src_len + dst_len;
        let mac = &payload[mac_start..mac_start + MAC_HEX_LEN];
        assert_eq!(mac, b"11223344");
        let data = data_slice(&payload, mac_start + MAC_HEX_LEN);
        assert_eq!(data, b"PAYLOAD");
    }
}
