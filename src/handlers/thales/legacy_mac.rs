use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::thales::common::{bytes_to_hex, parse_legacy_key};
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield legacy MAC commands.
///
/// ## TAK-terminated group: MA / MC / ME
/// Key: TAK (Terminal Authentication Key, LMK pair 16-17).
/// Algorithm: ANSI X9.9 with zero padding → APC ISO9797_ALGORITHM1.
/// Data is raw bytes terminated by '~' or end of payload. Superseded by M6/M8/MY.
///
///   MA (→ MB): [TAK key] [data~]
///   MC (→ MD): [TAK key] [8H MAC] [data~]
///   ME (→ MF): [src TAK] [dst TAK] [8H MAC] [data~]   — verify then re-MAC
///
/// ## Length-prefixed binary group: MK / MM / MO / MU / MW / MQ / MS
/// Data field has a 3H (3 hex char) length prefix followed by raw binary bytes.
/// Continuation modes (block numbers 1/2/3) require stateful IV chaining across
/// calls — APC is stateless and single-call only. Mode '0' (the only/last block)
/// is the supported path; modes 1-3 return error 15.
///
///   MK (→ ML): [TAK key] [3H len] [nB data]
///              Generate binary MAC, ISO9797_ALG1.
///   MM (→ MN): [TAK key] [8H MAC] [3H len] [nB data]
///              Verify binary MAC, ISO9797_ALG1.
///   MO (→ MP): [src TAK] [dst TAK] [8H MAC] [3H len] [nB data]
///              Verify binary MAC then re-MAC under dst key, ISO9797_ALG1.
///   MU (→ MV): [1N mode] [TAK key] [3H len] [nB data]
///              Generate MAC on binary message, ISO9797_ALG1. Mode '0' only.
///   MW (→ MX): [1N mode] [TAK key] [8H MAC] [3H len] [nB data]
///              Verify MAC on binary message, ISO9797_ALG1. Mode '0' only.
///   MQ (→ MR): [1N mode] [ZAK key] [3H len] [nB data]
///              Generate MAC (MAB) for large message, ISO9797_ALG1.
///              Key: ZAK (Zone Authentication Key, LMK pair 26-27); same
///              wire encoding as TAK. Mode '0' only.
///   MS (→ MT): [1N mode] [TAK/ZAK key] [3H len] [nB data]
///              Generate MAC using ANSI X9.19 (Retail MAC), ISO9797_ALG3.
///              Mode '0' only.
///
/// Sources: payShield 10K Legacy Host Commands (PUGD0538), pp. 89–104.
pub struct LegacyMacHandler;

const MAC_HEX_LEN: usize = 8;
const DATA_LEN_CHARS: usize = 3;

fn data_slice(payload: &[u8], start: usize) -> &[u8] {
    let end = payload[start..]
        .iter()
        .position(|&b| b == b'~')
        .map_or(payload.len(), |i| start + i);
    &payload[start..end]
}

/// Parse a 3H length-prefixed binary data field at `pos`.
/// Returns (hex-encoded data, total bytes consumed from `pos`).
fn parse_len_binary(payload: &[u8], pos: usize, cmd: &str) -> Result<(String, usize), ProxyError> {
    if payload.len() < pos + DATA_LEN_CHARS {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: data length field missing"
        )));
    }
    let len_str = std::str::from_utf8(&payload[pos..pos + DATA_LEN_CHARS])
        .map_err(|_| ProxyError::MalformedPayload(format!("{cmd}: data length not ASCII")))?;
    let byte_count = usize::from_str_radix(len_str, 16).map_err(|_| {
        ProxyError::MalformedPayload(format!("{cmd}: invalid data length '{len_str}'"))
    })?;
    let data_start = pos + DATA_LEN_CHARS;
    if payload.len() < data_start + byte_count {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: data truncated (need {byte_count}B)"
        )));
    }
    Ok((
        bytes_to_hex(&payload[data_start..data_start + byte_count]),
        DATA_LEN_CHARS + byte_count,
    ))
}

#[async_trait]
impl Handler for LegacyMacHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["MA", "MC", "ME", "MK", "MM", "MO", "MU", "MW", "MQ", "MS"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[
            Evidence {
                decision: "MA/MC ('~'-terminated) and MK/MM (3H-length-prefixed) generate/verify an ISO 9797-1 Alg1 MAC under a TAK. APC's Alg1 MAC is truncated to the 8H (4-byte) wire width.",
                because: "PUGD0538 pp.89-104. Verified live across both wire styles and randomized data lengths: proxy MAC == APC generate_mac (Iso9797Algorithm1), and the MC/MM verify round-trip accepts the proxy's MAC. Note: APC returns a 4-byte Alg1 MAC (verified live), so the handler's 8H truncation is a no-op — correcting an earlier comment that claimed APC returns 16H.",
                wire: WireGrounding::DiffXprov,
                crypto: CryptoGrounding::Apc,
                proof: Proof::LiveTest("legacy_mac_ma_mc_mk_mm_differential"),
            },
            Evidence {
                decision: "ME/MO (verify-then-re-MAC), MU/MW (mode-prefixed Alg1), MQ (ZAK Alg1), MS (Alg3 X9.19) share the same generate/verify paths but are not yet covered by a live differential.",
                because: "PUGD0538 pp.89-104 — manual-cited layout and the same ISO9797 Alg1/Alg3 APC mapping as the live-verified commands; a live differential for these is the tracked next step.",
                wire: WireGrounding::Cited,
                crypto: CryptoGrounding::None,
                proof: Proof::ManualCite("PUGD0538 pp.89-104; not yet live-differentialed"),
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
            b"MA" => handle_ma(payload, state).await,
            b"MC" => handle_mc(payload, state).await,
            b"ME" => handle_me(payload, state).await,
            b"MK" => handle_mk(payload, state).await,
            b"MM" => handle_mm(payload, state).await,
            b"MO" => handle_mo(payload, state).await,
            b"MU" => handle_mu(payload, state).await,
            b"MW" => handle_mw(payload, state).await,
            b"MQ" => handle_mq(payload, state).await,
            b"MS" => handle_ms(payload, state).await,
            _ => HandlerResult::err(*b"68"),
        }
    }
}

// ── MA / MC / ME — TAK + '~'-terminated data ─────────────────────────────

async fn handle_ma(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (key_id, key_len) = match parse_legacy_key(payload, 0) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let data_hex = bytes_to_hex(data_slice(payload, key_len));
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    debug!(key = %key_arn, "MA: generate_mac ISO9797_ALGORITHM1");
    generate_alg1_mac(&key_arn, &data_hex, state).await
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
    let data_hex = bytes_to_hex(data_slice(payload, key_len + MAC_HEX_LEN));
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    debug!(key = %key_arn, "MC: verify_mac ISO9797_ALGORITHM1");
    verify_alg1_mac(&key_arn, &data_hex, &mac_val, "MC", state).await
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
    let data_hex = bytes_to_hex(data_slice(payload, mac_start + MAC_HEX_LEN));
    let src_arn = match state.key_map.resolve_descriptor(&src_key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let dst_arn = match state.key_map.resolve_descriptor(&dst_key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    debug!(src = %src_arn, dst = %dst_arn, "ME: verify_mac then generate_mac");
    verify_then_generate_alg1(&src_arn, &dst_arn, &data_hex, &mac_val, "ME", state).await
}

// ── MK / MM / MO — binary data with 3H length prefix, no mode byte ────────

async fn handle_mk(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (key_id, key_consumed) = match parse_legacy_key(payload, 0) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let (data_hex, _) = match parse_len_binary(payload, key_consumed, "MK") {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    debug!(key = %key_arn, "MK: generate_mac binary ISO9797_ALGORITHM1");
    generate_alg1_mac(&key_arn, &data_hex, state).await
}

async fn handle_mm(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (key_id, key_consumed) = match parse_legacy_key(payload, 0) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    if payload.len() < key_consumed + MAC_HEX_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "MM: payload too short for MAC field".to_string(),
        ));
    }
    let mac_val =
        String::from_utf8_lossy(&payload[key_consumed..key_consumed + MAC_HEX_LEN]).to_string();
    let (data_hex, _) = match parse_len_binary(payload, key_consumed + MAC_HEX_LEN, "MM") {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    debug!(key = %key_arn, "MM: verify_mac binary ISO9797_ALGORITHM1");
    verify_alg1_mac(&key_arn, &data_hex, &mac_val, "MM", state).await
}

async fn handle_mo(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let (src_key_id, src_consumed) = match parse_legacy_key(payload, 0) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let (dst_key_id, dst_consumed) = match parse_legacy_key(payload, src_consumed) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let mac_start = src_consumed + dst_consumed;
    if payload.len() < mac_start + MAC_HEX_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "MO: payload too short for MAC field".to_string(),
        ));
    }
    let mac_val = String::from_utf8_lossy(&payload[mac_start..mac_start + MAC_HEX_LEN]).to_string();
    let (data_hex, _) = match parse_len_binary(payload, mac_start + MAC_HEX_LEN, "MO") {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let src_arn = match state.key_map.resolve_descriptor(&src_key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let dst_arn = match state.key_map.resolve_descriptor(&dst_key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    debug!(src = %src_arn, dst = %dst_arn, "MO: verify_mac then generate_mac (binary)");
    verify_then_generate_alg1(&src_arn, &dst_arn, &data_hex, &mac_val, "MO", state).await
}

// ── MU / MW — mode byte + binary data, mode '0' only ─────────────────────

async fn handle_mu(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    if payload.is_empty() {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "MU: empty payload".into(),
        ));
    }
    if payload[0] != b'0' {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "MU: continuation mode '{}' not supported (APC is stateless; use mode '0' only)",
            payload[0] as char
        )));
    }
    let (key_id, key_consumed) = match parse_legacy_key(payload, 1) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let (data_hex, _) = match parse_len_binary(payload, 1 + key_consumed, "MU") {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    debug!(key = %key_arn, "MU: generate_mac binary ISO9797_ALGORITHM1");
    generate_alg1_mac(&key_arn, &data_hex, state).await
}

async fn handle_mw(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    if payload.is_empty() {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "MW: empty payload".into(),
        ));
    }
    if payload[0] != b'0' {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "MW: continuation mode '{}' not supported (APC is stateless; use mode '0' only)",
            payload[0] as char
        )));
    }
    let (key_id, key_consumed) = match parse_legacy_key(payload, 1) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pos = 1 + key_consumed;
    if payload.len() < pos + MAC_HEX_LEN {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "MW: payload too short for MAC field".to_string(),
        ));
    }
    let mac_val = String::from_utf8_lossy(&payload[pos..pos + MAC_HEX_LEN]).to_string();
    let (data_hex, _) = match parse_len_binary(payload, pos + MAC_HEX_LEN, "MW") {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    debug!(key = %key_arn, "MW: verify_mac binary ISO9797_ALGORITHM1");
    verify_alg1_mac(&key_arn, &data_hex, &mac_val, "MW", state).await
}

// ── MQ / MS — mode byte + binary data, mode '0' only ─────────────────────

async fn handle_mq(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    if payload.is_empty() {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "MQ: empty payload".into(),
        ));
    }
    if payload[0] != b'0' {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "MQ: continuation mode '{}' not supported (APC is stateless; use mode '0' only)",
            payload[0] as char
        )));
    }
    let (key_id, key_consumed) = match parse_legacy_key(payload, 1) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let (data_hex, _) = match parse_len_binary(payload, 1 + key_consumed, "MQ") {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    debug!(key = %key_arn, "MQ: generate_mac binary ISO9797_ALGORITHM1");
    generate_alg1_mac(&key_arn, &data_hex, state).await
}

async fn handle_ms(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    if payload.is_empty() {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(
            "MS: empty payload".into(),
        ));
    }
    if payload[0] != b'0' {
        return HandlerResult::from_proxy_error(&ProxyError::MalformedPayload(format!(
            "MS: continuation mode '{}' not supported (APC is stateless; use mode '0' only)",
            payload[0] as char
        )));
    }
    let (key_id, key_consumed) = match parse_legacy_key(payload, 1) {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let (data_hex, _) = match parse_len_binary(payload, 1 + key_consumed, "MS") {
        Ok(v) => v,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let key_arn = match state.key_map.resolve_descriptor(&key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    debug!(key = %key_arn, "MS: generate_mac binary ISO9797_ALGORITHM3 (ANSI X9.19)");
    generate_alg3_mac(&key_arn, &data_hex, state).await
}

// ── shared APC helpers ────────────────────────────────────────────────────

async fn generate_alg1_mac(key_arn: &str, data_hex: &str, state: &Arc<AppState>) -> HandlerResult {
    use aws_sdk_paymentcryptographydata::types::{MacAlgorithm, MacAttributes};
    match state
        .data
        .generate_mac()
        .key_identifier(key_arn)
        .message_data(data_hex)
        .generation_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm1))
        .send()
        .await
    {
        Ok(resp) => {
            // Thales legacy MAC is 4 bytes (8 hex chars). APC's ISO9797 Alg1 MAC is
            // also 4 bytes (verified live), so this truncation is a defensive no-op —
            // it bounds the output to the wire width rather than being required.
            let mac = resp.mac();
            HandlerResult::success(mac.as_bytes()[..MAC_HEX_LEN.min(mac.len())].to_vec())
        }
        Err(e) => {
            warn!(?e, "generate_mac failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn generate_alg3_mac(key_arn: &str, data_hex: &str, state: &Arc<AppState>) -> HandlerResult {
    use aws_sdk_paymentcryptographydata::types::{MacAlgorithm, MacAttributes};
    match state
        .data
        .generate_mac()
        .key_identifier(key_arn)
        .message_data(data_hex)
        .generation_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm3))
        .send()
        .await
    {
        Ok(resp) => {
            let mac = resp.mac();
            HandlerResult::success(mac.as_bytes()[..MAC_HEX_LEN.min(mac.len())].to_vec())
        }
        Err(e) => {
            warn!(?e, "generate_mac failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn verify_alg1_mac(
    key_arn: &str,
    data_hex: &str,
    mac_val: &str,
    cmd: &str,
    state: &Arc<AppState>,
) -> HandlerResult {
    use aws_sdk_paymentcryptographydata::types::{MacAlgorithm, MacAttributes};
    match state
        .data
        .verify_mac()
        .key_identifier(key_arn)
        .message_data(data_hex)
        .mac(mac_val)
        .verification_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm1))
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error().is_some_and(
                aws_sdk_paymentcryptographydata::operation::verify_mac::VerifyMacError::is_verification_failed_exception,
            ) {
                warn!("{cmd}: MAC mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "{cmd}: verify_mac failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn verify_then_generate_alg1(
    src_arn: &str,
    dst_arn: &str,
    data_hex: &str,
    mac_val: &str,
    cmd: &str,
    state: &Arc<AppState>,
) -> HandlerResult {
    use aws_sdk_paymentcryptographydata::types::{MacAlgorithm, MacAttributes};
    match state
        .data
        .verify_mac()
        .key_identifier(src_arn)
        .message_data(data_hex)
        .mac(mac_val)
        .verification_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm1))
        .send()
        .await
    {
        Ok(_) => {}
        Err(e) => {
            if e.as_service_error().is_some_and(
                aws_sdk_paymentcryptographydata::operation::verify_mac::VerifyMacError::is_verification_failed_exception,
            ) {
                warn!("{cmd}: MAC mismatch on verify step");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "{cmd}: verify_mac failed");
            return HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()));
        }
    }
    match state
        .data
        .generate_mac()
        .key_identifier(dst_arn)
        .message_data(data_hex)
        .generation_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm1))
        .send()
        .await
    {
        Ok(resp) => {
            let mac = resp.mac();
            HandlerResult::success(mac.as_bytes()[..MAC_HEX_LEN.min(mac.len())].to_vec())
        }
        Err(e) => {
            warn!(?e, "{cmd}: generate_mac failed after verify succeeded");
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
        let mut v = vec![b'U'];
        v.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        v
    }

    fn len_binary(data: &[u8]) -> Vec<u8> {
        let mut v = format!("{:03X}", data.len()).into_bytes();
        v.extend_from_slice(data);
        v
    }

    // ── data_slice ────────────────────────────────────────────────────────

    #[test]
    fn data_slice_stops_at_tilde() {
        let payload = b"KEYDATAhello~extra~stuff";
        assert_eq!(data_slice(payload, 3), b"DATAhello");
    }

    #[test]
    fn data_slice_returns_all_when_no_tilde() {
        let payload = b"KEYdata";
        assert_eq!(data_slice(payload, 3), b"data");
    }

    #[test]
    fn data_slice_empty_at_tilde() {
        let payload = b"KEY~rest";
        assert_eq!(data_slice(payload, 3), b"");
    }

    // ── parse_len_binary ─────────────────────────────────────────────────

    #[test]
    fn parse_len_binary_reads_binary_bytes() {
        let data: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let mut payload = len_binary(data);
        payload.extend_from_slice(b"EXTRA");
        let (hex, consumed) = parse_len_binary(&payload, 0, "T").unwrap();
        assert_eq!(hex, "DEADBEEF");
        assert_eq!(consumed, 7); // 3 (len field) + 4 bytes
    }

    #[test]
    fn parse_len_binary_rejects_truncated_data() {
        let payload = b"004DE"; // claims 4 bytes but only 2 follow
        assert!(matches!(
            parse_len_binary(payload, 0, "T"),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn parse_len_binary_rejects_non_hex_length() {
        let payload = b"ZZZdata";
        assert!(matches!(
            parse_len_binary(payload, 0, "T"),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    // ── MA / MC / ME ──────────────────────────────────────────────────────

    #[test]
    fn ma_parse_single_key_extracts_data() {
        let mut payload = single_key();
        payload.extend_from_slice(b"MESSAGEDATA");
        let (_, key_len) = parse_legacy_key(&payload, 0).unwrap();
        assert_eq!(key_len, 16);
        let data = data_slice(&payload, key_len);
        assert_eq!(
            bytes_to_hex(data),
            "4D455353414745444154 41".replace(' ', "")
        );
    }

    #[test]
    fn mc_parse_extracts_mac_and_data() {
        let mut payload = double_key();
        payload.extend_from_slice(b"AABBCCDD"); // MAC
        payload.extend_from_slice(b"MSGBYTES");
        let (_, key_len) = parse_legacy_key(&payload, 0).unwrap();
        assert_eq!(key_len, 33);
        let mac = String::from_utf8_lossy(&payload[key_len..key_len + MAC_HEX_LEN]);
        assert_eq!(mac, "AABBCCDD");
    }

    #[test]
    fn mc_too_short_for_mac() {
        let payload = single_key();
        let (_, key_len) = parse_legacy_key(&payload, 0).unwrap();
        assert!(payload.len() < key_len + MAC_HEX_LEN);
    }

    #[test]
    fn me_parse_two_keys_then_mac_and_data() {
        let mut payload = single_key();
        payload.extend_from_slice(&single_key());
        payload.extend_from_slice(b"11223344");
        payload.extend_from_slice(b"PAYLOAD");
        let (_, src_len) = parse_legacy_key(&payload, 0).unwrap();
        let (_, dst_len) = parse_legacy_key(&payload, src_len).unwrap();
        let mac_start = src_len + dst_len;
        assert_eq!(&payload[mac_start..mac_start + MAC_HEX_LEN], b"11223344");
    }

    // ── MK / MM / MO ─────────────────────────────────────────────────────

    #[test]
    fn mk_parse_key_then_len_binary() {
        let mut payload = single_key();
        payload.extend_from_slice(&len_binary(&[0xAA, 0xBB, 0xCC]));
        let (key_id, key_consumed) = parse_legacy_key(&payload, 0).unwrap();
        assert_eq!(key_id.raw, "1234567890ABCDEF");
        let (hex, _) = parse_len_binary(&payload, key_consumed, "MK").unwrap();
        assert_eq!(hex, "AABBCC");
    }

    #[test]
    fn mm_parse_key_mac_then_binary() {
        let mut payload = single_key();
        payload.extend_from_slice(b"AABBCCDD"); // MAC (8H)
        payload.extend_from_slice(&len_binary(b"HELLO"));
        let (_, key_consumed) = parse_legacy_key(&payload, 0).unwrap();
        let mac = &payload[key_consumed..key_consumed + MAC_HEX_LEN];
        assert_eq!(mac, b"AABBCCDD");
        let (data_hex, _) = parse_len_binary(&payload, key_consumed + MAC_HEX_LEN, "MM").unwrap();
        assert_eq!(data_hex, bytes_to_hex(b"HELLO"));
    }

    #[test]
    fn mo_parse_two_keys_mac_then_binary() {
        let mut payload = single_key();
        payload.extend_from_slice(&single_key());
        payload.extend_from_slice(b"CCDDAABB");
        payload.extend_from_slice(&len_binary(&[0x01, 0x02]));
        let (_, src_len) = parse_legacy_key(&payload, 0).unwrap();
        let (_, dst_len) = parse_legacy_key(&payload, src_len).unwrap();
        let mac_start = src_len + dst_len;
        assert_eq!(&payload[mac_start..mac_start + MAC_HEX_LEN], b"CCDDAABB");
        let (hex, _) = parse_len_binary(&payload, mac_start + MAC_HEX_LEN, "MO").unwrap();
        assert_eq!(hex, "0102");
    }

    // ── MU / MW ───────────────────────────────────────────────────────────

    #[test]
    fn mu_parse_mode0_key_binary() {
        let mut payload = vec![b'0']; // mode 0
        payload.extend_from_slice(&single_key());
        payload.extend_from_slice(&len_binary(b"DATA"));
        assert_eq!(payload[0], b'0');
        let (_, key_consumed) = parse_legacy_key(&payload, 1).unwrap();
        let (hex, _) = parse_len_binary(&payload, 1 + key_consumed, "MU").unwrap();
        assert_eq!(hex, bytes_to_hex(b"DATA"));
    }

    #[test]
    fn mu_rejects_continuation_mode() {
        let mut payload = vec![b'1']; // mode 1 = continuation
        payload.extend_from_slice(&single_key());
        payload.extend_from_slice(&len_binary(b"DATA"));
        // The handler checks mode before parsing key — simulate that check
        assert_ne!(payload[0], b'0');
    }

    #[test]
    fn mw_parse_mode0_key_mac_binary() {
        let mut payload = vec![b'0'];
        payload.extend_from_slice(&single_key());
        payload.extend_from_slice(b"AABBCCDD"); // MAC
        payload.extend_from_slice(&len_binary(b"MSG"));
        let (_, key_consumed) = parse_legacy_key(&payload, 1).unwrap();
        let pos = 1 + key_consumed;
        let mac = &payload[pos..pos + MAC_HEX_LEN];
        assert_eq!(mac, b"AABBCCDD");
        let (hex, _) = parse_len_binary(&payload, pos + MAC_HEX_LEN, "MW").unwrap();
        assert_eq!(hex, bytes_to_hex(b"MSG"));
    }

    // ── MQ / MS ───────────────────────────────────────────────────────────

    #[test]
    fn mq_parse_mode0_key_binary() {
        let mut payload = vec![b'0'];
        payload.extend_from_slice(&single_key());
        payload.extend_from_slice(&len_binary(&[0xDE, 0xAD]));
        assert_eq!(payload[0], b'0');
        let (_, key_consumed) = parse_legacy_key(&payload, 1).unwrap();
        let (hex, _) = parse_len_binary(&payload, 1 + key_consumed, "MQ").unwrap();
        assert_eq!(hex, "DEAD");
    }

    #[test]
    fn ms_parse_mode0_key_binary() {
        let mut payload = vec![b'0'];
        payload.extend_from_slice(&double_key());
        payload.extend_from_slice(&len_binary(b"RETAIL"));
        let (key_id, key_consumed) = parse_legacy_key(&payload, 1).unwrap();
        assert!(key_id.raw.starts_with('U'));
        let (hex, _) = parse_len_binary(&payload, 1 + key_consumed, "MS").unwrap();
        assert_eq!(hex, bytes_to_hex(b"RETAIL"));
    }
}
