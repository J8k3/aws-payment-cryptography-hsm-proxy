use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use aws_sdk_paymentcryptographydata::types::{
    MacAlgorithmEmv, MacAttributes, MajorKeyDerivationMode, SessionKeyDerivationMode,
    SessionKeyDerivationValue,
};

use crate::error::ProxyError;
use crate::handlers::thales::common::{
    build_err, bytes_to_hex, decode_bcd_pan_seq, emv_pad, parse_key_32,
};
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield EMV "Generate a Secure Message with Integrity" commands.
///
/// JU (→ JV) — UnionPay/CUP variant (PUGD0538-003 §7 p.124).
/// KU (→ KV) — Generate a Secure Message with Integrity (PUGD0537-004 Rev A p.475).
/// KY (→ KZ) — EMV2000 / EMV-Common variant (PUGD0537-004 Rev A p.480).
///
/// These derive an integrity session key (SK-SMI) from an issuer master key
/// (MK-SMI, TR-31 `E2`) and MAC an issuer-script message. APC performs the whole
/// IMK → SK-SMI derivation itself via `GenerateMac` with `EmvMac` generation
/// attributes (the same pattern as the ARQC handlers use for verify) — the proxy
/// maps the wire onto `EmvMac` and does NOT derive anything. Confirmed live: an
/// `EmvMac` call with a created E2 master key returns a MAC for every session
/// method below.
///
/// # Scope (this handler)
///
/// Only **Mode 0 (integrity only)** is mapped. Modes 1–4 add confidentiality or
/// PIN change and require APC's separate `GenerateMacEmvPinChange` operation plus
/// a confidentiality (E1) key; they stay gated. `KY` stays gated in full: its
/// Mode-0 EMV2000 secure-messaging derivation takes an IV-SMI and a branch/height
/// key-tree that APC's `EmvMac` does not model, so it cannot be faithfully mapped
/// without a payShield reference.
///
/// # Scheme → APC session method (Mode 0)
///
/// APC's `EmvMac` `SessionKeyDerivationValue` is a tagged union of exactly one of
/// `ApplicationTransactionCounter` (ATC) or `ApplicationCryptogram` (AC); each
/// `SessionKeyDerivationMode` accepts exactly one of them (verified live):
///   EMV2000 / AMEX / VISA            → ATC
///   EMV_COMMON / MASTERCARD          → AC
///
///   JU '1' UnionPay CUP 4.2  → EMV2000  + ATC   (UnionPay == EMV2000, per the JS ARQC handler)
///   KU '0' Visa VIS          → VISA     + ATC   (session-key data = 2-byte ATC, left-zero-padded to 8B)
///   KU '1' Mastercard M/Chip → MC       + AC    (session-key data = 8-byte RANDi → AC)
///   KU '2' Amex AEIPS        → AMEX     + ATC   (session-key data = 2-byte ATC, left-zero-padded to 8B)
///   KU '5' JCB CVN04         → EMV_COMMON + AC  (session-key data = 8-byte Application Cryptogram)
///
/// Gated: KU '3'/'4' (JCB CVN01/02 — no APC session mode: no-session-key / JCB SKD),
/// KU '6' (UnionPay-in-KU) and everything on KY.
pub struct IssuerScriptMacHandler;

/// The value that seeds APC's session-key derivation, as required per mode.
enum SmiValue {
    /// 4-hex-char ATC (EMV2000 / AMEX / VISA).
    Atc(String),
    /// 16-hex-char Application Cryptogram (EMV_COMMON / MASTERCARD).
    Ac(String),
}

/// A resolved Mode-0 scheme: which APC session method, and its seed value.
struct SmiMapping {
    session_mode: SessionKeyDerivationMode,
    value: SmiValue,
}

struct SmiFields {
    key_id: KeyDescriptor,
    pan: String,
    pan_seq: String,
    mapping: SmiMapping,
    /// Issuer-script message, hex, already EMV (ISO 9797-1 method 2) padded for APC.
    message: Zeroizing<String>,
}

/// Require Mode Flag `'0'`; anything else is a gated (unsupported) mode.
fn require_mode_0(cmd: &str, byte: u8) -> Result<(), ProxyError> {
    match byte {
        b'0' => Ok(()),
        b'1'..=b'4' => Err(ProxyError::Unsupported(format!(
            "{cmd}: mode '{}' (confidentiality / PIN change) requires APC GenerateMacEmvPinChange \
             and a confidentiality key; only mode 0 (integrity) is supported",
            byte as char
        ))),
        other => Err(ProxyError::MalformedPayload(format!(
            "{cmd}: unknown mode flag '{}'",
            other as char
        ))),
    }
}

/// Read the 8-byte PAN/PAN-Seq BCD field at `pos`, returning `(pan, pan_seq)` and
/// the new offset.
fn read_pan_seq(
    cmd: &str,
    payload: &[u8],
    pos: usize,
) -> Result<(String, String, usize), ProxyError> {
    const N: usize = 8;
    if payload.len() < pos + N {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: PAN+Seq missing"
        )));
    }
    let arr: [u8; 8] = payload[pos..pos + N]
        .try_into()
        .map_err(|_| ProxyError::MalformedPayload(format!("{cmd}: PAN+Seq slice error")))?;
    let (pan, seq) = decode_bcd_pan_seq(arr);
    Ok((pan, seq, pos + N))
}

/// Apply APC-side message padding. payShield/CUP integrity MACs are computed over
/// ISO 9797-1 method-2-padded data; APC's `GenerateMac` does not pad `MessageData`,
/// so the proxy pads unless the host says it already did (`already_padded`).
fn message_for_apc(raw: &[u8], already_padded: bool) -> Zeroizing<String> {
    if already_padded {
        Zeroizing::new(bytes_to_hex(raw))
    } else {
        Zeroizing::new(bytes_to_hex(&emv_pad(raw)))
    }
}

/// Parse JU (UnionPay CUP) Mode-0.
///
/// Wire: Mode(1N) Scheme(1N='1') MK-SMI(32H|U+32H|S+..) PAN/Seq(8B)
///       ATC(2B) PaddingFlag(1N) MacMsgLen(4H) MacMsgData(nB) ';'(1A)
fn parse_ju(payload: &[u8]) -> Result<SmiFields, ProxyError> {
    let mut pos = 0;

    let mode = *payload
        .first()
        .ok_or_else(|| ProxyError::MalformedPayload("JU: mode flag missing".into()))?;
    require_mode_0("JU", mode)?;
    pos += 1;

    // Scheme ID — CUP defines only '1'.
    match payload.get(pos) {
        Some(b'1') => {}
        Some(other) => {
            return Err(ProxyError::MalformedPayload(format!(
                "JU: unsupported scheme '{}' (CUP defines only '1')",
                *other as char
            )))
        }
        None => return Err(ProxyError::MalformedPayload("JU: scheme ID missing".into())),
    }
    pos += 1;

    let (key_id, key_consumed) = parse_key_32(payload, pos)?;
    pos += key_consumed;

    let (pan, pan_seq, next) = read_pan_seq("JU", payload, pos)?;
    pos = next;

    // ATC (2B binary)
    if payload.len() < pos + 2 {
        return Err(ProxyError::MalformedPayload("JU: ATC missing".into()));
    }
    let atc = bytes_to_hex(&payload[pos..pos + 2]);
    pos += 2;

    // Padding Flag (1N): '1' = host already padded the message.
    let already_padded = match payload.get(pos) {
        Some(b'0') => false,
        Some(b'1') => true,
        Some(other) => {
            return Err(ProxyError::MalformedPayload(format!(
                "JU: invalid padding flag '{}'",
                *other as char
            )))
        }
        None => {
            return Err(ProxyError::MalformedPayload(
                "JU: padding flag missing".into(),
            ))
        }
    };
    pos += 1;

    // MAC Message Data Length (4H ASCII) + data + ';'.
    let (message_raw, next) = read_len_prefixed_message("JU", payload, pos)?;
    pos = next;
    expect_delimiter("JU", payload, pos)?;

    Ok(SmiFields {
        key_id,
        pan,
        pan_seq,
        mapping: SmiMapping {
            session_mode: SessionKeyDerivationMode::Emv2000,
            value: SmiValue::Atc(atc),
        },
        message: message_for_apc(message_raw, already_padded),
    })
}

/// Parse KU Mode-0 for the reachable schemes (0/1/2/5).
///
/// Wire: Mode(1N='0') Scheme(1N) MK-SMI(..) PAN/Seq(8B) IntegritySessionKeyData(8B)
///       [MacMsgLen(4H) only for scheme '5'] MacMsgData(nB) ';'(1A)
///
/// The KU message carries no host padding flag for these schemes, so the proxy
/// always method-2 pads it for APC.
fn parse_ku(payload: &[u8]) -> Result<SmiFields, ProxyError> {
    let mut pos = 0;

    let mode = *payload
        .first()
        .ok_or_else(|| ProxyError::MalformedPayload("KU: mode flag missing".into()))?;
    require_mode_0("KU", mode)?;
    pos += 1;

    let scheme = *payload
        .get(pos)
        .ok_or_else(|| ProxyError::MalformedPayload("KU: scheme ID missing".into()))?;
    pos += 1;

    let (key_id, key_consumed) = parse_key_32(payload, pos)?;
    pos += key_consumed;

    let (pan, pan_seq, next) = read_pan_seq("KU", payload, pos)?;
    pos = next;

    // Integrity Session Key Data — 8 bytes for schemes 0/1/2/5.
    const SKD_BYTES: usize = 8;
    if payload.len() < pos + SKD_BYTES {
        return Err(ProxyError::MalformedPayload(
            "KU: integrity session key data missing".into(),
        ));
    }
    let skd = &payload[pos..pos + SKD_BYTES];
    pos += SKD_BYTES;

    // Scheme → (session mode, seed). ATC schemes take the rightmost 2 bytes of the
    // 8-byte field (left zero-padded per Thales); AC schemes take all 8 bytes.
    let (session_mode, value, length_prefixed) = match scheme {
        b'0' => (
            SessionKeyDerivationMode::Visa,
            SmiValue::Atc(bytes_to_hex(&skd[6..8])),
            false,
        ),
        b'1' => (
            SessionKeyDerivationMode::MastercardSessionKey,
            SmiValue::Ac(bytes_to_hex(skd)),
            false,
        ),
        b'2' => (
            SessionKeyDerivationMode::Amex,
            SmiValue::Atc(bytes_to_hex(&skd[6..8])),
            false,
        ),
        b'5' => (
            SessionKeyDerivationMode::EmvCommonSessionKey,
            SmiValue::Ac(bytes_to_hex(skd)),
            true,
        ),
        b'3' | b'4' => {
            return Err(ProxyError::Unsupported(format!(
                "KU: scheme '{}' (JCB CVN01/02) has no APC session-key method \
                 (no-session-key / JCB SKD)",
                scheme as char
            )))
        }
        b'6' => {
            return Err(ProxyError::Unsupported(
                "KU: scheme '6' (UnionPay) is gated in KU; use JU for UnionPay".into(),
            ))
        }
        other => {
            return Err(ProxyError::MalformedPayload(format!(
                "KU: unknown scheme '{}'",
                other as char
            )))
        }
    };

    // Message framing: scheme '5' is length-prefixed; '0'/'1'/'2' are delimited by
    // ';' (payShield defines no length for them).
    let (message_raw, next) = if length_prefixed {
        read_len_prefixed_message("KU", payload, pos)?
    } else {
        read_delimited_message("KU", payload, pos)?
    };
    pos = next;
    expect_delimiter("KU", payload, pos)?;

    Ok(SmiFields {
        key_id,
        pan,
        pan_seq,
        mapping: SmiMapping {
            session_mode,
            value,
        },
        message: message_for_apc(message_raw, false),
    })
}

/// Read a `4H` ASCII length field followed by that many message bytes; returns the
/// message slice and the offset of the trailing delimiter.
fn read_len_prefixed_message<'a>(
    cmd: &str,
    payload: &'a [u8],
    pos: usize,
) -> Result<(&'a [u8], usize), ProxyError> {
    if payload.len() < pos + 4 {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: message length missing"
        )));
    }
    let len_hex = std::str::from_utf8(&payload[pos..pos + 4])
        .map_err(|_| ProxyError::MalformedPayload(format!("{cmd}: message length not ASCII")))?;
    let msg_len = usize::from_str_radix(len_hex, 16).map_err(|_| {
        ProxyError::MalformedPayload(format!("{cmd}: invalid message length '{len_hex}'"))
    })?;
    let start = pos + 4;
    if payload.len() < start + msg_len {
        return Err(ProxyError::MalformedPayload(format!(
            "{cmd}: message truncated: need {msg_len}B"
        )));
    }
    Ok((&payload[start..start + msg_len], start + msg_len))
}

/// Read a message with no length field: everything up to the next `';'` (0x3B).
///
/// payShield frames the Mode-0 schemes without a length, so the message runs to
/// the delimiter. Issuer-script APDUs that themselves contain a raw `0x3B` byte
/// cannot be represented in this framing — that limitation is inherent to the
/// payShield wire, not the proxy.
fn read_delimited_message<'a>(
    cmd: &str,
    payload: &'a [u8],
    pos: usize,
) -> Result<(&'a [u8], usize), ProxyError> {
    match payload[pos..].iter().position(|&b| b == 0x3B) {
        Some(rel) => Ok((&payload[pos..pos + rel], pos + rel)),
        None => Err(ProxyError::MalformedPayload(format!(
            "{cmd}: message delimiter ';' not found"
        ))),
    }
}

/// Verify the `';'` (0x3B) delimiter at `pos`.
fn expect_delimiter(cmd: &str, payload: &[u8], pos: usize) -> Result<(), ProxyError> {
    if payload.get(pos) == Some(&0x3B) {
        Ok(())
    } else {
        Err(ProxyError::MalformedPayload(format!(
            "{cmd}: expected ';' delimiter at offset {pos}, got {:?}",
            payload.get(pos)
        )))
    }
}

#[async_trait]
impl Handler for IssuerScriptMacHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["JU", "KU", "KY"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[
            Evidence {
                decision:
                    "JU (UnionPay CUP) and KU Mode-0 (integrity only) generate an issuer-script \
                     MAC → APC generate_mac with EmvMac attributes; APC performs the whole \
                     IMK-SMI → SK-SMI derivation. Scheme → session method: JU '1' → EMV2000+ATC; \
                     KU '0' → VISA+ATC, '1' → Mastercard+AC(RANDi), '2' → AMEX+ATC, '5' → \
                     EMV_COMMON+AC.",
                because:
                    "PUGD0537-004 Rev A p.475 (KU); PUGD0538-003 §7 p.124 (JU). Verified live: a \
                     created E2 IMK-SMI (DeriveKey mode) + EmvMac returns a MAC for each session \
                     method, and the SessionKeyDerivationValue union requires ATC for \
                     EMV2000/AMEX/VISA and ApplicationCryptogram for EMV_COMMON/MASTERCARD. The \
                     differential confirms the proxy's wire parse + EmvMac mapping equals a direct \
                     APC generate_mac. Crypto grade is `apc` (agrees with APC): unlike the ARQC \
                     family there is not yet an independent from-spec SMI-derivation anchor.",
                wire: WireGrounding::DiffXprov,
                crypto: CryptoGrounding::Apc,
                proof: Proof::LiveTest("issuer_script_mac_differential"),
            },
            Evidence {
                decision:
                    "KY, all confidentiality / PIN-change modes (1–4), KU schemes '3'/'4'/'6' \
                     return Unsupported (68).",
                because: "KY Mode-0 EMV2000 secure-messaging derivation takes an IV-SMI and a \
                     branch/height key-tree that APC's EmvMac does not model (PUGD0537-004 Rev A \
                     p.480), so it cannot be faithfully mapped without a payShield reference. \
                     Modes 1–4 add confidentiality / PIN change and need APC's separate \
                     GenerateMacEmvPinChange operation plus an E1 key. KU '3'/'4' (JCB CVN01/02) \
                     and '6' (UnionPay-in-KU) have no APC session-key method. Gated rather than \
                     emit a MAC under the wrong key.",
                wire: WireGrounding::None,
                crypto: CryptoGrounding::None,
                proof: Proof::Gated(
                    "KY IV-SMI/key-tree not modelled by APC EmvMac; confidentiality/PIN-change \
                     need GenerateMacEmvPinChange; JCB/UnionPay-in-KU have no APC session method",
                ),
            },
        ]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        let cmd = String::from_utf8_lossy(command_code);
        let fields = match cmd.as_ref() {
            "JU" => parse_ju(payload),
            "KU" => parse_ku(payload),
            "KY" => Err(ProxyError::Unsupported(
                "KY: EMV2000 secure-messaging integrity uses an IV-SMI and branch/height key-tree \
                 that APC's EmvMac does not model; gated pending payShield-referenced validation"
                    .into(),
            )),
            other => Err(ProxyError::Unsupported(format!(
                "{other}: not an issuer-script MAC command"
            ))),
        };
        let fields = match fields {
            Ok(f) => f,
            Err(e) => {
                warn!(command = %cmd, error = %e, "issuer-script MAC rejected");
                return HandlerResult::from_proxy_error(&e);
            }
        };
        handle_generate(&cmd, fields, state).await
    }
}

async fn handle_generate(cmd: &str, fields: SmiFields, state: &Arc<AppState>) -> HandlerResult {
    let key_arn = match state.key_map.resolve_descriptor(&fields.key_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    let session_value = match fields.mapping.value {
        SmiValue::Atc(atc) => SessionKeyDerivationValue::ApplicationTransactionCounter(atc),
        SmiValue::Ac(ac) => SessionKeyDerivationValue::ApplicationCryptogram(ac),
    };

    let emv = match MacAlgorithmEmv::builder()
        .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
        .primary_account_number(&fields.pan)
        .pan_sequence_number(&fields.pan_seq)
        .session_key_derivation_mode(fields.mapping.session_mode)
        .session_key_derivation_value(session_value)
        .build()
        .map_err(build_err)
    {
        Ok(e) => e,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(command = %cmd, key = %key_arn, "issuer-script MAC: generate_mac EmvMac");

    // payShield issuer-script MAC is a 4-byte MAC (response field 8H).
    match state
        .data
        .generate_mac()
        .key_identifier(&key_arn)
        .message_data(fields.message.as_str())
        .generation_attributes(MacAttributes::EmvMac(emv))
        .mac_length(4)
        .send()
        .await
    {
        Ok(resp) => HandlerResult::success(resp.mac().as_bytes().to_vec()),
        Err(e) => {
            warn!(command = %cmd, ?e, "issuer-script MAC: generate_mac failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // EMV pre-formatted (rightmost 16 of PAN||PSN) "1234567890123401" → PAN 12345678901234, Seq 01.
    const PAN_SEQ_BCD: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x01];

    fn key32() -> Vec<u8> {
        b"1234567890ABCDEF1234567890ABCDEF".to_vec()
    }

    #[test]
    fn command_codes_registered() {
        let h = IssuerScriptMacHandler;
        for c in ["JU", "KU", "KY"] {
            assert!(h.command_codes().contains(&c));
        }
    }

    // ── JU ──────────────────────────────────────────────────────────────────

    fn ju_payload(mode: u8, scheme: u8, pad_flag: u8, msg: &[u8]) -> Vec<u8> {
        let mut v = vec![mode, scheme];
        v.extend_from_slice(&key32());
        v.extend_from_slice(&PAN_SEQ_BCD);
        v.extend_from_slice(&[0x00, 0x2A]); // ATC 2B → "002A"
        v.push(pad_flag);
        v.extend_from_slice(format!("{:04X}", msg.len()).as_bytes()); // MacMsgLen 4H
        v.extend_from_slice(msg);
        v.push(0x3B); // ';'
        v
    }

    #[test]
    fn ju_mode0_parses_and_maps_emv2000_atc() {
        let f = parse_ju(&ju_payload(b'0', b'1', b'0', &[0xDE, 0xAD, 0xBE, 0xEF])).unwrap();
        assert_eq!(f.pan, "12345678901234");
        assert_eq!(f.pan_seq, "01");
        assert!(matches!(
            f.mapping.session_mode,
            SessionKeyDerivationMode::Emv2000
        ));
        assert!(matches!(f.mapping.value, SmiValue::Atc(ref a) if a == "002A"));
        // padding flag '0' → proxy method-2 pads.
        assert_eq!(f.message.as_str(), "DEADBEEF80000000");
    }

    #[test]
    fn ju_already_padded_message_not_repadded() {
        // 8-byte, already method-2 padded input; mode '0', pad flag '1' → forward as-is.
        let f = parse_ju(&ju_payload(
            b'0',
            b'1',
            b'1',
            &[0xDE, 0xAD, 0xBE, 0xEF, 0x80, 0, 0, 0],
        ))
        .unwrap();
        assert_eq!(f.message.as_str(), "DEADBEEF80000000");
    }

    #[test]
    fn ju_rejects_confidentiality_modes() {
        for m in *b"1234" {
            assert!(matches!(
                parse_ju(&ju_payload(m, b'1', b'0', &[0xAA])),
                Err(ProxyError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn ju_rejects_unknown_scheme() {
        assert!(matches!(
            parse_ju(&ju_payload(b'0', b'2', b'0', &[0xAA])),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    // ── KU ──────────────────────────────────────────────────────────────────

    /// KU with an 8-byte session-key-data field. `length_prefixed` mirrors the
    /// scheme's framing (only scheme '5' carries a 4H length).
    fn ku_payload(scheme: u8, skd: [u8; 8], msg: &[u8], length_prefixed: bool) -> Vec<u8> {
        let mut v = vec![b'0', scheme];
        v.extend_from_slice(&key32());
        v.extend_from_slice(&PAN_SEQ_BCD);
        v.extend_from_slice(&skd);
        if length_prefixed {
            v.extend_from_slice(format!("{:04X}", msg.len()).as_bytes());
        }
        v.extend_from_slice(msg);
        v.push(0x3B);
        v
    }

    #[test]
    fn ku_visa_scheme0_atc_from_rightmost_2_bytes() {
        let skd = [0, 0, 0, 0, 0, 0, 0x12, 0x34]; // ATC left-zero-padded to 8B
        let f = parse_ku(&ku_payload(b'0', skd, &[0xAB, 0xCD], false)).unwrap();
        assert!(matches!(
            f.mapping.session_mode,
            SessionKeyDerivationMode::Visa
        ));
        assert!(matches!(f.mapping.value, SmiValue::Atc(ref a) if a == "1234"));
        assert_eq!(f.message.as_str(), "ABCD800000000000");
    }

    #[test]
    fn ku_mastercard_scheme1_randi_as_ac() {
        let randi = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let f = parse_ku(&ku_payload(b'1', randi, &[0xAB], false)).unwrap();
        assert!(matches!(
            f.mapping.session_mode,
            SessionKeyDerivationMode::MastercardSessionKey
        ));
        assert!(matches!(f.mapping.value, SmiValue::Ac(ref a) if a == "1122334455667788"));
    }

    #[test]
    fn ku_amex_scheme2_atc() {
        let skd = [0, 0, 0, 0, 0, 0, 0x00, 0x07];
        let f = parse_ku(&ku_payload(b'2', skd, &[0xAB], false)).unwrap();
        assert!(matches!(
            f.mapping.session_mode,
            SessionKeyDerivationMode::Amex
        ));
        assert!(matches!(f.mapping.value, SmiValue::Atc(ref a) if a == "0007"));
    }

    #[test]
    fn ku_jcb_cvn04_scheme5_emvcommon_ac_length_prefixed() {
        let ac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let f = parse_ku(&ku_payload(b'5', ac, &[0xDE, 0xAD], true)).unwrap();
        assert!(matches!(
            f.mapping.session_mode,
            SessionKeyDerivationMode::EmvCommonSessionKey
        ));
        assert!(matches!(f.mapping.value, SmiValue::Ac(ref a) if a == "AABBCCDDEEFF0011"));
        assert_eq!(f.message.as_str(), "DEAD800000000000");
    }

    #[test]
    fn ku_gates_jcb_and_unionpay_schemes() {
        let skd = [0u8; 8];
        for s in *b"346" {
            assert!(matches!(
                parse_ku(&ku_payload(s, skd, &[0xAB], false)),
                Err(ProxyError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn ku_rejects_confidentiality_mode() {
        // Force mode '2' by editing the first byte.
        let mut p = ku_payload(b'0', [0u8; 8], &[0xAB], false);
        p[0] = b'2';
        assert!(matches!(parse_ku(&p), Err(ProxyError::Unsupported(_))));
    }

    #[test]
    fn ku_delimited_message_stops_at_semicolon() {
        let skd = [0, 0, 0, 0, 0, 0, 0x00, 0x01];
        let f = parse_ku(&ku_payload(b'0', skd, &[0x01, 0x02, 0x03], false)).unwrap();
        // 3-byte message method-2 padded to 8 bytes.
        assert_eq!(f.message.as_str(), "0102038000000000");
    }

    #[test]
    fn unsupported_maps_to_68() {
        assert_eq!(
            ProxyError::Unsupported("KY".into()).payshield_code(),
            *b"68"
        );
    }
}
