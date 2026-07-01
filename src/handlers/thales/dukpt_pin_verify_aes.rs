use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::{
    map_pin_block_format, parse_bdk, parse_ksn_with_descriptor, parse_legacy_key,
};
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;
use aws_sdk_paymentcryptographydata::types::{DukptDerivationType, PinBlockFormatForPinData};

/// payShield 3DES & AES DUKPT PIN verification (PUGD0537-004 Rev A p.349/352/355/358).
///
/// GO — Verify PIN, IBM 3624 method  → APC verify_pin_data (Ibm3624PinVerification)
/// GQ — Verify PIN, Visa PVV method  → 68 (gated; APC-side limitation, see below)
/// GS — Verify PIN, Diebold method   → 68 (Diebold table in HSM user storage)
/// GU — Verify PIN, Encrypted PIN    → 68 (LMK reference PIN, no APC equivalent)
///
/// GO supports both 3DES (X9.24-1) and AES (X9.24-3) DUKPT; the derivation type
/// comes from the KSN descriptor (20H → Tdes2Key, 24H → Aes128). Mode '1' (verify
/// PIN + MAC) is rejected (68).
///
/// GO field layout (p.349):
///   Mode:             1N  ('0'/'2' accepted, '1' → 68)
///   BDK:             32H | 'U'+32H | 'S'+keyblock
///   PVK:             16H | 'U'+32H | 'T'+48H  (IBM single-length baseline)
///   KSN Descriptor + KSN: parse_ksn_with_descriptor (3H + 20H or 24H)
///   PIN Block:       16H (DES BDK) | 32H (AES BDK)
///   PIN Block Format Code: 2N  (01/05/47 mapped; 04 'Plus' → 68)
///   Check Length:     2N  consumed
///   Account Number:  12N
///   Decimalization Table: 16H
///   PIN Validation Data:  12A
///   Offset:          12H  IBM offset, F-padded (stripped before the APC call)
///
/// GQ/GS/GU return 68. The GQ wire parser was removed when it was gated (recover
/// from git history if the APC path is fixed).
///
/// Why these decisions, and how each was verified, live in `Handler::grounding()`
/// — the single source of truth (see `src/handlers/grounding.rs`), not duplicated
/// here.
pub struct DukptPinVerifyAesHandler;

const CHECK_LEN: usize = 2;
const ACCOUNT_LEN: usize = 12;
const DECIM_TABLE_LEN: usize = 16;
const PIN_VAL_DATA_LEN: usize = 12;
const IBM_OFFSET_LEN: usize = 12;
const PIN_FMT_LEN: usize = 2;
const PIN_BLOCK_DES: usize = 16;
const PIN_BLOCK_AES: usize = 32;

struct GoFields {
    bdk_id: KeyDescriptor,
    pvk_id: KeyDescriptor,
    deriv_type: DukptDerivationType,
    pin_block_format: PinBlockFormatForPinData,
    ksn: String,
    pin_block: Zeroizing<String>,
    account: String,
    decim_table: String,
    pin_val_data: String,
    offset: String,
}

/// Parse the leading Mode (1N) field. Returns the offset of the first field
/// after Mode (and any Mode='1' MAC fields, which are rejected).
fn parse_mode(payload: &[u8], cmd: &str) -> Result<usize, ProxyError> {
    match payload.first() {
        Some(b'0' | b'2') => Ok(1),
        Some(b'1') => Err(ProxyError::Unsupported(format!(
            "{cmd} Mode '1' (PIN+MAC verify): APC verify_pin_data cannot verify a MAC atomically"
        ))),
        Some(other) => Err(ProxyError::MalformedPayload(format!(
            "{cmd}: invalid Mode '{}'",
            *other as char
        ))),
        None => Err(ProxyError::MalformedPayload(format!(
            "{cmd}: empty payload (no Mode)"
        ))),
    }
}

/// Encrypted PIN block width for a DUKPT derivation type: 16H for 3DES, 32H for AES.
fn pin_block_len(deriv_type: &DukptDerivationType) -> usize {
    match deriv_type {
        DukptDerivationType::Aes128 | DukptDerivationType::Aes192 | DukptDerivationType::Aes256 => {
            PIN_BLOCK_AES
        }
        _ => PIN_BLOCK_DES,
    }
}

/// Map a GO/GQ PIN Block Format Code (2N). '04' (Plus) has no APC equivalent.
fn map_dukpt_format(payload: &[u8], pos: usize) -> Result<PinBlockFormatForPinData, ProxyError> {
    let end = pos + PIN_FMT_LEN;
    if payload.len() < end {
        return Err(ProxyError::MalformedPayload(
            "DUKPT verify: payload too short for PIN block format code".into(),
        ));
    }
    let code = std::str::from_utf8(&payload[pos..end])
        .map_err(|_| ProxyError::MalformedPayload("DUKPT verify: format code not ASCII".into()))?;
    if code == "04" {
        return Err(ProxyError::Unsupported(
            "Thales PIN block format '04' (Plus) has no APC equivalent".into(),
        ));
    }
    map_pin_block_format(code)
}

fn parse_go(payload: &[u8]) -> Result<GoFields, ProxyError> {
    let pos = parse_mode(payload, "GO")?;
    let (bdk_id, bdk_len) = parse_bdk(payload, pos)?;
    let (pvk_id, pvk_len) = parse_legacy_key(payload, pos + bdk_len)?;

    let ksn_offset = pos + bdk_len + pvk_len;
    let (ksn, ksn_consumed, deriv_type) = parse_ksn_with_descriptor(payload, ksn_offset)?;

    let pin_start = ksn_offset + ksn_consumed;
    let pin_len = pin_block_len(&deriv_type);
    let fmt_start = pin_start + pin_len;
    let pin_block_format = map_dukpt_format(payload, fmt_start)?;

    let check_start = fmt_start + PIN_FMT_LEN;
    let account_start = check_start + CHECK_LEN;
    let decim_start = account_start + ACCOUNT_LEN;

    if let Some(&b'K' | &b'L') = payload.get(decim_start) {
        warn!("GO: user-storage/AES-encrypted decimalization table not supported");
        return Err(ProxyError::MalformedPayload(
            "GO: K/L prefix decim table not supported".into(),
        ));
    }

    let pin_val_start = decim_start + DECIM_TABLE_LEN;

    if payload.get(pin_val_start) == Some(&b'P') {
        warn!("GO: 'P'-prefix PIN validation data (16H) not supported");
        return Err(ProxyError::MalformedPayload(
            "GO: P-prefix PIN validation data not supported".into(),
        ));
    }

    let offset_start = pin_val_start + PIN_VAL_DATA_LEN;
    let min_len = offset_start + IBM_OFFSET_LEN;

    if payload.len() < min_len {
        return Err(ProxyError::MalformedPayload(format!(
            "GO payload too short: {} < {}",
            payload.len(),
            min_len
        )));
    }

    Ok(GoFields {
        bdk_id,
        pvk_id,
        deriv_type,
        pin_block_format,
        ksn,
        pin_block: Zeroizing::new(
            String::from_utf8_lossy(&payload[pin_start..pin_start + pin_len]).to_string(),
        ),
        account: String::from_utf8_lossy(&payload[account_start..account_start + ACCOUNT_LEN])
            .to_string(),
        decim_table: String::from_utf8_lossy(&payload[decim_start..decim_start + DECIM_TABLE_LEN])
            .to_string(),
        pin_val_data: String::from_utf8_lossy(
            &payload[pin_val_start..pin_val_start + PIN_VAL_DATA_LEN],
        )
        .to_string(),
        offset: String::from_utf8_lossy(&payload[offset_start..offset_start + IBM_OFFSET_LEN])
            .to_string(),
    })
}

#[async_trait]
impl Handler for DukptPinVerifyAesHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["GO", "GQ", "GS", "GU"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[
            Evidence {
                decision: "GO (IBM3624 DUKPT PIN verify) wire: Mode + BDK + PVK + KSN-descriptor(3H)+KSN + PIN block + fmt code + check len + PAN + decim table + PIN validation data + offset(12H, F-padded). The 12H offset's F-padding is STRIPPED before APC.",
                because: "PUGD0537-004 Rev A p.349. Verified live: proxy GO verdict == APC verify_pin_data verdict (IBM3624 + 3DES DUKPT) for valid PINs across randomized PAN/KSN. The live differential CAUGHT a real bug: APC's pin_offset is ^[0-9]+$, so the wire's F-padded offset was rejected (GO returned 41 for every valid PIN) until the strip was added.",
                wire: WireGrounding::DiffXprov,
                crypto: CryptoGrounding::Apc,
                proof: Proof::LiveTest("dukpt_pin_verify_go_differential"),
            },
            Evidence {
                decision: "GQ (Visa PVV DUKPT verify) returns Unsupported (68).",
                because: "APC single-call verify_pin_data + DukptAttributes + VisaPin returns InternalServerException (500), verified live us-east-1 + us-west-2 on schema-valid inputs. Isolated: the IBM3624 sibling (GO) works single-call, non-DUKPT Visa PVV works, and a two-call translate-then-verify works. Gated honestly rather than inject an intermediate interchange key into the PIN path. Repro filed for AWS.",
                wire: WireGrounding::None,
                crypto: CryptoGrounding::None,
                proof: Proof::Gated("APC single-call DUKPT+VisaPin verify returns 500; see handler doc"),
            },
            Evidence {
                decision: "GS (Diebold) and GU (Encrypted PIN) DUKPT verify return Unsupported (68).",
                because: "Diebold indexes a conversion table in HSM user storage and GU compares against an LMK-encrypted reference PIN — neither has an APC equivalent (APC verify_pin_data does IBM3624 offset / Visa PVV only). PUGD0537-004 Rev A p.355/358.",
                wire: WireGrounding::None,
                crypto: CryptoGrounding::None,
                proof: Proof::Gated("no APC equivalent (Diebold table / LMK-compare)"),
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
            b"GO" => handle_go(payload, state).await,
            b"GQ" => {
                // Gated (returns 68). Reason and evidence: Handler::grounding().
                warn!("GQ gated: APC single-call DUKPT+VisaPin verify returns 500");
                HandlerResult::from_proxy_error(&ProxyError::Unsupported(
                    "GQ (Visa PVV, DUKPT verify): APC VerifyPinData with DukptAttributes + \
                     VisaPin returns InternalServerException; gated pending an APC fix. \
                     Workaround: translate the DUKPT PIN block to a ZPK, then verify the \
                     PVV non-DUKPT."
                        .into(),
                ))
            }
            b"GS" | b"GU" => {
                warn!(cmd = %String::from_utf8_lossy(command_code), "no APC equivalent; returning 68");
                HandlerResult::err(*b"68")
            }
            _ => HandlerResult::err(*b"68"),
        }
    }
}

async fn handle_go(payload: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_go(payload) {
        Ok(f) => f,
        Err(e) => {
            warn!(?e, "GO parse error");
            return HandlerResult::from_proxy_error(&e);
        }
    };

    let bdk_arn = match state.key_map.resolve_descriptor(&fields.bdk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };
    let pvk_arn = match state.key_map.resolve_descriptor(&fields.pvk_id) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        DukptAttributes, Ibm3624PinVerification, PinVerificationAttributes,
    };

    let dukpt_attrs = match DukptAttributes::builder()
        .key_serial_number(&fields.ksn)
        .dukpt_derivation_type(fields.deriv_type)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    // The GO wire offset is 12H, left-justified and F-padded (PUGD0537-004
    // p.349). APC's pin_offset must be digits only (^[0-9]+$), so strip the F
    // padding — the significant offset digits match the PIN length. (Verified
    // against live APC: a padded offset is rejected with a ValidationException.)
    let pin_offset = fields.offset.trim_end_matches('F');

    let ibm_attrs = match Ibm3624PinVerification::builder()
        .decimalization_table(&fields.decim_table)
        .pin_validation_data_pad_character("F")
        .pin_validation_data(&fields.pin_val_data)
        .pin_offset(pin_offset)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(bdk = %bdk_arn, pvk = %pvk_arn, ksn_len = fields.ksn.len(), "GO: verify_pin_data IBM3624 DUKPT");

    match state
        .data
        .verify_pin_data()
        .verification_key_identifier(&pvk_arn)
        .encryption_key_identifier(&bdk_arn)
        .encrypted_pin_block(fields.pin_block.as_str())
        .primary_account_number(&fields.account)
        .pin_block_format(fields.pin_block_format)
        .verification_attributes(PinVerificationAttributes::Ibm3624Pin(ibm_attrs))
        .dukpt_attributes(dukpt_attrs)
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error()
                .is_some_and(aws_sdk_paymentcryptographydata::operation::verify_pin_data::VerifyPinDataError::is_verification_failed_exception)
            {
                warn!("GO: PIN mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "GO: verify_pin_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aws_sdk_paymentcryptographydata::types::DukptDerivationType;

    fn bdk_32() -> Vec<u8> {
        b"12345678901234561234567890123456".to_vec()
    }
    fn pvk_16() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec()
    }

    // 3DES KSN descriptor: nibbles = 0x14 = 20 → 20H KSN
    fn ksn_tdes() -> Vec<u8> {
        let mut v = b"014".to_vec();
        v.extend_from_slice(b"12345678901234567890");
        v
    }

    // AES KSN descriptor: nibbles = 0x18 = 24 → 24H KSN
    fn ksn_aes() -> Vec<u8> {
        let mut v = b"018".to_vec();
        v.extend_from_slice(b"123456789012345678901234");
        v
    }

    fn pin16() -> &'static [u8] {
        b"1234567890ABCDEF"
    }
    fn pin32() -> &'static [u8] {
        b"1234567890ABCDEF1234567890ABCDEF"
    }

    // Mode '0' + BDK + PVK + KSN + PIN block + format code + check length + account + ...
    fn build_go(bdk: &[u8], pvk: &[u8], ksn_block: &[u8], pin_block: &[u8], fmt: &[u8]) -> Vec<u8> {
        let mut v = b"0".to_vec(); // Mode
        v.extend_from_slice(bdk);
        v.extend_from_slice(pvk);
        v.extend_from_slice(ksn_block);
        v.extend_from_slice(pin_block);
        v.extend_from_slice(fmt); // PIN block format code
        v.extend_from_slice(b"04"); // check length
        v.extend_from_slice(b"123456789012"); // account
        v.extend_from_slice(b"1234567890123456"); // decim table
        v.extend_from_slice(b"NNNNNNNNNNNN"); // pin val data
        v.extend_from_slice(b"123456FFFFFF"); // offset
        v
    }

    #[test]
    fn go_parse_tdes_ksn() {
        let p = build_go(&bdk_32(), &pvk_16(), &ksn_tdes(), pin16(), b"01");
        let f = parse_go(&p).unwrap();
        assert_eq!(f.ksn, "12345678901234567890");
        assert!(matches!(f.deriv_type, DukptDerivationType::Tdes2Key));
        assert!(matches!(
            f.pin_block_format,
            PinBlockFormatForPinData::IsoFormat0
        ));
        assert_eq!(f.pin_block.as_str(), "1234567890ABCDEF");
        assert_eq!(f.account, "123456789012");
        assert_eq!(f.offset, "123456FFFFFF");
    }

    #[test]
    fn go_parse_aes_uses_32h_pin_block() {
        let p = build_go(&bdk_32(), &pvk_16(), &ksn_aes(), pin32(), b"47");
        let f = parse_go(&p).unwrap();
        assert_eq!(f.ksn.len(), 24);
        assert!(matches!(f.deriv_type, DukptDerivationType::Aes128));
        assert_eq!(f.pin_block.as_str().len(), 32);
        assert!(matches!(
            f.pin_block_format,
            PinBlockFormatForPinData::IsoFormat3
        ));
        assert_eq!(f.account, "123456789012");
    }

    #[test]
    fn go_rejects_mode_1() {
        let mut p = build_go(&bdk_32(), &pvk_16(), &ksn_tdes(), pin16(), b"01");
        p[0] = b'1'; // Mode '1' = PIN+MAC verify
        assert!(matches!(parse_go(&p), Err(ProxyError::Unsupported(_))));
    }

    #[test]
    fn go_rejects_plus_format() {
        let p = build_go(&bdk_32(), &pvk_16(), &ksn_tdes(), pin16(), b"04");
        assert!(matches!(parse_go(&p), Err(ProxyError::Unsupported(_))));
    }

    #[test]
    fn go_rejects_k_prefix_decim() {
        let mut p = b"0".to_vec(); // Mode
        p.extend_from_slice(&bdk_32());
        p.extend_from_slice(&pvk_16());
        p.extend_from_slice(&ksn_tdes());
        p.extend_from_slice(pin16()); // PIN block
        p.extend_from_slice(b"01"); // format code
        p.extend_from_slice(b"04"); // check length
        p.extend_from_slice(b"123456789012"); // account
        p.push(b'K');
        assert!(matches!(parse_go(&p), Err(ProxyError::MalformedPayload(_))));
    }
}
