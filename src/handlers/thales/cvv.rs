use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_key_32;
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield card verification commands.
///
/// CW (→ CX) — Generate a Card Verification Code/Value → generate_card_validation_data
/// CY (→ CZ) — Verify a Card Verification Code/Value   → verify_card_validation_data
/// NY (→ NZ) — Generate Static CVC3 / IVCVC3 (Mastercard PayPass)        [unsupported]
/// RY (→ RZ) — Calculate / Verify American Express Card Security Codes   [unsupported]
///
/// CW / CY wire format (PUGD0537-004 Rev A, pp.250, 303 — AUTHORITATIVE).
/// Neither command carries a "mode" selector: the Visa/Mastercard product
/// (CVV1/CVC1, CVV2/CVC2, iCVV/Chip-CVC, CAVV/AAV) is chosen entirely by the
/// 3-digit service code value. Magnetic-stripe CVV1/CVC1 uses the card's real
/// service code (e.g. "201"); CVV2/CVC2 (signature panel) uses "000"; iCVV /
/// Chip CVC (EMV) uses "999"; CAVV/AAV (3-D Secure) replaces the expiry with an
/// unpredictable number and the service code with the auth-results codes.
/// Because all of these use the single Visa CVV algorithm parameterised by the
/// service code, both commands map to APC's CardVerificationValue1 with the
/// service code taken straight from the wire (CardVerificationValue2 is merely
/// CardVerificationValue1 with service code "000").
///
///   CW:  CVK (32H | 'U'+32H | 'S'+TR-31)
///        PAN (nN, max 19) ';' expiry (4N) service code (3N)
///   CY:  CVK
///        CVV (3N) PAN (nN, max 19) ';' expiry (4N) service code (3N)
///
/// NY and RY return 68 — see `handle_ny` / `handle_ry`.
///
/// Why these decisions, and how each was verified, live in `Handler::grounding()`
/// — the single source of truth (see `src/handlers/grounding.rs`), not duplicated
/// here.
pub struct CvvHandler;

const EXPIRY_LEN: usize = 4;
const SERVICE_LEN: usize = 3;
const CVV_LEN: usize = 3;
const PAN_MAX: usize = 19;
const PAN_DELIM: u8 = b';';

struct CwFields {
    cvk: KeyDescriptor,
    pan: String,
    expiry: String,
    service_code: String,
}

struct CyFields {
    cvk: KeyDescriptor,
    cvv: String,
    pan: String,
    expiry: String,
    service_code: String,
}

/// Read a variable-length PAN (1..=19 digits) terminated by a ';' delimiter.
/// Returns the PAN and the offset of the first byte *after* the delimiter.
fn read_pan(buf: &[u8], pos: usize) -> Result<(String, usize), ProxyError> {
    let rest = buf.get(pos..).unwrap_or(&[]);
    let delim = rest
        .iter()
        .position(|&b| b == PAN_DELIM)
        .ok_or_else(|| ProxyError::MalformedPayload("CVV: missing ';' PAN delimiter".into()))?;
    if delim == 0 || delim > PAN_MAX {
        return Err(ProxyError::MalformedPayload(format!(
            "CVV: PAN length {delim} out of range (1..={PAN_MAX})"
        )));
    }
    let pan = String::from_utf8_lossy(&rest[..delim]).to_string();
    Ok((pan, pos + delim + 1))
}

/// Read the trailing `expiry (4N) service code (3N)` pair at `pos`.
fn read_expiry_service(buf: &[u8], pos: usize) -> Result<(String, String), ProxyError> {
    let exp_end = pos + EXPIRY_LEN;
    let svc_end = exp_end + SERVICE_LEN;
    if buf.len() < svc_end {
        return Err(ProxyError::MalformedPayload(format!(
            "CVV: payload too short for expiry+service: {} < {}",
            buf.len(),
            svc_end
        )));
    }
    let expiry = String::from_utf8_lossy(&buf[pos..exp_end]).to_string();
    let service_code = String::from_utf8_lossy(&buf[exp_end..svc_end]).to_string();
    Ok((expiry, service_code))
}

fn parse_cw(body: &[u8]) -> Result<CwFields, ProxyError> {
    let (cvk, n) = parse_key_32(body, 0)?;
    let (pan, pos) = read_pan(body, n)?;
    let (expiry, service_code) = read_expiry_service(body, pos)?;
    Ok(CwFields {
        cvk,
        pan,
        expiry,
        service_code,
    })
}

fn parse_cy(body: &[u8]) -> Result<CyFields, ProxyError> {
    let (cvk, n) = parse_key_32(body, 0)?;
    let cvv_end = n + CVV_LEN;
    if body.len() < cvv_end {
        return Err(ProxyError::MalformedPayload(format!(
            "CY: payload too short for CVV: {} < {}",
            body.len(),
            cvv_end
        )));
    }
    let cvv = String::from_utf8_lossy(&body[n..cvv_end]).to_string();
    let (pan, pos) = read_pan(body, cvv_end)?;
    let (expiry, service_code) = read_expiry_service(body, pos)?;
    Ok(CyFields {
        cvk,
        cvv,
        pan,
        expiry,
        service_code,
    })
}

#[async_trait]
impl Handler for CvvHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["CW", "CY", "NY", "RY"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[
            Evidence {
                decision: "CW/CY wire: CVK(32H) then a VARIABLE-LENGTH ';'-terminated PAN, then expiry(4N) + service code(3N) — not a fixed-16 PAN.",
                because: "PUGD0537-004 Rev A p.250 (CW) / p.303 (CY). A fixed-16 parse mis-reads Amex(15)/19-digit PANs. Verified live: proxy CVV == APC generate_card_validation_data across randomized PAN lengths (incl. 15) and service codes, plus a CY round-trip.",
                wire: WireGrounding::DiffXprov,
                crypto: CryptoGrounding::Apc,
                proof: Proof::LiveTest("cvv_cw_cy_differential"),
            },
            Evidence {
                decision: "The CVV primitive is additionally cross-validated against a second \
                           implementation (2impl) — beyond agreement with APC alone.",
                because: "APC's generate_card_validation_data agrees with CyberChef Payments — a \
                          purpose-built, inspectable payment-cryptography implementation, a \
                          separate codebase in a different language — over randomized PAN / expiry \
                          / service code with a shared clear CVK. Combined with the proxy==APC \
                          differential above, the proxy's CVV agrees with a second implementation. \
                          Honest strength: CyberChef Payments shares an author with this proxy, so \
                          it cross-checks the implementation (catching coding-level divergence) \
                          rather than being a neutral third-party oracle, and it is less \
                          battle-tested than APC — so this is corroboration; APC (AWS) is the \
                          independent reference. Run separately from this repository's automated \
                          tests.",
                wire: WireGrounding::None,
                crypto: CryptoGrounding::TwoImpl,
                proof: Proof::ManualCite(
                    "cross-validated against CyberChef Payments (a second implementation by the same author); run separately",
                ),
            },
            Evidence {
                decision: "NY (Mastercard CVC3) and RY (Amex CSC) return Unsupported (68).",
                because: "NY's NZ response returns two values (IVCVC3 + CVC3) and RY validates 3 CSC lengths at once / includes AEVV — neither reproducible as APC's single generate/verify_card_validation_data call (PUGD0537-004 Rev A p.493 (NY) / p.315 (RY)).",
                wire: WireGrounding::None,
                crypto: CryptoGrounding::None,
                proof: Proof::Gated("no single-call APC equivalent; see handler doc"),
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
            b"CY" => handle_cy(payload, state).await,
            b"NY" => handle_ny(),
            b"RY" => handle_ry(),
            _ => handle_cw(payload, state).await,
        }
    }
}

async fn handle_cw(body: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_cw(body) {
        Ok(f) => f,
        Err(e) => {
            warn!(?e, "CW parse error");
            return HandlerResult::from_proxy_error(&e);
        }
    };

    let cvk_arn = match state.key_map.resolve_descriptor(&fields.cvk) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        CardGenerationAttributes, CardVerificationValue1,
    };

    let attrs = match CardVerificationValue1::builder()
        .card_expiry_date(&fields.expiry)
        .service_code(&fields.service_code)
        .build()
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => CardGenerationAttributes::CardVerificationValue1(a),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(cvk = %cvk_arn, service = %fields.service_code, "CW: generate_card_validation_data");

    match state
        .data
        .generate_card_validation_data()
        .key_identifier(&cvk_arn)
        .primary_account_number(&fields.pan)
        .generation_attributes(attrs)
        .send()
        .await
    {
        Ok(resp) => HandlerResult::success(resp.validation_data().as_bytes().to_vec()),
        Err(e) => {
            warn!(?e, "CW: generate_card_validation_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

async fn handle_cy(body: &[u8], state: &Arc<AppState>) -> HandlerResult {
    let fields = match parse_cy(body) {
        Ok(f) => f,
        Err(e) => {
            warn!(?e, "CY parse error");
            return HandlerResult::from_proxy_error(&e);
        }
    };

    let cvk_arn = match state.key_map.resolve_descriptor(&fields.cvk) {
        Ok(a) => a.to_string(),
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    use aws_sdk_paymentcryptographydata::types::{
        CardVerificationAttributes, CardVerificationValue1,
    };

    let attrs = match CardVerificationValue1::builder()
        .card_expiry_date(&fields.expiry)
        .service_code(&fields.service_code)
        .build()
        .map(CardVerificationAttributes::CardVerificationValue1)
        .map_err(|e| ProxyError::ApcError(e.to_string()))
    {
        Ok(a) => a,
        Err(e) => return HandlerResult::from_proxy_error(&e),
    };

    debug!(cvk = %cvk_arn, service = %fields.service_code, "CY: verify_card_validation_data");

    match state
        .data
        .verify_card_validation_data()
        .key_identifier(&cvk_arn)
        .primary_account_number(&fields.pan)
        .validation_data(&fields.cvv)
        .verification_attributes(attrs)
        .send()
        .await
    {
        Ok(_) => HandlerResult::success(vec![]),
        Err(e) => {
            if e.as_service_error().is_some_and(aws_sdk_paymentcryptographydata::operation::verify_card_validation_data::VerifyCardValidationDataError::is_verification_failed_exception) {
                warn!("CY: CVV mismatch");
                return HandlerResult::from_proxy_error(&ProxyError::VerificationFailed);
            }
            warn!(?e, "CY: verify_card_validation_data failed");
            HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
        }
    }
}

/// NY — Generate Static CVC3 / IVCVC3 for Mastercard PayPass.
///
/// NOT SUPPORTED ON APC. NY derives a CVC3 session key from an issuer master key
/// (MK-CVC3) and returns *two* values in NZ: the IVCVC3 (5N) and the static
/// CVC3/PINCVC3 (5N). APC's generate_card_validation_data produces a single
/// validation value and exposes no way to emit the intermediate IVCVC3, and the
/// PINIVCVC3/PINCVC3 scheme (Scheme ID '2') and explicit Option A/B derivation
/// selector have no APC equivalent. A wire-compatible NZ therefore cannot be
/// produced. (The previous implementation parsed a fabricated fixed-width layout
/// and mapped to CardVerificationValue1 + DynamicCardVerificationValue, which is
/// the wrong algorithm and the wrong response shape.)
fn handle_ny() -> HandlerResult {
    warn!(
        "NY rejected: PayPass CVC3 returns IVCVC3+CVC3, which APC's single-value API cannot model"
    );
    HandlerResult::from_proxy_error(&ProxyError::Unsupported(
        "NY: Mastercard PayPass CVC3 generation returns both an IVCVC3 and a CVC3; AWS Payment \
         Cryptography returns a single card-validation value and cannot reproduce the NZ response"
            .into(),
    ))
}

/// RY — Calculate/Verify American Express Card Security Codes.
///
/// NOT SUPPORTED ON APC. Despite the name, RY is the Amex CSC command (Mode '3'
/// calculate / '4' verify, with a Flag selecting Classic CSC v1.0, Enhanced CSC
/// v2.0, or AEVV) — not the Visa CVV2 algorithm the previous code mapped it to.
/// Its response carries up to three independently-validated codes (5-digit,
/// 4-digit and 3-digit CSC), and the AEVV (3-D Secure) variant has no APC
/// equivalent. APC's Amex card-security-code support is a single-value
/// generate/verify (AmexCardSecurityCodeVersion1/2) that cannot reproduce RY's
/// multi-length CSC response or the AEVV path, so RY is not wire-translatable.
fn handle_ry() -> HandlerResult {
    warn!("RY rejected: Amex multi-length CSC / AEVV response cannot be modeled on APC");
    HandlerResult::from_proxy_error(&ProxyError::Unsupported(
        "RY: American Express CSC (Classic/Enhanced/AEVV) returns multiple CSC lengths and an AEVV \
         variant that AWS Payment Cryptography's single-value Amex CSC API cannot reproduce"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Double-length CVK, no prefix: 32 hex chars.
    fn cvk32() -> Vec<u8> {
        b"0123456789ABCDEF0123456789ABCDEF".to_vec()
    }

    fn build_cw(cvk: &[u8], pan: &[u8]) -> Vec<u8> {
        let mut v = cvk.to_vec();
        v.extend_from_slice(pan);
        v.push(b';');
        v.extend_from_slice(b"2512"); // expiry
        v.extend_from_slice(b"201"); // service code
        v
    }

    fn build_cy(cvk: &[u8], cvv: &[u8], pan: &[u8]) -> Vec<u8> {
        let mut v = cvk.to_vec();
        v.extend_from_slice(cvv);
        v.extend_from_slice(pan);
        v.push(b';');
        v.extend_from_slice(b"2512");
        v.extend_from_slice(b"000");
        v
    }

    #[test]
    fn cw_parses_16_digit_pan() {
        let f = parse_cw(&build_cw(&cvk32(), b"4111111111111111")).unwrap();
        assert_eq!(f.cvk.raw, "0123456789ABCDEF0123456789ABCDEF");
        assert_eq!(f.pan, "4111111111111111");
        assert_eq!(f.expiry, "2512");
        assert_eq!(f.service_code, "201");
    }

    #[test]
    fn cw_parses_15_digit_amex_pan() {
        // 15-digit PAN would be silently corrupted by a fixed 16-char field.
        let f = parse_cw(&build_cw(&cvk32(), b"371449635398431")).unwrap();
        assert_eq!(f.pan, "371449635398431");
        assert_eq!(f.expiry, "2512");
        assert_eq!(f.service_code, "201");
    }

    #[test]
    fn cw_parses_19_digit_pan() {
        let f = parse_cw(&build_cw(&cvk32(), b"4111111111111111234")).unwrap();
        assert_eq!(f.pan, "4111111111111111234");
    }

    #[test]
    fn cw_parses_u_prefixed_key() {
        let mut cvk = vec![b'U'];
        cvk.extend_from_slice(&cvk32());
        let f = parse_cw(&build_cw(&cvk, b"4111111111111111")).unwrap();
        assert_eq!(f.cvk.raw, "U0123456789ABCDEF0123456789ABCDEF");
        assert_eq!(f.pan, "4111111111111111");
    }

    #[test]
    fn cw_rejects_missing_delimiter() {
        let mut v = cvk32();
        v.extend_from_slice(b"4111111111111111"); // no ';'
        assert!(matches!(parse_cw(&v), Err(ProxyError::MalformedPayload(_))));
    }

    #[test]
    fn cw_rejects_overlong_pan() {
        let mut v = cvk32();
        v.extend_from_slice(b"12345678901234567890"); // 20 digits
        v.push(b';');
        v.extend_from_slice(b"2512201");
        assert!(matches!(parse_cw(&v), Err(ProxyError::MalformedPayload(_))));
    }

    #[test]
    fn cy_parses_cvv_then_variable_pan() {
        let f = parse_cy(&build_cy(&cvk32(), b"123", b"4111111111111111")).unwrap();
        assert_eq!(f.cvv, "123");
        assert_eq!(f.pan, "4111111111111111");
        assert_eq!(f.expiry, "2512");
        assert_eq!(f.service_code, "000");
    }

    #[test]
    fn cy_parses_15_digit_pan() {
        let f = parse_cy(&build_cy(&cvk32(), b"999", b"371449635398431")).unwrap();
        assert_eq!(f.cvv, "999");
        assert_eq!(f.pan, "371449635398431");
    }

    #[test]
    fn ny_unsupported() {
        assert_eq!(handle_ny().error_code, *b"68");
    }

    #[test]
    fn ry_unsupported() {
        assert_eq!(handle_ry().error_code, *b"68");
    }
}
