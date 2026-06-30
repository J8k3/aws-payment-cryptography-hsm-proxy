use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::handlers::thales::common::parse_legacy_key;
use crate::handlers::{AppState, Handler, HandlerResult};
use crate::key_map::KeyDescriptor;

/// payShield PIN translation commands.
///
/// CC (→ CD) — Translate a PIN from one ZPK to another        → translate_pin_data
/// CA (→ CB) — Translate a PIN from TPK to ZPK (3DES DUKPT)    → translate_pin_data
/// G0 (→ G1) — Translate a PIN from BDK to BDK/ZPK (DUKPT)     → [unsupported, see below]
/// BQ (→ BR) — Translate PIN Algorithm                        → [unsupported, see below]
///
/// CC / CA wire format (PUGD0537-004 Rev A, p.282 / p.285 — AUTHORITATIVE):
///   Source key        16H | 'U'+32H | 'T'+48H | 'S'+keyblock   (CC: ZPK, CA: TPK)
///   [CA only] Destination Key Flag  1A  ('*' = BDK-1, '~' = BDK-2) — DUKPT dest
///   Destination key   16H | 'U'+32H | 'T'+48H | 'S'+keyblock   (ZPK)
///   Maximum PIN Length  2N
///   Source PIN Block    16H (DES) | 32H (AES, ISO format 4)
///   Source PIN Block Format Code       2N
///   Destination PIN Block Format Code  2N
///   PAN/Token           12N (rightmost 12 excl. check digit, for formats 01/05/47)
///
/// The PIN block format codes are the standard Thales 2N values:
///   '01' = ISO 9564-1 Format 0 (ANSI X9.8)
///   '04' = Plus network format        (no APC equivalent)
///   '05' = ISO 9564-1 Format 1
///   '47' = ISO 9564-1 Format 3
///   '48' = ISO 9564-1 Format 4        (AES, 32H block, variable PAN+delimiter)
///
/// SCOPE: this handler implements the common static 3DES path — CC and CA where
/// the destination is a ZPK and the source/destination formats are 0/1/3 (DES,
/// 16H block, 12N PAN). The following are returned as Unsupported (payShield 68)
/// rather than parsed from an unverified layout:
///   - Format '04' (Plus): no APC equivalent.
///   - Format '48' (ISO 4): needs a 32H AES block and the ISO-4 variable
///     PAN+delimiter encoding, which must be validated against live APC first.
///   - CA with a '*'/'~' Destination Key Flag (DUKPT destination).
///   - G0 (source BDK DUKPT) and BQ (Translate PIN Algorithm): distinct layouts
///     with optional source/destination KSNs that require DUKPT validation.
///     (The previous handler mapped a non-existent 'CI' command and a fabricated
///     fixed-width layout with leading key-type bytes and a '00/01/03/04' format
///     scheme that matches no real Thales message.)
pub struct PinHandler;

const MAX_PIN_LEN_FIELD: usize = 2;
const PIN_BLOCK_DES: usize = 16;
const FMT_CODE_LEN: usize = 2;
const ACCOUNT_LEN: usize = 12;

/// ISO PIN block format selected by a Thales 2N format code, restricted to the
/// DES formats this handler translates.
#[derive(Clone, Copy)]
enum IsoFmt {
    F0,
    F1,
    F3,
}

fn map_translate_format(code: &[u8]) -> Result<IsoFmt, ProxyError> {
    match code {
        b"01" => Ok(IsoFmt::F0),
        b"05" => Ok(IsoFmt::F1),
        b"47" => Ok(IsoFmt::F3),
        b"04" => Err(ProxyError::Unsupported(
            "PIN block format '04' (Plus) has no APC equivalent".into(),
        )),
        b"48" => Err(ProxyError::Unsupported(
            "PIN block format '48' (ISO 4) translate is not yet validated against APC".into(),
        )),
        other => Err(ProxyError::UnsupportedPinFormat(
            String::from_utf8_lossy(other).to_string(),
        )),
    }
}

struct PinFields {
    source_key: KeyDescriptor,
    dest_key: KeyDescriptor,
    source_format: IsoFmt,
    dest_format: IsoFmt,
    pin_block: Zeroizing<String>,
    account_number: String,
}

/// Parse CC (`has_dest_flag` = false) or CA (`has_dest_flag` = true) static
/// translate commands. The DES path: 16H source PIN block, 12N PAN.
fn parse_translate(payload: &[u8], has_dest_flag: bool) -> Result<PinFields, ProxyError> {
    let (source_key, src_len) = parse_legacy_key(payload, 0)?;
    let mut pos = src_len;

    if has_dest_flag {
        // A '*' or '~' flag means the destination is a BDK (DUKPT) — not handled here.
        if let Some(&b'*' | &b'~') = payload.get(pos) {
            return Err(ProxyError::Unsupported(
                "CA with a DUKPT destination (BDK key flag) is not supported".into(),
            ));
        }
    }

    let (dest_key, dest_len) = parse_legacy_key(payload, pos)?;
    pos += dest_len;

    let maxlen_end = pos + MAX_PIN_LEN_FIELD;
    let pin_end = maxlen_end + PIN_BLOCK_DES;
    let src_fmt_end = pin_end + FMT_CODE_LEN;
    let dst_fmt_end = src_fmt_end + FMT_CODE_LEN;
    let acct_end = dst_fmt_end + ACCOUNT_LEN;

    if payload.len() < acct_end {
        return Err(ProxyError::MalformedPayload(format!(
            "translate payload too short: {} < {}",
            payload.len(),
            acct_end
        )));
    }

    let source_format = map_translate_format(&payload[pin_end..src_fmt_end])?;
    let dest_format = map_translate_format(&payload[src_fmt_end..dst_fmt_end])?;

    Ok(PinFields {
        source_key,
        dest_key,
        source_format,
        dest_format,
        pin_block: Zeroizing::new(
            String::from_utf8_lossy(&payload[maxlen_end..pin_end]).to_string(),
        ),
        account_number: String::from_utf8_lossy(&payload[dst_fmt_end..acct_end]).to_string(),
    })
}

#[async_trait]
impl Handler for PinHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["CA", "CC", "BQ", "G0"]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult {
        let fields = match command_code {
            b"CC" => parse_translate(payload, false),
            b"CA" => parse_translate(payload, true),
            b"G0" => {
                warn!("G0 (BDK DUKPT translate) not yet validated against APC; returning 68");
                return HandlerResult::from_proxy_error(&ProxyError::Unsupported(
                    "G0: BDK-to-BDK/ZPK DUKPT PIN translate carries optional source and destination \
                     KSNs and needs DUKPT validation against APC before it can be proxied".into(),
                ));
            }
            b"BQ" => {
                warn!("BQ (Translate PIN Algorithm) not supported; returning 68");
                return HandlerResult::from_proxy_error(&ProxyError::Unsupported(
                    "BQ: Translate PIN Algorithm is a distinct operation not yet mapped to APC"
                        .into(),
                ));
            }
            _ => return HandlerResult::err(*b"68"),
        };

        let fields = match fields {
            Ok(f) => f,
            Err(e) => {
                warn!(?e, cmd = %String::from_utf8_lossy(command_code), "translate parse error");
                return HandlerResult::from_proxy_error(&e);
            }
        };

        let incoming_arn = match state.key_map.resolve_descriptor(&fields.source_key) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };
        let outgoing_arn = match state.key_map.resolve_descriptor(&fields.dest_key) {
            Ok(a) => a.to_string(),
            Err(e) => return HandlerResult::from_proxy_error(&e),
        };

        let incoming_attrs = build_translation_attrs(fields.source_format, &fields.account_number);
        let outgoing_attrs = build_translation_attrs(fields.dest_format, &fields.account_number);
        let (incoming_attrs, outgoing_attrs) = match (incoming_attrs, outgoing_attrs) {
            (Ok(i), Ok(o)) => (i, o),
            (Err(e), _) | (_, Err(e)) => return HandlerResult::from_proxy_error(&e),
        };

        debug!(incoming = %incoming_arn, outgoing = %outgoing_arn, "translate_pin_data");

        match state
            .data
            .translate_pin_data()
            .incoming_key_identifier(&incoming_arn)
            .outgoing_key_identifier(&outgoing_arn)
            .encrypted_pin_block(fields.pin_block.as_str())
            .incoming_translation_attributes(incoming_attrs)
            .outgoing_translation_attributes(outgoing_attrs)
            .send()
            .await
        {
            Ok(resp) => {
                let pin_block_out = Zeroizing::new(resp.pin_block().to_string());
                HandlerResult::success(pin_block_out.as_bytes().to_vec())
            }
            Err(e) => {
                warn!(?e, "translate_pin_data failed");
                HandlerResult::from_proxy_error(&ProxyError::ApcError(e.to_string()))
            }
        }
    }
}

fn build_translation_attrs(
    format: IsoFmt,
    account_number: &str,
) -> Result<aws_sdk_paymentcryptographydata::types::TranslationIsoFormats, ProxyError> {
    use aws_sdk_paymentcryptographydata::types::{
        TranslationIsoFormats, TranslationPinDataIsoFormat034, TranslationPinDataIsoFormat1,
    };
    match format {
        IsoFmt::F0 => Ok(TranslationIsoFormats::IsoFormat0(
            TranslationPinDataIsoFormat034::builder()
                .primary_account_number(account_number)
                .build()
                .map_err(|e| ProxyError::ApcError(e.to_string()))?,
        )),
        IsoFmt::F1 => Ok(TranslationIsoFormats::IsoFormat1(
            TranslationPinDataIsoFormat1::builder().build(),
        )),
        IsoFmt::F3 => Ok(TranslationIsoFormats::IsoFormat3(
            TranslationPinDataIsoFormat034::builder()
                .primary_account_number(account_number)
                .build()
                .map_err(|e| ProxyError::ApcError(e.to_string()))?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key16() -> Vec<u8> {
        b"1234567890ABCDEF".to_vec()
    }

    // CC: source ZPK + dest ZPK + max pin len + pin block + src fmt + dst fmt + PAN
    fn build_cc(src: &[u8], dst: &[u8], src_fmt: &[u8], dst_fmt: &[u8]) -> Vec<u8> {
        let mut v = src.to_vec();
        v.extend_from_slice(dst);
        v.extend_from_slice(b"12"); // max PIN length
        v.extend_from_slice(b"1234567890ABCDEF"); // 16H PIN block
        v.extend_from_slice(src_fmt);
        v.extend_from_slice(dst_fmt);
        v.extend_from_slice(b"432109876543"); // 12N PAN
        v
    }

    #[test]
    fn cc_parses_iso0_to_iso0() {
        let p = build_cc(&key16(), &key16(), b"01", b"01");
        let f = parse_translate(&p, false).unwrap();
        assert_eq!(f.source_key.raw, "1234567890ABCDEF");
        assert_eq!(f.dest_key.raw, "1234567890ABCDEF");
        assert!(matches!(f.source_format, IsoFmt::F0));
        assert!(matches!(f.dest_format, IsoFmt::F0));
        assert_eq!(f.pin_block.as_str(), "1234567890ABCDEF");
        assert_eq!(f.account_number, "432109876543");
    }

    #[test]
    fn cc_parses_format_codes_05_and_47() {
        let p = build_cc(&key16(), &key16(), b"05", b"47");
        let f = parse_translate(&p, false).unwrap();
        assert!(matches!(f.source_format, IsoFmt::F1));
        assert!(matches!(f.dest_format, IsoFmt::F3));
    }

    #[test]
    fn cc_parses_u_prefixed_keys() {
        let mut src = vec![b'U'];
        src.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        let p = build_cc(&src, &key16(), b"01", b"01");
        let f = parse_translate(&p, false).unwrap();
        assert_eq!(f.source_key.raw, "U1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(f.dest_key.raw, "1234567890ABCDEF");
    }

    #[test]
    fn rejects_plus_format() {
        let p = build_cc(&key16(), &key16(), b"04", b"01");
        assert!(matches!(
            parse_translate(&p, false),
            Err(ProxyError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_iso4_format_pending_validation() {
        let p = build_cc(&key16(), &key16(), b"48", b"01");
        assert!(matches!(
            parse_translate(&p, false),
            Err(ProxyError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_unknown_format() {
        let p = build_cc(&key16(), &key16(), b"99", b"01");
        assert!(matches!(
            parse_translate(&p, false),
            Err(ProxyError::UnsupportedPinFormat(_))
        ));
    }

    #[test]
    fn ca_rejects_dukpt_dest_flag() {
        let mut v = key16(); // source TPK
        v.push(b'*'); // BDK-1 destination flag
        v.extend_from_slice(&key16());
        v.extend_from_slice(b"121234567890ABCDEF0101432109876543");
        assert!(matches!(
            parse_translate(&v, true),
            Err(ProxyError::Unsupported(_))
        ));
    }

    #[test]
    fn ca_parses_zpk_dest_no_flag() {
        // CA with a ZPK destination (no flag) parses like CC.
        let p = build_cc(&key16(), &key16(), b"01", b"47");
        let f = parse_translate(&p, true).unwrap();
        assert!(matches!(f.source_format, IsoFmt::F0));
        assert!(matches!(f.dest_format, IsoFmt::F3));
    }
}
