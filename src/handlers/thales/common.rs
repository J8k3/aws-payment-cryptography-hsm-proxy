use crate::error::ProxyError;
use crate::key_map::{KeyBlockMeta, KeyDescriptor};

use aws_sdk_paymentcryptographydata::types::{
    SessionKeyAmex, SessionKeyDerivation, SessionKeyEmv2000, SessionKeyEmvCommon,
    SessionKeyMastercard, SessionKeyVisa,
};

/// Apply EMV (ISO 9797-1 method 2) padding to ARQC MAC input: append a single
/// `0x80`, then `0x00` up to the next 8-byte boundary (always at least one byte).
///
/// APC's `verify_auth_request_cryptogram` MACs the transaction data exactly as
/// supplied and does not pad, whereas the card (and a real payShield) MAC the
/// method-2-padded data. The proxy receives unpadded host data, so it must pad
/// before forwarding — verified against live APC.
pub fn emv_pad(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 8);
    out.extend_from_slice(data);
    out.push(0x80);
    while out.len() % 8 != 0 {
        out.push(0x00);
    }
    out
}

/// Map a Thales 2-digit PIN Block Format Code to the APC `PinBlockFormatForPinData`.
///
/// Source: PUGD0537-004 Rev A ("Only these Thales PIN Block formats are supported"):
///   '01' = ISO 9564-1 & ANSI X9.8 Format 0  -> IsoFormat0
///   '05' = ISO 9564-1 Format 1              -> IsoFormat1
///   '47' = ISO 9564-1 & ANSI X9.8 Format 3  -> IsoFormat3
///   '48' = ISO 9564-1 Format 4 (AES)        -> IsoFormat4
///
/// Docutel ('02'), Diebold/IBM ('03'), PLUS ('04') and EMV-1996 / ISO Format 2 ('34')
/// have no APC equivalent and return an error (payShield 23) rather than silently
/// mis-decoding the PIN block. APC does not default this; the caller must map it.
pub fn map_pin_block_format(
    code: &str,
) -> Result<aws_sdk_paymentcryptographydata::types::PinBlockFormatForPinData, ProxyError> {
    use aws_sdk_paymentcryptographydata::types::PinBlockFormatForPinData;
    match code {
        "01" => Ok(PinBlockFormatForPinData::IsoFormat0),
        "05" => Ok(PinBlockFormatForPinData::IsoFormat1),
        "47" => Ok(PinBlockFormatForPinData::IsoFormat3),
        "48" => Ok(PinBlockFormatForPinData::IsoFormat4),
        other => Err(ProxyError::UnsupportedPinFormat(format!(
            "Thales PIN block format code '{other}' has no APC equivalent (supported: 01/05/47/48)"
        ))),
    }
}

/// EMV session-key derivation method selected by a Thales KQ/KW Scheme ID.
///
/// Mapping verified against PUGD0537-004 Rev A Core Host Commands (KQ p.468, KW p.471)
/// and confirmed end-to-end against live AWS Payment Cryptography: the session
/// method materially changes the derived key, so an incorrect choice causes APC
/// to reject a valid cryptogram (error 01).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmvSession {
    /// EMV Common Session Key derivation (PAN + PAN seq + ATC).
    EmvCommon,
    /// EMV2000 session key derivation (PAN + PAN seq + ATC).
    Emv2000,
    /// Mastercard proprietary session key derivation (PAN + PAN seq + ATC + UN).
    Mastercard,
    /// American Express AEIPS (PAN + PAN seq).
    Amex,
    /// Visa (PAN + PAN seq) — APC's `SessionKeyVisa`, no ATC/UN in derivation.
    Visa,
}

/// Build the APC `SessionKeyDerivation` for `method`.
///
/// `un` (unpredictable number) is consumed only by the Mastercard method; `atc`
/// is consumed by EMV Common / EMV2000 / Mastercard, but not by Amex or Visa
/// (both derive from PAN + PAN seq only). Other arguments unused by a given
/// method are ignored.
pub fn build_session_key(
    method: EmvSession,
    pan: &str,
    pan_seq: &str,
    atc: &str,
    un: &str,
) -> Result<SessionKeyDerivation, ProxyError> {
    // Non-capturing closure: Copy, so it can be reused across the arms' map_err.
    let be =
        |e: aws_sdk_paymentcryptographydata::error::BuildError| ProxyError::ApcError(e.to_string());
    Ok(match method {
        EmvSession::EmvCommon => SessionKeyDerivation::EmvCommon(
            SessionKeyEmvCommon::builder()
                .primary_account_number(pan)
                .pan_sequence_number(pan_seq)
                .application_transaction_counter(atc)
                .build()
                .map_err(be)?,
        ),
        EmvSession::Emv2000 => SessionKeyDerivation::Emv2000(
            SessionKeyEmv2000::builder()
                .primary_account_number(pan)
                .pan_sequence_number(pan_seq)
                .application_transaction_counter(atc)
                .build()
                .map_err(be)?,
        ),
        EmvSession::Mastercard => SessionKeyDerivation::Mastercard(
            SessionKeyMastercard::builder()
                .primary_account_number(pan)
                .pan_sequence_number(pan_seq)
                .application_transaction_counter(atc)
                .unpredictable_number(un)
                .build()
                .map_err(be)?,
        ),
        EmvSession::Amex => SessionKeyDerivation::Amex(
            SessionKeyAmex::builder()
                .primary_account_number(pan)
                .pan_sequence_number(pan_seq)
                .build()
                .map_err(be)?,
        ),
        EmvSession::Visa => SessionKeyDerivation::Visa(
            SessionKeyVisa::builder()
                .primary_account_number(pan)
                .pan_sequence_number(pan_seq)
                .build()
                .map_err(be)?,
        ),
    })
}

/// Parse a TR-31 key block introduced by an 'S' prefix in the wire frame.
///
/// payShield "Key Block LMK" form: a leading 'S' byte followed by an ASCII
/// TR-31 (X9.143) key block. The block self-describes its total length, key
/// usage, and algorithm. If a "KC" optional block is present, the KCV is
/// extracted from it — that is what enables the proxy to resolve the block to
/// an already-imported APC key without any per-application config.
///
/// TR-31 ASCII header (16 chars, positions relative to start of block, not 'S'):
///   0      Version ID            ('A' | 'B' | 'C' | 'D' | 'E')
///   1..5   Block Length          4 decimal chars, total block size
///   5..7   Key Usage             2 chars (TR-31 codes — P0, B0, M1, ...)
///   7      Algorithm             1 char ('A'=AES, 'T'=TDES, 'D'=DES, 'H'=HMAC, …)
///   8      Mode of Use           1 char
///   9..11  Key Version Number    2 chars
///   11     Exportability         1 char
///   12..14 Number of Opt Blocks  2 decimal chars
///   14..16 Reserved              "00"
///
/// Returns `(KeyDescriptor, bytes_consumed)`. `bytes_consumed` includes the
/// leading 'S' (i.e. 1 + declared block length). `KeyDescriptor.raw` is the
/// full wire form including 'S', preserving back-compat with operators that
/// have hard-coded an exact wrapped block in `key_mappings`.
fn parse_tr31_block(buf: &[u8], offset: usize) -> Result<(KeyDescriptor, usize), ProxyError> {
    const HEADER_LEN: usize = 16;
    let remaining = buf.get(offset..).unwrap_or(&[]);
    if remaining.first() != Some(&b'S') {
        return Err(ProxyError::MalformedPayload(
            "expected 'S' prefix for TR-31 key block".into(),
        ));
    }
    if remaining.len() < 1 + HEADER_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "TR-31 block truncated: header needs {} bytes, got {}",
            1 + HEADER_LEN,
            remaining.len()
        )));
    }

    // Skip 'S' — TR-31 positions are relative to the version ID.
    let block = &remaining[1..];

    let length_str = std::str::from_utf8(&block[1..5])
        .map_err(|_| ProxyError::MalformedPayload("TR-31 length field not ASCII".into()))?;
    let block_len: usize = length_str.parse().map_err(|_| {
        ProxyError::MalformedPayload(format!("TR-31 length not decimal: '{length_str}'"))
    })?;
    if block_len < HEADER_LEN {
        return Err(ProxyError::MalformedPayload(format!(
            "TR-31 length {block_len} smaller than header"
        )));
    }
    if remaining.len() < 1 + block_len {
        return Err(ProxyError::MalformedPayload(format!(
            "TR-31 block truncated: declared {block_len} bytes, got {}",
            remaining.len() - 1
        )));
    }

    let key_usage = std::str::from_utf8(&block[5..7])
        .map_err(|_| ProxyError::MalformedPayload("TR-31 key usage not ASCII".into()))?
        .to_string();
    let algorithm = block[7] as char;

    let opt_block_count_str = std::str::from_utf8(&block[12..14])
        .map_err(|_| ProxyError::MalformedPayload("TR-31 opt block count not ASCII".into()))?;
    let opt_block_count: usize = opt_block_count_str.parse().map_err(|_| {
        ProxyError::MalformedPayload(format!(
            "TR-31 opt block count not decimal: '{opt_block_count_str}'"
        ))
    })?;

    let kcv = scan_kc_optional_block(&block[HEADER_LEN..block_len], opt_block_count)?;

    let raw = String::from_utf8_lossy(&remaining[..1 + block_len]).to_string();
    let consumed = 1 + block_len;
    Ok((
        KeyDescriptor {
            raw,
            block: Some(KeyBlockMeta {
                key_usage,
                algorithm,
                kcv,
            }),
        },
        consumed,
    ))
}

/// Walk TR-31 optional blocks looking for "KC" (Key Check Value).
///
/// Optional block format (X9.143):
///   ID:     2 ASCII chars
///   Length: 2 hex chars (length of the WHOLE optional block including ID+length)
///   Data:   (Length - 4) chars
///
/// If Length = "00", an extended length field follows (rare; not encountered in
/// practice for KC blocks under 256 chars). We bail out of the scan on
/// extended-length blocks rather than misinterpret them.
///
/// "KC" data layout:
///   2 chars   KCV version ("00" = legacy per X9.24-1, "01" = CMAC-based)
///   N chars   KCV value (hex). Typically 6 chars for TDES, 8 for AES.
fn scan_kc_optional_block(
    opt_area: &[u8],
    expected_count: usize,
) -> Result<Option<String>, ProxyError> {
    let mut pos = 0;
    for _ in 0..expected_count {
        if opt_area.len() < pos + 4 {
            return Err(ProxyError::MalformedPayload(
                "TR-31 optional block header truncated".into(),
            ));
        }
        let id = &opt_area[pos..pos + 2];
        let len_str = std::str::from_utf8(&opt_area[pos + 2..pos + 4])
            .map_err(|_| ProxyError::MalformedPayload("TR-31 opt block length not ASCII".into()))?;
        let len = usize::from_str_radix(len_str, 16).map_err(|_| {
            ProxyError::MalformedPayload(format!("TR-31 opt block length not hex: '{len_str}'"))
        })?;
        if len == 0 {
            // Extended-length form — not parsed here. Don't fail the whole block
            // resolution; KCV resolution just becomes None and the resolver will
            // surface a clear error if no label fallback exists.
            return Ok(None);
        }
        if len < 4 || opt_area.len() < pos + len {
            return Err(ProxyError::MalformedPayload(
                "TR-31 optional block length inconsistent".into(),
            ));
        }
        if id == b"KC" {
            // Data starts at pos+4; first 2 bytes are KCV version, rest is KCV hex.
            if len < 6 {
                return Err(ProxyError::MalformedPayload(
                    "TR-31 KC optional block missing KCV".into(),
                ));
            }
            let kcv = std::str::from_utf8(&opt_area[pos + 6..pos + len]).map_err(|_| {
                ProxyError::MalformedPayload("TR-31 KC block value not ASCII".into())
            })?;
            return Ok(Some(kcv.to_ascii_uppercase()));
        }
        pos += len;
    }
    Ok(None)
}

/// Parse a legacy payShield variable-length key field starting at `buf[offset]`.
///
/// Supported wire forms:
///   16H          — single-length variant LMK key
///   'U' + 32H    — double-length variant LMK key
///   'T' + 48H    — triple-length variant LMK key
///   'S' + TR-31  — wrapped key block (resolves via KCV index from APC scan)
///
/// Returns `(KeyDescriptor, bytes_consumed)`. The descriptor is what
/// `KeyMap::resolve_descriptor` consumes.
pub fn parse_legacy_key(buf: &[u8], offset: usize) -> Result<(KeyDescriptor, usize), ProxyError> {
    let remaining = buf.get(offset..).unwrap_or(&[]);
    let (len, prefix_len) = match remaining.first() {
        Some(&b'S') => return parse_tr31_block(buf, offset),
        Some(&b'U') => (32, 1),
        Some(&b'T') => (48, 1),
        Some(_) => (16, 0),
        None => {
            return Err(ProxyError::MalformedPayload(
                "key field missing".to_string(),
            ))
        }
    };
    let total = prefix_len + len;
    if remaining.len() < total {
        return Err(ProxyError::MalformedPayload(format!(
            "key field truncated: need {} bytes at offset {}, got {}",
            total,
            offset,
            remaining.len()
        )));
    }
    let raw = String::from_utf8_lossy(&remaining[..total]).to_string();
    Ok((KeyDescriptor::label(raw), total))
}

/// Parse a BDK field: 32H (double-length baseline), 'U'+32H, or 'S'+TR-31.
///
/// BDK (Base Derivation Key) is always at least double-length, so the
/// no-prefix case is 32 hex chars (not 16). Used by DUKPT verify commands
/// (CK, CM, CO, CQ) where the BDK is encrypted under LMK pair 28-29.
pub fn parse_bdk(buf: &[u8], offset: usize) -> Result<(KeyDescriptor, usize), ProxyError> {
    let remaining = buf.get(offset..).unwrap_or(&[]);
    let total = match remaining.first() {
        Some(&b'S') => return parse_tr31_block(buf, offset),
        Some(&b'U') => 33,
        Some(_) => 32,
        None => {
            return Err(ProxyError::MalformedPayload(
                "BDK field missing".to_string(),
            ))
        }
    };
    if remaining.len() < total {
        return Err(ProxyError::MalformedPayload(format!(
            "BDK field truncated: need {} at offset {}, got {}",
            total,
            offset,
            remaining.len()
        )));
    }
    let raw = String::from_utf8_lossy(&remaining[..total]).to_string();
    Ok((KeyDescriptor::label(raw), total))
}

/// Parse a key field with 32H baseline: 32H | 'U'+32H | 'T'+48H | 'S'+TR-31.
///
/// Used for keys that are always at least double-length — e.g. CM's PVK
/// (Visa PIN Verification Key under LMK pair 14-15 variant 0).
pub fn parse_key_32(buf: &[u8], offset: usize) -> Result<(KeyDescriptor, usize), ProxyError> {
    let remaining = buf.get(offset..).unwrap_or(&[]);
    let (len, prefix_len) = match remaining.first() {
        Some(&b'S') => return parse_tr31_block(buf, offset),
        Some(&b'U') => (32, 1),
        Some(&b'T') => (48, 1),
        Some(_) => (32, 0),
        None => {
            return Err(ProxyError::MalformedPayload(
                "key field (32H-base) missing".to_string(),
            ))
        }
    };
    let total = prefix_len + len;
    if remaining.len() < total {
        return Err(ProxyError::MalformedPayload(format!(
            "key field (32H-base) truncated: need {} at offset {}, got {}",
            total,
            offset,
            remaining.len()
        )));
    }
    let raw = String::from_utf8_lossy(&remaining[..total]).to_string();
    Ok((KeyDescriptor::label(raw), total))
}

/// Parse a KSN descriptor (3H) and the KSN that follows it.
///
/// payShield KSN descriptor format:
///   Char 0:   key type nibble (consumed, not returned)
///   Chars 1-2: KSN length in nibbles as 2-char hex (e.g. "14" = 20 nibbles = 10 bytes)
///
/// Returns `(ksn_string, total_bytes_consumed)` where total includes the 3H descriptor.
///
/// Derivation type by KSN length:
///   20H (10 bytes) → 3DES DUKPT (X9.24-1)  → DukptDerivationType::Tdes2Key
///   24H (12 bytes) → AES DUKPT  (X9.24-3)  → DukptDerivationType::Aes128
pub fn parse_ksn_with_descriptor(
    buf: &[u8],
    offset: usize,
) -> Result<
    (
        String,
        usize,
        aws_sdk_paymentcryptographydata::types::DukptDerivationType,
    ),
    ProxyError,
> {
    use aws_sdk_paymentcryptographydata::types::DukptDerivationType;

    const DESC_LEN: usize = 3;
    let remaining = buf.get(offset..).unwrap_or(&[]);
    if remaining.len() < DESC_LEN {
        return Err(ProxyError::MalformedPayload(
            "KSN descriptor missing".into(),
        ));
    }

    let nibble_hex = std::str::from_utf8(&remaining[1..3])
        .map_err(|_| ProxyError::MalformedPayload("KSN descriptor not ASCII".into()))?;
    let ksn_nibbles = usize::from_str_radix(nibble_hex, 16).map_err(|_| {
        ProxyError::MalformedPayload(format!(
            "KSN descriptor: invalid nibble count '{nibble_hex}'"
        ))
    })?;

    if remaining.len() < DESC_LEN + ksn_nibbles {
        return Err(ProxyError::MalformedPayload(format!(
            "KSN truncated: need {ksn_nibbles}H at offset {}, got {}",
            offset + DESC_LEN,
            remaining.len() - DESC_LEN,
        )));
    }

    let ksn = String::from_utf8_lossy(&remaining[DESC_LEN..DESC_LEN + ksn_nibbles]).to_string();

    let deriv_type = match ksn_nibbles {
        20 => DukptDerivationType::Tdes2Key, // X9.24-1
        24 => DukptDerivationType::Aes128,   // X9.24-3
        n => {
            return Err(ProxyError::MalformedPayload(format!(
                "KSN length {n}H not supported (expected 20H 3DES or 24H AES)"
            )))
        }
    };

    Ok((ksn, DESC_LEN + ksn_nibbles, deriv_type))
}

/// Convert a byte slice to an uppercase hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            write!(s, "{b:02X}").expect("write to String is infallible");
            s
        })
}

/// Decode the EMV "pre-formatted" PAN/PAN-Sequence field (8 BCD bytes = 16
/// digits) into `(pan, pan_seq)` for APC.
///
/// Per EMV Book 2 Annex A1.4.1 this field carries the RIGHTMOST 16 digits of
/// (PAN || 2-digit PAN sequence number), left zero-padded — NOT a left-justified
/// PAN with 0xF padding. The last two digits are the PAN sequence number; the
/// preceding 14 are the rightmost PAN digits. The EMV Option A left zero-padding
/// is stripped so APC receives a conventional PAN — the derivation value is
/// unchanged because APC re-applies `rightmost16(PAN || PSN)` internally.
/// Verified against live APC: a 16-digit-PAN ARQC verifies (error 00) with this
/// split (16-digit PANs have no leading zero, so the strip is a no-op there).
pub fn decode_bcd_pan_seq(bytes: [u8; 8]) -> (String, String) {
    let hex = bytes_to_hex(&bytes); // exactly 16 BCD digits
    let pan_seq = hex[14..16].to_string();
    let pan = hex[..14].trim_start_matches('0').to_string();
    (pan, pan_seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_hex_values() {
        assert_eq!(bytes_to_hex(&[0xDE, 0xAD, 0xBE, 0xEF]), "DEADBEEF");
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn decode_bcd_pan_and_seq() {
        // EMV pre-formatted (rightmost 16 of PAN||PSN): "1234567890123401" -> first 14 / last 2.
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x01];
        let (pan, seq) = decode_bcd_pan_seq(bytes);
        assert_eq!(pan, "12345678901234");
        assert_eq!(seq, "01");
    }

    #[test]
    fn decode_bcd_pan_seq_strips_option_a_padding() {
        // 12-digit PAN 123456789012, PSN 01 → EMV Option A pre-format =
        // rightmost-16(PAN‖PSN) left zero-padded: "0012345678901201". The Option A
        // padding is stripped to recover the conventional PAN.
        let bytes = [0x00, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x01];
        let (pan, seq) = decode_bcd_pan_seq(bytes);
        assert_eq!(pan, "123456789012");
        assert_eq!(seq, "01");
    }

    #[test]
    fn single_length_key() {
        let buf = b"1234567890ABCDEF rest";
        let (desc, consumed) = parse_legacy_key(buf, 0).unwrap();
        assert_eq!(desc.raw, "1234567890ABCDEF");
        assert!(desc.block.is_none());
        assert_eq!(consumed, 16);
    }

    #[test]
    fn double_length_key() {
        let mut buf = Vec::new();
        buf.push(b'U');
        buf.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        buf.extend_from_slice(b"extra");
        let (desc, consumed) = parse_legacy_key(&buf, 0).unwrap();
        assert_eq!(&desc.raw[..1], "U");
        assert_eq!(consumed, 33);
    }

    #[test]
    fn triple_length_key() {
        let mut buf = Vec::new();
        buf.push(b'T');
        buf.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
        let (desc, consumed) = parse_legacy_key(&buf, 0).unwrap();
        assert_eq!(&desc.raw[..1], "T");
        assert_eq!(consumed, 49);
    }

    #[test]
    fn ksn_descriptor_tdes_20h() {
        let mut buf = b"014".to_vec();
        buf.extend_from_slice(b"12345678901234567890");
        buf.extend_from_slice(b"extra");
        let (ksn, consumed, deriv) = parse_ksn_with_descriptor(&buf, 0).unwrap();
        assert_eq!(ksn, "12345678901234567890");
        assert_eq!(consumed, 23);
        assert!(matches!(
            deriv,
            aws_sdk_paymentcryptographydata::types::DukptDerivationType::Tdes2Key
        ));
    }

    #[test]
    fn ksn_descriptor_aes_24h() {
        let mut buf = b"018".to_vec();
        buf.extend_from_slice(b"123456789012345678901234");
        let (ksn, consumed, deriv) = parse_ksn_with_descriptor(&buf, 0).unwrap();
        assert_eq!(ksn.len(), 24);
        assert_eq!(consumed, 27);
        assert!(matches!(
            deriv,
            aws_sdk_paymentcryptographydata::types::DukptDerivationType::Aes128
        ));
    }

    #[test]
    fn ksn_descriptor_with_offset() {
        let mut buf = b"SKIP014".to_vec();
        buf.extend_from_slice(b"12345678901234567890");
        let (ksn, consumed, _) = parse_ksn_with_descriptor(&buf, 4).unwrap();
        assert_eq!(ksn, "12345678901234567890");
        assert_eq!(consumed, 23);
    }

    #[test]
    fn ksn_descriptor_rejects_unsupported_length() {
        let mut buf = b"010".to_vec();
        buf.extend_from_slice(b"1234567890123456");
        assert!(parse_ksn_with_descriptor(&buf, 0).is_err());
    }

    #[test]
    fn truncated_single_returns_error() {
        let buf = b"1234";
        assert!(parse_legacy_key(buf, 0).is_err());
    }

    #[test]
    fn truncated_double_returns_error() {
        let buf = b"U1234";
        assert!(parse_legacy_key(buf, 0).is_err());
    }

    #[test]
    fn empty_returns_error() {
        assert!(parse_legacy_key(b"", 0).is_err());
    }

    #[test]
    fn nonzero_offset() {
        let buf = b"SKIP1234567890ABCDEF";
        let (desc, consumed) = parse_legacy_key(buf, 4).unwrap();
        assert_eq!(desc.raw, "1234567890ABCDEF");
        assert_eq!(consumed, 16);
    }

    // ── TR-31 wrapped key block ─────────────────────────────────────────────

    /// Build an 'S'-prefixed TR-31 ASCII block. Length is set automatically.
    fn build_tr31(
        usage: &str,
        algo: char,
        opt_blocks: &[u8],
        encrypted_payload_chars: &str,
    ) -> Vec<u8> {
        let header_no_length = format!(
            "{ver}LLLL{usage}{algo}{mode}{ver_no}{exp}{opt_count:02}{reserved}",
            ver = "D",
            usage = usage,
            algo = algo,
            mode = "B",
            ver_no = "00",
            exp = "N",
            opt_count = count_opt_blocks(opt_blocks),
            reserved = "00",
        );
        let total = header_no_length.len() + opt_blocks.len() + encrypted_payload_chars.len();
        let mut header = header_no_length.into_bytes();
        let len_str = format!("{total:04}");
        header[1..5].copy_from_slice(len_str.as_bytes());

        let mut out = vec![b'S'];
        out.extend_from_slice(&header);
        out.extend_from_slice(opt_blocks);
        out.extend_from_slice(encrypted_payload_chars.as_bytes());
        out
    }

    fn count_opt_blocks(opt_area: &[u8]) -> usize {
        let mut count = 0;
        let mut pos = 0;
        while pos + 4 <= opt_area.len() {
            let len_str = std::str::from_utf8(&opt_area[pos + 2..pos + 4]).unwrap();
            let len = usize::from_str_radix(len_str, 16).unwrap();
            if len == 0 || pos + len > opt_area.len() {
                break;
            }
            count += 1;
            pos += len;
        }
        count
    }

    /// A "KC" optional block with version "00" and a 6-char KCV.
    fn kc_block(kcv: &str) -> Vec<u8> {
        // ID(2) + Length(2) + Version(2) + KCV
        let total_len = 2 + 2 + 2 + kcv.len();
        let mut v = format!("KC{total_len:02X}00").into_bytes();
        v.extend_from_slice(kcv.as_bytes());
        v
    }

    #[test]
    fn tr31_block_with_kc_extracts_kcv() {
        let mut buf = build_tr31("P0", 'T', &kc_block("ABCDEF"), "FAKEENCRYPTEDDATA1234567");
        buf.extend_from_slice(b"trailing");

        let (desc, consumed) = parse_legacy_key(&buf, 0).unwrap();
        let block = desc.block.expect("block metadata");
        assert_eq!(block.key_usage, "P0");
        assert_eq!(block.algorithm, 'T');
        assert_eq!(block.kcv.as_deref(), Some("ABCDEF"));
        assert_eq!(consumed, desc.raw.len());
        assert!(consumed < buf.len()); // didn't consume trailing
    }

    #[test]
    fn tr31_block_without_kc_yields_no_kcv() {
        let buf = build_tr31("M6", 'A', &[], "FAKEENCRYPTEDDATA1234567");
        let (desc, _) = parse_legacy_key(&buf, 0).unwrap();
        let block = desc.block.expect("block metadata");
        assert_eq!(block.key_usage, "M6");
        assert_eq!(block.algorithm, 'A');
        assert!(block.kcv.is_none());
    }

    #[test]
    fn tr31_block_normalizes_kcv_to_uppercase() {
        let buf = build_tr31("P0", 'T', &kc_block("abcdef"), "DATA");
        let (desc, _) = parse_legacy_key(&buf, 0).unwrap();
        assert_eq!(desc.block.unwrap().kcv.as_deref(), Some("ABCDEF"));
    }

    #[test]
    fn tr31_block_skips_other_optional_blocks_before_kc() {
        // "KS" optional block (key set ID, 8 chars total = ID(2)+LEN(2)+DATA(4)) before "KC".
        let mut opts = b"KS080012".to_vec(); // ID=KS, len=08, data=0012
        opts.extend_from_slice(&kc_block("123456"));
        let buf = build_tr31("M1", 'T', &opts, "DATA");
        let (desc, _) = parse_legacy_key(&buf, 0).unwrap();
        assert_eq!(desc.block.unwrap().kcv.as_deref(), Some("123456"));
    }

    #[test]
    fn tr31_truncated_returns_error() {
        let mut buf = build_tr31("P0", 'T', &kc_block("ABCDEF"), "DATA");
        buf.truncate(buf.len() - 2);
        assert!(parse_legacy_key(&buf, 0).is_err());
    }

    #[test]
    fn tr31_bad_length_field_returns_error() {
        let mut buf = build_tr31("P0", 'T', &kc_block("ABCDEF"), "DATA");
        buf[1..5].copy_from_slice(b"XXXX");
        assert!(parse_legacy_key(&buf, 0).is_err());
    }

    #[test]
    fn parse_bdk_handles_tr31_prefix() {
        let buf = build_tr31("B0", 'T', &kc_block("08D7B4"), "ENCRYPTEDDATAHERE1234567");
        let (desc, _) = parse_bdk(&buf, 0).unwrap();
        let block = desc.block.expect("block metadata");
        assert_eq!(block.key_usage, "B0");
        assert_eq!(block.kcv.as_deref(), Some("08D7B4"));
    }

    #[test]
    fn parse_key_32_handles_tr31_prefix() {
        let buf = build_tr31("V2", 'T', &kc_block("664CDA"), "ENCRYPTEDDATAHERE1234567");
        let (desc, _) = parse_key_32(&buf, 0).unwrap();
        let block = desc.block.expect("block metadata");
        assert_eq!(block.key_usage, "V2");
    }
}
