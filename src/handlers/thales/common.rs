use crate::error::ProxyError;

/// Parse a legacy payShield variable-length key field starting at `buf[offset]`.
///
/// Legacy commands encode key material in one of three forms:
///   16H          — single-length key (16 hex chars, 8 bytes)
///   'U' + 32H    — double-length key (33 chars total)
///   'T' + 48H    — triple-length key (49 chars total)
///
/// Returns `(key_identifier, bytes_consumed)`. The key identifier (including
/// any 'U'/'T' prefix) is passed to `KeyMap::resolve` as-is; the administrator's
/// key_mappings must use the same form that the legacy application sends.
pub fn parse_legacy_key(buf: &[u8], offset: usize) -> Result<(String, usize), ProxyError> {
    let remaining = buf.get(offset..).unwrap_or(&[]);
    let (len, prefix_len) = match remaining.first() {
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
    let key_str = String::from_utf8_lossy(&remaining[..total]).to_string();
    Ok((key_str, total))
}

/// Parse a BDK field: 32H (double-length baseline) or 'U'+32H.
///
/// BDK (Base Derivation Key) is always at least double-length, so the no-prefix
/// case is 32 hex chars (not 16). Used by DUKPT verify commands (CK, CM, CO, CQ)
/// where the BDK is encrypted under LMK pair 28-29.
///
/// 'S' prefix (Key Block LMK / TR-31) is not supported.
pub fn parse_bdk(buf: &[u8], offset: usize) -> Result<(String, usize), ProxyError> {
    let remaining = buf.get(offset..).unwrap_or(&[]);
    let (total, ok) = match remaining.first() {
        Some(&b'U') => (33, true),
        Some(&b'S') => {
            return Err(ProxyError::MalformedPayload(
                "Key Block LMK ('S' prefix) BDK not supported".to_string(),
            ))
        }
        Some(_) => (32, true),
        None => {
            return Err(ProxyError::MalformedPayload(
                "BDK field missing".to_string(),
            ))
        }
    };
    if !ok || remaining.len() < total {
        return Err(ProxyError::MalformedPayload(format!(
            "BDK field truncated: need {} at offset {}, got {}",
            total,
            offset,
            remaining.len()
        )));
    }
    Ok((
        String::from_utf8_lossy(&remaining[..total]).to_string(),
        total,
    ))
}

/// Parse a key field with 32H baseline: 32H | 'U'+32H | 'T'+48H.
///
/// Used for keys that are always at least double-length — e.g. CM's PVK
/// (Visa PIN Verification Key under LMK pair 14-15 variant 0).
pub fn parse_key_32(buf: &[u8], offset: usize) -> Result<(String, usize), ProxyError> {
    let remaining = buf.get(offset..).unwrap_or(&[]);
    let (len, prefix_len) = match remaining.first() {
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
    Ok((
        String::from_utf8_lossy(&remaining[..total]).to_string(),
        total,
    ))
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

/// Decode 8 BCD bytes → `(pan_12_digits, pan_seq_2_digits)`.
///
/// The 8 bytes encode 16 nibbles: first 12 = rightmost PAN digits,
/// next 2 = PAN sequence number, last 2 = 0xF padding.
pub fn decode_bcd_pan_seq(bytes: [u8; 8]) -> (String, String) {
    let hex = bytes_to_hex(&bytes);
    (hex[..12].to_string(), hex[12..14].to_string())
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
        // PAN=123456789012, Seq=01 → BCD: 0x12,0x34,0x56,0x78,0x90,0x12,0x01,0xFF
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x01, 0xFF];
        let (pan, seq) = decode_bcd_pan_seq(bytes);
        assert_eq!(pan, "123456789012");
        assert_eq!(seq, "01");
    }

    #[test]
    fn single_length_key() {
        let buf = b"1234567890ABCDEF rest";
        let (key, consumed) = parse_legacy_key(buf, 0).unwrap();
        assert_eq!(key, "1234567890ABCDEF");
        assert_eq!(consumed, 16);
    }

    #[test]
    fn double_length_key() {
        let mut buf = Vec::new();
        buf.push(b'U');
        buf.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF");
        buf.extend_from_slice(b"extra");
        let (key, consumed) = parse_legacy_key(&buf, 0).unwrap();
        assert_eq!(&key[..1], "U");
        assert_eq!(consumed, 33);
    }

    #[test]
    fn triple_length_key() {
        let mut buf = Vec::new();
        buf.push(b'T');
        buf.extend_from_slice(b"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
        let (key, consumed) = parse_legacy_key(&buf, 0).unwrap();
        assert_eq!(&key[..1], "T");
        assert_eq!(consumed, 49);
    }

    #[test]
    fn ksn_descriptor_tdes_20h() {
        // Descriptor "014" → key type '0', nibbles = 0x14 = 20 → 20H KSN
        let mut buf = b"014".to_vec();
        buf.extend_from_slice(b"12345678901234567890"); // 20H KSN
        buf.extend_from_slice(b"extra");
        let (ksn, consumed, deriv) = parse_ksn_with_descriptor(&buf, 0).unwrap();
        assert_eq!(ksn, "12345678901234567890");
        assert_eq!(consumed, 23); // 3 descriptor + 20 KSN
        assert!(matches!(
            deriv,
            aws_sdk_paymentcryptographydata::types::DukptDerivationType::Tdes2Key
        ));
    }

    #[test]
    fn ksn_descriptor_aes_24h() {
        // Descriptor "018" → nibbles = 0x18 = 24 → 24H KSN, AES-128
        let mut buf = b"018".to_vec();
        buf.extend_from_slice(b"123456789012345678901234"); // 24H KSN
        let (ksn, consumed, deriv) = parse_ksn_with_descriptor(&buf, 0).unwrap();
        assert_eq!(ksn.len(), 24);
        assert_eq!(consumed, 27); // 3 + 24
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
        // "010" → nibbles = 0x10 = 16 → not 20 or 24, should error
        let mut buf = b"010".to_vec();
        buf.extend_from_slice(b"1234567890123456"); // 16H
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
        let (key, consumed) = parse_legacy_key(buf, 4).unwrap();
        assert_eq!(key, "1234567890ABCDEF");
        assert_eq!(consumed, 16);
    }
}
