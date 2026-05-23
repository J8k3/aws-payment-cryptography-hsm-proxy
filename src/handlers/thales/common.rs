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
        None => return Err(ProxyError::MalformedPayload("key field missing".to_string())),
    };
    let total = prefix_len + len;
    if remaining.len() < total {
        return Err(ProxyError::MalformedPayload(format!(
            "key field truncated: need {} bytes at offset {}, got {}",
            total, offset, remaining.len()
        )));
    }
    let key_str = String::from_utf8_lossy(&remaining[..total]).to_string();
    Ok((key_str, total))
}

#[cfg(test)]
mod tests {
    use super::*;

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
