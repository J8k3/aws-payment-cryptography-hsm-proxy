//! `FieldReader` — a bounds-checked cursor for parsing binary/ASCII HSM wire
//! payloads.
//!
//! Replaces the repeated
//! ```ignore
//! if buf.len() < pos + N { return Err(ProxyError::MalformedPayload(..)); }
//! let field = &buf[pos..pos + N];
//! pos += N;
//! ```
//! idiom with fallible `take*` methods that return `ProxyError::MalformedPayload`
//! on underflow instead of panicking — which is why `bytes::Buf` is not used here
//! (its readers panic on underflow, so guarding every call would just reintroduce
//! the manual bounds check). Every method advances the cursor by exactly the bytes
//! it consumes; `ctx` (the command name) prefixes every error.

use crate::error::ProxyError;

pub(crate) struct FieldReader<'a> {
    buf: &'a [u8],
    pos: usize,
    ctx: &'static str,
}

impl<'a> FieldReader<'a> {
    pub(crate) fn new(buf: &'a [u8], ctx: &'static str) -> Self {
        Self { buf, pos: 0, ctx }
    }

    /// Current offset into the payload.
    // Adopted incrementally across the parser migration on this branch.
    #[allow(dead_code)]
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    /// The not-yet-consumed remainder of the payload.
    #[allow(dead_code)]
    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos.min(self.buf.len())..]
    }

    fn truncated(&self, n: usize, field: &'static str) -> ProxyError {
        ProxyError::MalformedPayload(format!(
            "{}: {field} truncated (need {n} at offset {}, have {})",
            self.ctx,
            self.pos,
            self.buf.len().saturating_sub(self.pos),
        ))
    }

    /// Take the next `n` bytes, advancing the cursor.
    pub(crate) fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], ProxyError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| self.truncated(n, field))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Take exactly `N` bytes as a fixed-size array.
    pub(crate) fn take_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], ProxyError> {
        Ok(self
            .take(N, field)?
            .try_into()
            .expect("take returned exactly N bytes"))
    }

    /// Take a single byte.
    pub(crate) fn byte(&mut self, field: &'static str) -> Result<u8, ProxyError> {
        Ok(self.take(1, field)?[0])
    }

    /// Take one byte and require it equals `expected` (e.g. a `0x3B` delimiter).
    pub(crate) fn expect_byte(
        &mut self,
        expected: u8,
        field: &'static str,
    ) -> Result<(), ProxyError> {
        let at = self.pos;
        let b = self.byte(field)?;
        if b != expected {
            return Err(ProxyError::MalformedPayload(format!(
                "{}: expected {field} 0x{expected:02X} at offset {at}, got 0x{b:02X}",
                self.ctx,
            )));
        }
        Ok(())
    }

    /// Take a 2-byte big-endian integer, returned as `usize`.
    pub(crate) fn u16_be(&mut self, field: &'static str) -> Result<usize, ProxyError> {
        Ok(u16::from_be_bytes(self.take_array::<2>(field)?) as usize)
    }

    /// Run an existing `(buf, offset) -> (T, bytes_consumed)` sub-parser at the
    /// current position, advancing the cursor by what it consumed. Bridges the
    /// variable-length key parsers (`parse_legacy_key` / `parse_bdk` /
    /// `parse_key_32` / `parse_ksn_with_descriptor`) into the reader.
    pub(crate) fn parse_with<T>(
        &mut self,
        f: impl FnOnce(&'a [u8], usize) -> Result<(T, usize), ProxyError>,
    ) -> Result<T, ProxyError> {
        let (val, consumed) = f(self.buf, self.pos)?;
        self.pos += consumed;
        Ok(val)
    }

    /// Take `n` bytes and return them as an uppercase hex string (the wire form
    /// the proxy forwards to APC).
    pub(crate) fn take_hex(&mut self, n: usize, field: &'static str) -> Result<String, ProxyError> {
        Ok(hex::encode_upper(self.take(n, field)?))
    }

    /// Decode a `width`-character ASCII length field in the given `radix`, then
    /// take that many bytes and return them. Collapses the "ASCII length prefix
    /// then payload" pattern shared by the JS / MAC / encrypt handlers.
    pub(crate) fn take_ascii_len_field(
        &mut self,
        width: usize,
        radix: u32,
        field: &'static str,
    ) -> Result<&'a [u8], ProxyError> {
        let len_str = std::str::from_utf8(self.take(width, field)?).map_err(|_| {
            ProxyError::MalformedPayload(format!("{}: {field} length not ASCII", self.ctx))
        })?;
        let len = usize::from_str_radix(len_str, radix).map_err(|_| {
            ProxyError::MalformedPayload(format!(
                "{}: invalid {field} length '{len_str}'",
                self.ctx
            ))
        })?;
        self.take(len, field)
    }

    /// Like [`take_ascii_len_field`], but for the MAC-family message field where
    /// the decoded length counts *message bytes* while the field itself is ASCII
    /// hex (2 chars per byte). Takes `2 * byte_len` bytes and returns the raw
    /// slice (callers choose `from_utf8` vs `from_utf8_lossy`).
    ///
    /// [`take_ascii_len_field`]: Self::take_ascii_len_field
    pub(crate) fn take_ascii_len_hex(
        &mut self,
        width: usize,
        radix: u32,
        field: &'static str,
    ) -> Result<&'a [u8], ProxyError> {
        let len_str = std::str::from_utf8(self.take(width, field)?).map_err(|_| {
            ProxyError::MalformedPayload(format!("{}: {field} length not ASCII", self.ctx))
        })?;
        let byte_len = usize::from_str_radix(len_str, radix).map_err(|_| {
            ProxyError::MalformedPayload(format!(
                "{}: invalid {field} length '{len_str}'",
                self.ctx
            ))
        })?;
        self.take(byte_len * 2, field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_advances_and_bounds_check() {
        let mut r = FieldReader::new(&[1, 2, 3, 4], "T");
        assert_eq!(r.take(2, "a").unwrap(), &[1, 2]);
        assert_eq!(r.pos(), 2);
        assert_eq!(r.remaining(), &[3, 4]);
        assert_eq!(r.take(2, "b").unwrap(), &[3, 4]);
        assert!(matches!(
            r.take(1, "c"),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn take_past_end_errors_not_panics() {
        let mut r = FieldReader::new(&[0xAA], "T");
        assert!(matches!(
            r.take(4, "big"),
            Err(ProxyError::MalformedPayload(_))
        ));
        // cursor unmoved after a failed take
        assert_eq!(r.pos(), 0);
    }

    #[test]
    fn take_overflow_is_error() {
        let mut r = FieldReader::new(&[0; 4], "T");
        assert!(matches!(
            r.take(usize::MAX, "huge"),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn array_hex_u16_byte() {
        let mut r = FieldReader::new(&[0xDE, 0xAD, 0x00, 0x10, 0x3B], "T");
        assert_eq!(r.take_hex(2, "x").unwrap(), "DEAD");
        assert_eq!(r.u16_be("len").unwrap(), 16);
        assert_eq!(r.byte("b").unwrap(), 0x3B);
    }

    #[test]
    fn expect_byte_matches_and_mismatches() {
        let mut r = FieldReader::new(&[0x3B, 0x40], "T");
        assert!(r.expect_byte(0x3B, "delim").is_ok());
        assert!(matches!(
            r.expect_byte(0x3B, "delim"),
            Err(ProxyError::MalformedPayload(_))
        ));
    }

    #[test]
    fn ascii_len_field_reads_payload() {
        // "04" (hex) = 4 bytes follow
        let buf = [b'0', b'4', 1, 2, 3, 4, 9];
        let mut r = FieldReader::new(&buf, "MAC");
        assert_eq!(r.take_ascii_len_field(2, 16, "msg").unwrap(), &[1, 2, 3, 4]);
        assert_eq!(r.remaining(), &[9]);
    }

    #[test]
    fn ascii_len_field_rejects_non_ascii_and_bad_radix() {
        let mut r = FieldReader::new(&[0xFF, 0xFE, 0, 0], "MAC");
        assert!(matches!(
            r.take_ascii_len_field(2, 16, "msg"),
            Err(ProxyError::MalformedPayload(_))
        ));
        let mut r2 = FieldReader::new(b"ZZ", "MAC");
        assert!(matches!(
            r2.take_ascii_len_field(2, 16, "msg"),
            Err(ProxyError::MalformedPayload(_))
        ));
    }
}
