use super::{ParsedCommand, Protocol};
use bytes::Bytes;

/// Thales payShield 10K host command framing.
///
/// Request wire format:
///   [2B big-endian length][2B header][2B command code][variable payload]
///
/// Length field convention (standard payShield 10K framing): counts every byte after the length field
/// itself — header (2) + command code (2) + payload. An older variant counts only the payload.
/// If traffic from your payShield parses incorrectly, compare the frame_len calculation here
/// against the length field definition in your Host Programmer's Guide.
///
/// Response wire format:
///   [2B big-endian length][2B header][2B response code][2B error code][variable payload]
///
/// The response code is the command code with the second byte incremented by 1 in ASCII,
/// e.g. CA→CB, CC→CD, M6→M7. Error code "00" = success.
pub struct ThalesPayShield;

impl ThalesPayShield {
    /// Frame an outbound host command: [2B BE length][2B header][2B command
    /// code][payload]. The wire layout is the same as `frame_response` with no
    /// error-code field — kept next to it so the framing convention (including
    /// the length-field variant documented above) lives in exactly one module.
    /// Used by the outbound probe (`hsm_probe`); responses come back through
    /// `parse`, which is direction-agnostic.
    pub fn frame_request(&self, header: [u8; 2], command_code: &[u8], payload: &[u8]) -> Vec<u8> {
        self.frame_response(header, command_code, &[], payload)
    }
}

impl Protocol for ThalesPayShield {
    fn parse(&self, buf: &[u8]) -> Option<ParsedCommand> {
        if buf.len() < 6 {
            return None;
        }
        let body_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        // A well-formed body is at least header(2) + command code(2). A shorter
        // declared length is a malformed frame; refuse it rather than slicing
        // past `msg` below (which would panic on msg[0..4] / &msg[4..]). The
        // connection then makes no progress and is closed by the caller's
        // buffer cap. Returning None (not a valid ParsedCommand) is safe because
        // no valid frame ever has body_len < 4.
        if body_len < 4 {
            return None;
        }
        let frame_len = 2 + body_len;
        if buf.len() < frame_len {
            return None;
        }
        let msg = &buf[2..frame_len];
        Some(ParsedCommand {
            header: [msg[0], msg[1]],
            command_code: vec![msg[2], msg[3]],
            payload: Bytes::copy_from_slice(&msg[4..]),
            frame_len,
        })
    }

    fn response_code(&self, cmd: &[u8]) -> Vec<u8> {
        vec![
            *cmd.first().unwrap_or(&0),
            cmd.get(1).copied().unwrap_or(0).wrapping_add(1),
        ]
    }

    fn frame_response(
        &self,
        header: [u8; 2],
        response_code: &[u8],
        error_code: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        // body = header(2) + response_code(2) + error_code(2) + payload
        let body_len = 2 + response_code.len() + error_code.len() + payload.len();
        let mut out = Vec::with_capacity(2 + body_len);
        out.extend_from_slice(&(body_len as u16).to_be_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(response_code);
        out.extend_from_slice(error_code);
        out.extend_from_slice(payload);
        out
    }

    fn frame_error(&self, header: [u8; 2], command_code: &[u8], error_code: &[u8]) -> Vec<u8> {
        let rc = self.response_code(command_code);
        self.frame_response(header, &rc, error_code, &[])
    }

    fn is_response_complete(&self, data: &[u8]) -> bool {
        if data.len() < 2 {
            return false;
        }
        let expected = u16::from_be_bytes([data[0], data[1]]) as usize;
        data.len() >= expected + 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Protocol;

    fn make_frame(header: [u8; 2], cmd: &[u8], payload: &[u8]) -> Vec<u8> {
        let body_len = 2 + cmd.len() + payload.len();
        let mut out = Vec::new();
        out.extend_from_slice(&(body_len as u16).to_be_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(cmd);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parse_valid_frame() {
        let frame = make_frame([0x00, 0x00], b"CA", b"somedata");
        let cmd = ThalesPayShield.parse(&frame).expect("should parse");
        assert_eq!(&cmd.command_code, b"CA");
        assert_eq!(cmd.header, [0x00, 0x00]);
        assert_eq!(&*cmd.payload, b"somedata");
        assert_eq!(cmd.frame_len, frame.len());
    }

    #[test]
    fn parse_returns_none_for_short_input() {
        assert!(ThalesPayShield.parse(b"\x00\x04\x00\x00").is_none()); // claims 4 bytes body but only 2 follow
    }

    #[test]
    fn parse_returns_none_for_empty() {
        assert!(ThalesPayShield.parse(b"").is_none());
    }

    #[test]
    fn parse_does_not_panic_on_short_body_len() {
        // A complete buffer (>= 6 bytes) whose declared body_len is 0..4 is
        // malformed: the body can't hold header(2)+command(2). Before the guard
        // this sliced past `msg` and panicked. Must return None, never panic.
        for body_len in 0u16..4 {
            let mut frame = body_len.to_be_bytes().to_vec();
            frame.extend_from_slice(&[0xAA; 8]); // plenty of trailing bytes
            assert!(
                ThalesPayShield.parse(&frame).is_none(),
                "body_len={body_len} must be rejected, not parsed/panicked"
            );
        }
    }

    #[test]
    fn parse_accepts_minimal_valid_frame() {
        // body_len == 4 is the smallest valid frame: header + command, empty payload.
        let frame = make_frame([0x00, 0x00], b"CA", b"");
        let cmd = ThalesPayShield.parse(&frame).expect("minimal frame parses");
        assert_eq!(&cmd.command_code, b"CA");
        assert!(cmd.payload.is_empty());
    }

    #[test]
    fn response_code_increments_second_byte() {
        assert_eq!(ThalesPayShield.response_code(b"CA"), b"CB");
        assert_eq!(ThalesPayShield.response_code(b"M6"), b"M7");
        assert_eq!(ThalesPayShield.response_code(b"G0"), b"G1");
    }

    #[test]
    fn frame_response_length_prefix_matches_body() {
        let out = ThalesPayShield.frame_response([0x00, 0x00], b"CB", b"00", b"payload");
        let body_len = u16::from_be_bytes([out[0], out[1]]) as usize;
        assert_eq!(body_len, out.len() - 2);
    }

    #[test]
    fn frame_response_round_trip() {
        let header = [0x61, 0x62];
        let response_code = b"CB";
        let error_code = b"00";
        let payload = b"someresponsedata";
        let out = ThalesPayShield.frame_response(header, response_code, error_code, payload);
        // Parse it back
        let parsed = ThalesPayShield
            .parse(&out)
            .expect("framed output should be parseable");
        assert_eq!(parsed.header, header);
        // response code + error code + payload is the parsed payload
        assert!(out.len() > 2);
    }

    #[test]
    fn frame_error_produces_no_payload() {
        let out = ThalesPayShield.frame_error([0x00, 0x00], b"CA", b"68");
        let parsed = ThalesPayShield
            .parse(&out)
            .expect("error frame should parse");
        // payload should be just error code (2 bytes) since frame_error passes empty payload
        // header(2) + response_code(2) + error_code(2) = 6 bytes body
        assert_eq!(&*parsed.payload, b"68");
    }

    // ── property-based tests ──────────────────────────────────────────────────

    proptest::proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(data: Vec<u8>) {
            let _ = ThalesPayShield.parse(&data);
        }

        #[test]
        fn partial_frame_returns_none(body_len in 1u16..1024, actual_len in 0usize..4usize) {
            // Claim a body longer than what we actually provide — must return None
            let mut data = Vec::new();
            data.extend_from_slice(&body_len.to_be_bytes());
            for i in 0..actual_len {
                data.push(i as u8);
            }
            // Only assert None when the provided bytes are shorter than the claimed frame
            let frame_len = 2 + body_len as usize;
            if data.len() < frame_len {
                proptest::prop_assert!(ThalesPayShield.parse(&data).is_none());
            }
        }

        #[test]
        fn valid_frame_parse_frame_len_matches_consumed(payload in proptest::collection::vec(0u8..128, 0..32)) {
            let frame = make_frame([0x00, 0x01], b"CA", &payload);
            let cmd = ThalesPayShield.parse(&frame).expect("valid frame should parse");
            proptest::prop_assert_eq!(cmd.frame_len, frame.len());
        }

        #[test]
        fn is_response_complete_consistent_with_length_prefix(payload in proptest::collection::vec(0u8..128, 0..64)) {
            let frame = make_frame([0x00, 0x00], b"CB", &payload);
            // A complete frame always reports true; truncations must report false
            proptest::prop_assert!(ThalesPayShield.is_response_complete(&frame));
            if frame.len() > 2 {
                proptest::prop_assert!(!ThalesPayShield.is_response_complete(&frame[..frame.len()-1]));
            }
        }
    }
}
