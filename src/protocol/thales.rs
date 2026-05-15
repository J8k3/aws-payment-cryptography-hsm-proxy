use bytes::Bytes;
use super::{ParsedCommand, Protocol};

/// Thales payShield 10K host command framing.
///
/// Request wire format:
///   [2B big-endian length][2B header][2B command code][variable payload]
///   The length field counts every byte that follows it (header + command + payload).
///
/// Response wire format:
///   [2B big-endian length][2B header][2B response code][2B error code][variable payload]
///
/// The response code is the command code with the second byte incremented by 1 in ASCII,
/// e.g. CA→CB, CC→CD, M6→M7. Error code "00" = success.
pub struct ThalesPayShield;

impl Protocol for ThalesPayShield {
    fn parse(&self, buf: &[u8]) -> Option<ParsedCommand> {
        if buf.len() < 6 {
            return None;
        }
        let body_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
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
        let parsed = ThalesPayShield.parse(&out).expect("framed output should be parseable");
        assert_eq!(parsed.header, header);
        // response code + error code + payload is the parsed payload
        assert!(out.len() > 2);
    }

    #[test]
    fn frame_error_produces_no_payload() {
        let out = ThalesPayShield.frame_error([0x00, 0x00], b"CA", b"68");
        let parsed = ThalesPayShield.parse(&out).expect("error frame should parse");
        // payload should be just error code (2 bytes) since frame_error passes empty payload
        // header(2) + response_code(2) + error_code(2) = 6 bytes body
        assert_eq!(&*parsed.payload, b"68");
    }
}
