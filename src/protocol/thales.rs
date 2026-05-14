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
}
