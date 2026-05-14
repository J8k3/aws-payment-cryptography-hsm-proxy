use bytes::Bytes;
use super::{ParsedCommand, Protocol};

/// Futurex Excrypt protocol framing.
///
/// Wire format:
///   Request:  [AOCCCC;P1value;P2value;...;]
///   Response: [AOCCCC;P1value;...;BBstatus;]
///
///   - Messages are bracket-delimited: starts with '[', ends with ']'
///   - 'AO' is a fixed prefix present on all messages
///   - CCCC is the 4-character command code (e.g., TPIN, GKEY)
///   - Parameters are 2-char code + value, semicolon-delimited, non-positional
///   - BB is the response status field: 'Y' = success
///
/// Key hierarchies: MFK (3DES, primary live path) and PMK (AES, migration target).
/// Not all commands support PMK. Parameter semantics are command-scoped — the same
/// 2-char code can mean different things in different commands.
pub struct FuturexExcrypt;

impl Protocol for FuturexExcrypt {
    fn parse(&self, buf: &[u8]) -> Option<ParsedCommand> {
        // Find the bracket-delimited frame
        let start = buf.iter().position(|&b| b == b'[')?;
        let end_rel = buf[start..].iter().position(|&b| b == b']')?;
        let frame_len = start + end_rel + 1;
        let inner = &buf[start + 1..start + end_rel]; // strip [ and ]

        // Split on first semicolon to isolate the command field ("AOTPIN")
        let first_semi = inner.iter().position(|&b| b == b';').unwrap_or(inner.len());
        let cmd_field = &inner[..first_semi];

        // All Futurex messages start with the two-byte "AO" prefix
        if cmd_field.len() < 6 || !cmd_field.starts_with(b"AO") {
            return None;
        }
        let command_code = cmd_field[2..6].to_vec(); // 4-char code, e.g. b"TPIN"

        // Payload: everything after "AOCCCC;" up to the closing bracket
        let params_start = if first_semi < inner.len() { first_semi + 1 } else { inner.len() };
        let payload = Bytes::copy_from_slice(&inner[params_start..]);

        Some(ParsedCommand {
            header: [0, 0],
            command_code,
            payload,
            frame_len,
        })
    }

    fn response_code(&self, command_code: &[u8]) -> Vec<u8> {
        // Futurex responses echo the command code unchanged
        command_code.to_vec()
    }

    fn frame_response(
        &self,
        _header: [u8; 2],
        response_code: &[u8],
        error_code: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        // [AOCCCC;...payload params...;BBstatus;]
        let mut out = Vec::new();
        out.extend_from_slice(b"[AO");
        out.extend_from_slice(response_code);
        out.push(b';');
        if !payload.is_empty() {
            out.extend_from_slice(payload); // handlers produce "PARAM<value>;" already
        }
        // BB status parameter: map internal "00" (success) to Futurex "Y"
        let status: &[u8] = if error_code == b"00" { b"Y" } else { error_code };
        out.extend_from_slice(b"BB");
        out.extend_from_slice(status);
        out.push(b';');
        out.push(b']');
        out
    }

    fn frame_error(&self, header: [u8; 2], command_code: &[u8], error_code: &[u8]) -> Vec<u8> {
        let rc = self.response_code(command_code);
        self.frame_response(header, &rc, error_code, &[])
    }
}

/// Parse a Futurex parameter string into a map of 2-char code → value.
///
/// Input: the payload bytes from ParsedCommand, e.g. "AW1;AX<key>;AL<pin>;AK<pan>;"
/// Each token before a semicolon has a 2-char code followed by its value.
pub fn parse_params(payload: &[u8]) -> std::collections::HashMap<[u8; 2], Vec<u8>> {
    let mut map = std::collections::HashMap::new();
    for token in payload.split(|&b| b == b';') {
        if token.len() < 3 {
            continue;
        }
        let code: [u8; 2] = [token[0], token[1]];
        map.insert(code, token[2..].to_vec());
    }
    map
}

/// Redact known-sensitive Futurex parameter codes from a param map for safe logging.
///
/// AX/BT = key blocks, AL = PIN block — never logged in plaintext.
pub fn redact_for_log(params: &std::collections::HashMap<[u8; 2], Vec<u8>>) -> String {
    const SENSITIVE: &[[u8; 2]] = &[*b"AX", *b"BT", *b"AL"];
    let mut parts: Vec<String> = params
        .iter()
        .map(|(code, val)| {
            let code_str = String::from_utf8_lossy(code);
            if SENSITIVE.contains(code) {
                format!("{}=[REDACTED]", code_str)
            } else {
                format!("{}={}", code_str, String::from_utf8_lossy(val))
            }
        })
        .collect();
    parts.sort();
    parts.join(";")
}
