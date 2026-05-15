pub mod futurex;
pub mod thales;

use bytes::Bytes;

/// A parsed inbound command from any vendor protocol.
#[derive(Debug)]
pub struct ParsedCommand {
    /// Vendor-specific header bytes echoed in the response (Thales: 2 bytes; Futurex: unused).
    pub header: [u8; 2],
    /// Command code as raw bytes. Thales: 2 bytes (e.g. b"CA"). Futurex: 4 bytes (e.g. b"TPIN").
    pub command_code: Vec<u8>,
    /// Raw payload bytes following the command code.
    pub payload: Bytes,
    /// Total bytes consumed from the input buffer for this message.
    pub frame_len: usize,
}

/// Framing contract implemented by each vendor protocol.
pub trait Protocol: Send + Sync {
    /// Try to parse one complete command from the buffer.
    /// Returns None if there is not yet enough data.
    fn parse(&self, buf: &[u8]) -> Option<ParsedCommand>;

    /// Derive the wire response code from the inbound command code.
    /// Thales: increment second byte (CA→CB). Futurex: echo the command.
    fn response_code(&self, command_code: &[u8]) -> Vec<u8>;

    /// Frame a complete response for the wire.
    fn frame_response(
        &self,
        header: [u8; 2],
        response_code: &[u8],
        error_code: &[u8],
        payload: &[u8],
    ) -> Vec<u8>;

    /// Frame an error response (empty payload).
    fn frame_error(&self, header: [u8; 2], command_code: &[u8], error_code: &[u8]) -> Vec<u8>;

    /// Returns true when `data` contains a complete framed response from the real HSM.
    /// Used by the discovery passthrough to know when to stop reading.
    fn is_response_complete(&self, data: &[u8]) -> bool;
}
