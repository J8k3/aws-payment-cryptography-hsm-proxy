use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("key not found in mapping: {0:?}")]
    KeyNotFound(String),

    #[error("malformed command payload: {0}")]
    MalformedPayload(String),

    #[error("command not supported by proxy: {0}")]
    UnsupportedCommand(String),

    #[error("APC API error: {0}")]
    ApcError(String),

    #[error("unsupported PIN block format: {0}")]
    UnsupportedPinFormat(String),

    #[error("unsupported MAC algorithm mode: {0}")]
    UnsupportedMacMode(String),
}

impl ProxyError {
    /// Map to a 2-char payShield error code.
    ///
    /// Reference: Thales payShield 10K Host Command Reference Manual.
    /// "00" = no error; "10" = source key error; "15" = algorithm unavailable;
    /// "40" = internal failure; "68" = command not authorized.
    pub fn payshield_code(&self) -> &'static [u8; 2] {
        match self {
            ProxyError::KeyNotFound(_) => b"10",
            ProxyError::MalformedPayload(_) => b"15",
            ProxyError::UnsupportedCommand(_) => b"68",
            ProxyError::ApcError(_) => b"40",
            ProxyError::UnsupportedPinFormat(_) => b"15",
            ProxyError::UnsupportedMacMode(_) => b"15",
        }
    }
}
