use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("key not found in mapping: {0:?}")]
    KeyNotFound(String),

    #[error("malformed command payload: {0}")]
    MalformedPayload(String),

    #[error("APC API error: {0}")]
    ApcError(String),

    #[error("unsupported PIN block format: {0}")]
    UnsupportedPinFormat(String),

    #[error("unsupported MAC algorithm mode: {0}")]
    UnsupportedMacMode(String),

    /// APC returned a verification mismatch (wrong PIN, MAC, or CVV value).
    /// Distinct from ApcError — the call succeeded but the value was incorrect.
    #[error("verification failed")]
    VerificationFailed,
}

impl ProxyError {
    /// Map to a 2-char payShield error code.
    ///
    /// Reference: Thales payShield 10K Legacy Host Commands, Section 13 (Standard Error Codes).
    /// "00" = success; "01" = incorrect PIN/MAC/CVV; "10" = source key error;
    /// "15" = invalid input data; "23" = invalid PIN block format;
    /// "41" = internal hardware/software error; "68" = command disabled.
    pub fn payshield_code(&self) -> &'static [u8; 2] {
        match self {
            ProxyError::KeyNotFound(_) => b"10",
            ProxyError::MalformedPayload(_) => b"15",
            ProxyError::ApcError(_) => b"41",
            ProxyError::UnsupportedPinFormat(_) => b"23",
            ProxyError::UnsupportedMacMode(_) => b"15",
            ProxyError::VerificationFailed => b"01",
        }
    }
}
