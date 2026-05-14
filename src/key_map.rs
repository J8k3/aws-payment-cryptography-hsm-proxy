use std::collections::HashMap;
use crate::error::ProxyError;

/// Resolves legacy HSM key identifiers to APC key ARNs.
///
/// The proxy.yaml key_mappings section maps whatever string the legacy application
/// sends as a key field (typically the key's LMK-encrypted hex representation, or a
/// human-readable label if the application has been lightly configured to use one)
/// to an APC key ARN or alias.
///
/// Values that already look like APC identifiers pass through unchanged.
pub struct KeyMap(HashMap<String, String>);

impl KeyMap {
    pub fn new(mappings: HashMap<String, String>) -> Self {
        Self(mappings)
    }

    /// Resolve a key identifier to an APC key ARN or alias.
    pub fn resolve<'a>(&'a self, key_id: &'a str) -> Result<&'a str, ProxyError> {
        // Already an APC ARN or alias — pass through.
        if key_id.starts_with("arn:aws:payment-cryptography") || key_id.starts_with("alias/") {
            return Ok(key_id);
        }
        self.0
            .get(key_id)
            .map(|s| s.as_str())
            .ok_or_else(|| ProxyError::KeyNotFound(key_id.to_string()))
    }
}
