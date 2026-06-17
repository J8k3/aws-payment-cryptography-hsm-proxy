use async_trait::async_trait;
use std::sync::Arc;
use tracing::warn;

use crate::error::ProxyError;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield JA (→ JB) — Generate a Random PIN.
///
/// NOT SUPPORTED ON APC.
///
/// The real JA command takes only an account number (12N), an optional PIN
/// length (2N), and an optional excluded-PIN table; it carries no keys at all.
/// JB returns the generated PIN *encrypted under the LMK* — specifically a
/// proprietary, LMK-encrypted PIN block in which the PIN is cryptographically
/// bound to the account number. There is no decimalization table, validation
/// data, offset, or ZPK-encrypted output anywhere in the JA/JB exchange; those
/// belong to the separate offset-generation and translation commands that an
/// issuer would invoke afterwards.
///
/// AWS Payment Cryptography has no Local Master Key and cannot emit an
/// LMK-encrypted PIN block, so the defining output of JA has no APC equivalent.
/// (The superficially similar generate_pin_data + Ibm3624RandomPin operation is
/// a *fused* random-PIN/offset/ZPK-encrypt flow that requires a generation key
/// and an encryption key and returns a ZPK-encrypted block — it does not
/// reproduce JA's LMK-bound output and does not match JA's wire format.)
///
/// We therefore return "command disabled" (payShield 68) rather than parse a
/// fabricated field layout and emit a mismatched APC call. Issuers migrating to
/// APC should generate PINs with generate_pin_data, taking the ZPK-encrypted
/// block and verification value directly instead of an LMK-encrypted PIN.
pub struct RandomPinHandler;

#[async_trait]
impl Handler for RandomPinHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["JA"]
    }

    async fn handle(
        &self,
        _command_code: &[u8],
        _payload: &[u8],
        _state: &Arc<AppState>,
    ) -> HandlerResult {
        warn!("JA rejected: random-PIN output is LMK-encrypted, which APC cannot model");
        HandlerResult::from_proxy_error(&ProxyError::Unsupported(
            "JA: Generate a Random PIN returns a PIN encrypted under the LMK; AWS Payment \
             Cryptography has no LMK and cannot produce this output. Use generate_pin_data to \
             issue PINs as ZPK-encrypted blocks with a verification value instead"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_code_registered() {
        assert!(RandomPinHandler.command_codes().contains(&"JA"));
    }

    #[test]
    fn unsupported_maps_to_68() {
        assert_eq!(
            ProxyError::Unsupported("JA".into()).payshield_code(),
            *b"68"
        );
    }
}
