use async_trait::async_trait;
use std::sync::Arc;
use tracing::warn;

use crate::error::ProxyError;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield HMAC commands.
///
/// LQ (→ LR) — Generate an HMAC on a Block of Data.
/// LS (→ LT) — Verify an HMAC on a Block of Data.
///
/// NOT YET VALIDATED AGAINST APC — returns payShield 68.
///
/// AWS Payment Cryptography does support HMAC via generate_mac / verify_mac, so
/// LQ/LS are a realistic future mapping. They are gated here because the previous
/// implementation parsed a fabricated layout that does not match the authoritative
/// wire format (PUGD0537-004 Rev A, p.405 / p.407):
///
///   Hash Identifier   2N   '01' SHA-1, '05' SHA-224, '06' SHA-256, '07' SHA-384,
///                          '08' SHA-512 (Key Block LMK: 2H, ignored, 'FF')
///   HMAC Length       4N   output length t in BYTES — the HMAC may be truncated
///   HMAC Key Format   2N   '00' Thales HMAC, '04' key block
///   HMAC Key Length   4N   length in bytes of the next field ('FFFF' for key block)
///   HMAC Key          nB   the LMK-encrypted key, with NO key-scheme prefix
///   Delimiter         1A   ';' (Variant LMK only)
///   Data Length       5N   length of the message
///   Message Data      nB   raw bytes to authenticate (NOT hex on the wire)
///   (LS additionally carries the HMAC to verify.)
///
/// The previous handler instead used a 1N hash selector ('1'-'4', with no
/// SHA-224), a scheme-prefixed key via parse_legacy_key, a 4-hex-char message
/// length, and treated the message as hex. A faithful mapping must also resolve
/// the binary HMAC Length truncation and the raw-byte representation of the key
/// and message fields against APC's generate_mac/verify_mac (which take a key
/// ARN and hex message data), and confirm SHA-224 support. Until that is
/// validated end-to-end, returning "command disabled" is correct.
pub struct HmacHandler;

#[async_trait]
impl Handler for HmacHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["LQ", "LS"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision: "LQ (generate HMAC) and LS (verify HMAC) return Unsupported (68) — gated \
                       pending wire-format validation, NOT because APC lacks the capability.",
            because: "APC supports HMAC via generate_mac/verify_mac, so LQ/LS are a realistic \
                      future mapping. They are gated because the previous handler parsed a \
                      fabricated layout that does not match the authoritative wire format \
                      (PUGD0537-004 Rev A p.405/407): a 2N hash id, a byte-length HMAC-truncation \
                      field, a length-prefixed inline key, and a raw-byte (not hex) message. A \
                      faithful mapping must resolve the HMAC-length truncation and the raw-byte \
                      key/message representation against APC's hex-message generate_mac/verify_mac \
                      and confirm SHA-224 support — validated end-to-end before enabling. Until \
                      then, returning 68 is correct rather than proxying a guessed layout.",
            wire: WireGrounding::None,
            crypto: CryptoGrounding::None,
            proof: Proof::Gated(
                "wire format not yet validated against APC (deferred implementation)",
            ),
        }]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        _payload: &[u8],
        _state: &Arc<AppState>,
    ) -> HandlerResult {
        let code = String::from_utf8_lossy(command_code);
        warn!(command = %code, "HMAC command gated: wire format not yet validated against APC");
        HandlerResult::from_proxy_error(&ProxyError::Unsupported(format!(
            "{code}: HMAC generate/verify is supported by APC (generate_mac/verify_mac) but the LQ/LS \
             wire format (2N hash id, byte-length HMAC truncation, length-prefixed inline key, raw-byte \
             message) must be validated against APC before it can be proxied"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_codes_registered() {
        let h = HmacHandler;
        assert!(h.command_codes().contains(&"LQ"));
        assert!(h.command_codes().contains(&"LS"));
    }

    #[test]
    fn unsupported_maps_to_68() {
        assert_eq!(
            ProxyError::Unsupported("LQ".into()).payshield_code(),
            *b"68"
        );
    }
}
