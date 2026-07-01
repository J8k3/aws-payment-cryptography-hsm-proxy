use async_trait::async_trait;
use std::sync::Arc;
use tracing::warn;

use crate::error::ProxyError;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield Diebold PIN commands — GA (derive PIN) and CE (generate offset).
///
/// Both return payShield 68 (not supported on APC). Rationale and migration
/// path: see `Handler::grounding()`.
pub struct DieboldPinHandler;

#[async_trait]
impl Handler for DieboldPinHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["CE", "GA"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision:
                "GA (derive PIN, Diebold method) and CE (generate Diebold PIN offset) return \
                       Unsupported (68).",
            because: "The Diebold method is not an IBM 3624 variant: instead of a DES \
                      encrypt-and-decimalize of the transformed account number, the HSM indexes a \
                      randomizing conversion table loaded into its user storage, and the derived \
                      PIN depends entirely on that table's contents. APC exposes no user-storage \
                      table and no generation attribute that reproduces a Diebold lookup, so it \
                      cannot be modeled. Mapping onto Ibm3624NaturalPin/Ibm3624PinOffset would \
                      silently produce a DIFFERENT PIN — a correctness failure, not a missing \
                      feature — so we reject rather than emit an incorrect APC call. Migration: \
                      re-issue affected PINs under IBM 3624 (EE/DE) or Visa PVV (DG/FW).",
            wire: WireGrounding::None,
            crypto: CryptoGrounding::None,
            proof: Proof::Gated("no APC equivalent — Diebold user-storage conversion table"),
        }]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        _payload: &[u8],
        _state: &Arc<AppState>,
    ) -> HandlerResult {
        let code = String::from_utf8_lossy(command_code);
        warn!(command = %code, "Diebold PIN command rejected: not modelable on APC");
        HandlerResult::from_proxy_error(&ProxyError::Unsupported(format!(
            "{code}: the Diebold PIN method relies on an HSM user-storage conversion table that AWS \
             Payment Cryptography cannot replicate; re-issue affected PINs under IBM 3624 or Visa PVV"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_codes_registered() {
        let h = DieboldPinHandler;
        assert!(h.command_codes().contains(&"GA"));
        assert!(h.command_codes().contains(&"CE"));
    }

    #[test]
    fn unsupported_maps_to_68() {
        let e = ProxyError::Unsupported("GA".into());
        assert_eq!(e.payshield_code(), *b"68");
    }
}
