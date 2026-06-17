use async_trait::async_trait;
use std::sync::Arc;
use tracing::warn;

use crate::error::ProxyError;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield Diebold PIN commands.
///
/// GA (→ GB) — Derive a PIN Using the Diebold Method.
/// CE (→ CF) — Generate a Diebold PIN Offset.
///
/// NOT SUPPORTED ON APC.
///
/// The Diebold method is frequently mistaken for an IBM 3624 variant, but it is
/// not. Instead of deriving the PIN by a DES encrypt-and-decimalize of the
/// transformed account number, the HSM indexes a Diebold conversion
/// (randomizing) table that the operator has loaded into the device's *user
/// storage*. The wire request carries an index flag plus a table pointer into
/// that user-storage table, and the resulting PIN/offset depends entirely on the
/// table's contents.
///
/// AWS Payment Cryptography exposes no user-storage table facility and no
/// generation attribute that reproduces a Diebold lookup, so neither GA nor CE
/// can be modeled against APC. Mapping them onto Ibm3624NaturalPin /
/// Ibm3624PinOffset would silently produce a *different* PIN — a correctness
/// failure, not merely a missing feature. We therefore return "command disabled"
/// (payShield 68) rather than emit an incorrect APC call.
///
/// Migration path: re-issue affected PINs under a scheme APC supports
/// (IBM 3624 natural PIN/offset via EE/DE, or Visa PVV via DG/FW).
pub struct DieboldPinHandler;

#[async_trait]
impl Handler for DieboldPinHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["CE", "GA"]
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
