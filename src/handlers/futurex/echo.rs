use async_trait::async_trait;
use std::sync::Arc;
use tracing::debug;

use crate::handlers::{AppState, Handler, HandlerResult};

/// Futurex Excrypt ECHO — connectivity heartbeat. No APC call.
///
/// Futurex HSM Reference Manual: ECHO returns an empty success response.
/// Used by applications at startup and during health checks to confirm
/// the HSM connection is alive.
pub struct EchoHandler;

#[async_trait]
impl Handler for EchoHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["ECHO"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision: "Futurex Excrypt ECHO is a connectivity heartbeat: returns an empty success \
                       response, makes no APC call.",
            because:
                "Futurex HSM Reference Manual — ECHO confirms the HSM connection is alive. No \
                      cryptography or key material is involved, so the proxy answers locally. \
                      Nothing to differentially verify against APC.",
            wire: WireGrounding::Cited,
            crypto: CryptoGrounding::None,
            proof: Proof::ManualCite("Futurex HSM Reference Manual — ECHO returns empty success"),
        }]
    }

    async fn handle(
        &self,
        _command_code: &[u8],
        _payload: &[u8],
        _state: &Arc<AppState>,
    ) -> HandlerResult {
        debug!("ECHO heartbeat");
        HandlerResult::success(vec![])
    }
}
