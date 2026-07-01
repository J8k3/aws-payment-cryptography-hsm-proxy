use async_trait::async_trait;
use std::sync::Arc;
use tracing::debug;

use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield B2: echo/heartbeat. Returns success with no payload.
pub struct HeartbeatHandler;

#[async_trait]
impl Handler for HeartbeatHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["B2"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision: "B2 is a heartbeat/echo: returns success with an empty payload and makes no \
                       APC call.",
            because:
                "PUGD0537-004 B2 (echo). No cryptography and no key material are involved, so \
                      the proxy answers locally — host health checks succeed without a data-plane \
                      round-trip. Nothing to differentially verify against APC.",
            wire: WireGrounding::Cited,
            crypto: CryptoGrounding::None,
            proof: Proof::ManualCite("PUGD0537-004 B2 — echo/heartbeat, empty success response"),
        }]
    }

    async fn handle(
        &self,
        _command_code: &[u8],
        _payload: &[u8],
        _state: &Arc<AppState>,
    ) -> HandlerResult {
        debug!("B2 heartbeat");
        HandlerResult::success(vec![])
    }
}
