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
