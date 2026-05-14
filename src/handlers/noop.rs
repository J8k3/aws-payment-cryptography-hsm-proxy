use async_trait::async_trait;
use std::sync::Arc;

use super::{AppState, Handler, HandlerResult};

/// Commands that APC explicitly does not support.
/// Returns payShield error code 68 (command not available).
///
/// Includes: LMK management (B0/BG/BW/BS), MFK-protected PIN (JC/JE/JG),
/// zone↔main key PIN translate (LE/LG/LO), key block format ops (EM/EU),
/// and administrative/diagnostic commands the service manages internally.
pub struct NotAvailableHandler;

#[async_trait]
impl Handler for NotAvailableHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &[
            "B0", "BG", "BW", "BS",
            "JC", "JE", "JG",
            "LE", "LG", "LO",
            "EM", "EU",
            "AE", "AG", "AK", "AM",
            "J6", "J8", "JK",
            "NC", "NI", "NO",
            "Q0", "Q6", "Q8",
            "RA",
            "SE", "TG", "TY",
            "UI", "VW", "VY",
            "WC", "WQ", "WW", "WY",
        ]
    }

    async fn handle(&self, _command_code: &[u8], _payload: &[u8], _state: &Arc<AppState>) -> HandlerResult {
        HandlerResult::err(b"68")
    }
}
