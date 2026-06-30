use async_trait::async_trait;
use std::sync::Arc;
use tracing::warn;

use crate::error::ProxyError;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield dynamic card-verification commands.
///
/// QY (→ QZ) — Generate a Dynamic CVV.
/// PM (→ PN) — Verify a Dynamic CVV/CVC.
///
/// NOT SUPPORTED ON APC (see reasoning below).
///
/// These are EMV, multi-scheme dynamic-CVV operations, not the static-CVK
/// CW/CY algorithm. The real wire format (PUGD0537-004 Rev A, p.306 / p.308)
/// begins with a Scheme ID and derives a *card-unique* key from an issuer
/// master key:
///
/// QY (generate):
///   Scheme ID (1N)            '0' Visa dCVV, '1' Visa AV, '5' Visa dCVV2 time-based
///   Master Key (MK-AC, E0)    32H | 'U'+32H | 'T'+48H | 'S'+keyblock
///   Key Derivation Method (1A) 'A'/'B' (EMV 4.1 Book 2 Option A/B)
///   PAN (nN, max 19) ';'      variable, delimiter-terminated
///   then scheme-specific fields — for Visa dCVV: expiry (4N),
///   service code (3N, must be '998'), ATC (6N).
///
/// PM (verify):
///   Scheme ID (1N)            '0' Visa, '1' Mastercard, '2' Amex, '3' Discover,
///                             '4' Oberthur, '5' Visa dCVV2, '6' JCB, '7' Gemalto
///   Version (1N)              scheme-specific (Visa DCVV/LUC, MC CVC3, …)
///   MK-DCVV master key        MK-AC or MK-CVC3, derivation-method dependent
///   then scheme/version-specific fields.
///
/// Why this cannot be faithfully proxied to APC today:
///   - The card key is derived from an EMV master key (E-type) via an explicit
///     Option A/B method; the previous handler instead resolved a static C0 CVK
///     and emitted a CardVerificationValue/DynamicCardVerificationValue call from
///     a fabricated fixed-width layout (32H CVK, fixed 16N PAN, 4H ATC, a
///     spurious PAN-sequence field) that matches no real QY/PM message.
///   - Visa dCVV (Scheme '0') is the one scheme that plausibly maps to APC's
///     generate/verify_card_validation_data with DynamicCardVerificationValue,
///     but APC requires a PAN sequence number that the Visa-dCVV wire format does
///     not carry, and the ATC width/encoding and card-key derivation must be
///     validated against live APC before a mapping can be trusted.
///   - The remaining schemes (Visa AV, Visa dCVV2 time-based, Mastercard CVC3,
///     Amex ExpressPay, Discover, Oberthur, JCB, Gemalto) have no APC equivalent.
///
/// Returning "command disabled" (payShield 68) is correct until a Scheme-'0'
/// mapping is implemented and validated end-to-end against AWS Payment
/// Cryptography. This avoids emitting a cryptographically wrong dCVV.
pub struct DynamicCvvHandler;

#[async_trait]
impl Handler for DynamicCvvHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["QY", "PM"]
    }

    async fn handle(
        &self,
        command_code: &[u8],
        _payload: &[u8],
        _state: &Arc<AppState>,
    ) -> HandlerResult {
        let code = String::from_utf8_lossy(command_code);
        warn!(command = %code, "dynamic CVV command rejected: EMV-derived multi-scheme dCVV not modelable on APC");
        HandlerResult::from_proxy_error(&ProxyError::Unsupported(format!(
            "{code}: dynamic CVV (dCVV/dCVV2) derives a card-unique key from an EMV master key across \
             multiple card schemes; AWS Payment Cryptography cannot reproduce the QY/PM operation as \
             specified"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_codes_registered() {
        let h = DynamicCvvHandler;
        assert!(h.command_codes().contains(&"QY"));
        assert!(h.command_codes().contains(&"PM"));
    }

    #[test]
    fn unsupported_maps_to_68() {
        assert_eq!(
            ProxyError::Unsupported("QY".into()).payshield_code(),
            *b"68"
        );
    }
}
