use async_trait::async_trait;
use std::sync::Arc;
use tracing::warn;

use crate::error::ProxyError;
use crate::handlers::{AppState, Handler, HandlerResult};

/// payShield EMV "Generate a Secure Message with Integrity" commands.
///
/// JU (→ JV) — UnionPay/CUP variant.
/// KU (→ KV) — Generate a Secure Message with Integrity.
/// KY (→ KZ) — Generate a Secure Message with Integrity (additional profiles).
///
/// NOT YET VALIDATED AGAINST APC — returns payShield 68.
///
/// These commands derive an integrity session key from an issuer master key
/// (MK-SMI) and MAC an issuer-script message. The previous implementation parsed
/// a fabricated layout that does not match the authoritative KU wire format
/// (PUGD0537-004 Rev A, p.475):
///
///   Mode Flag        1N   '0' integrity only; '1'-'4' add confidentiality / PIN change
///   Scheme ID        1N   '0' Visa, '1' Mastercard, '2' Amex, '3'-'5' JCB, '6' UnionPay
///   MK-SMI           32H | 'U'+32H | 'S'+keyblock   (E2 key) — NO 3H key-type prefix
///   PAN/PAN Seq      8B   pre-formatted PAN + sequence number
///   Integrity Session Key Data  8B  (the 2-byte ATC right-justified, zero-padded to
///                         8 bytes, for schemes 0/1/2/5; 2B for schemes 3/4)
///   [Padding Flag, Plaintext Message Data Length, Plaintext Message Data, ';' ...]
///
/// The previous handler inserted a non-existent '[3H] Key Type' field before the
/// MK-SMI (a 3-byte misalignment) and read the session-key data as a bare 2-byte
/// ATC instead of the 8-byte field (a further 6-byte misalignment). It also
/// assumed the APC key was a pre-derived session key, whereas KU supplies the
/// *master* key plus the derivation data and performs EMV session-key derivation
/// internally — something APC's generate_mac does not do. A faithful mapping must
/// resolve the session-key derivation (per scheme) and the binary field
/// representation against APC before it can be proxied.
pub struct IssuerScriptMacHandler;

#[async_trait]
impl Handler for IssuerScriptMacHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &["JU", "KU", "KY"]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        &[Evidence {
            decision:
                "JU/KU/KY (Generate a Secure Message with Integrity) return Unsupported (68). \
                       JU is the UnionPay/CUP variant; KY adds further profiles.",
            because: "PUGD0537-004 Rev A p.475 (KU) / p.480 (KY); PUGD0538-003 §7 p.124 (JU, \
                      UnionPay). These derive an integrity session \
                      key from an issuer master key (MK-SMI, E2) per scheme and MAC an \
                      issuer-script message. APC's generate_mac takes a pre-derived key and does \
                      not perform EMV session-key derivation, and the KU wire supplies the MASTER \
                      key plus derivation data (no 3H key-type prefix), so a faithful mapping must \
                      resolve the per-scheme session-key derivation and the binary field layout \
                      against APC before it can be proxied. Gated rather than emit a MAC under the \
                      wrong key. (The previous handler mis-parsed the layout — a 3-byte + 6-byte \
                      misalignment.)",
            wire: WireGrounding::None,
            crypto: CryptoGrounding::None,
            proof: Proof::Gated(
                "EMV MK-SMI session-key derivation not in APC generate_mac; wire not yet validated",
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
        warn!(command = %code, "issuer-script MAC command gated: wire format/derivation not validated against APC");
        HandlerResult::from_proxy_error(&ProxyError::Unsupported(format!(
            "{code}: Generate Secure Message with Integrity derives an EMV integrity session key from a \
             master key (MK-SMI) per card scheme; this derivation and the binary wire layout must be \
             validated against APC before it can be proxied"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_codes_registered() {
        let h = IssuerScriptMacHandler;
        assert!(h.command_codes().contains(&"KU"));
        assert!(h.command_codes().contains(&"KY"));
        assert!(h.command_codes().contains(&"JU"));
    }

    #[test]
    fn unsupported_maps_to_68() {
        assert_eq!(
            ProxyError::Unsupported("KU".into()).payshield_code(),
            *b"68"
        );
    }
}
