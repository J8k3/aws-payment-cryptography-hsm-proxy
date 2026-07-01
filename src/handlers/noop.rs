use async_trait::async_trait;
use std::sync::Arc;

use super::{AppState, Handler, HandlerResult};

/// Commands that APC does not support. Returns payShield error code 68.
///
/// PIN — no APC path:
///   AQ  RSA-encrypted PIN translate (no RSA PIN decrypt in APC)
///   BA  Encrypt clear PIN to LMK-encrypted block (LMK output)
///   BC/BE  Terminal/interchange PIN verify via comparison method (no decrypt-and-compare)
///   BK  IBM offset from customer-selected clear PIN (clear PIN rejected by APC per PCI PIN)
///   CG/EG  Diebold PIN verify (APC PinVerificationAttributes is IBM3624/VisaPVV only)
///   DE/DG  IBM offset / ABA PVV from LMK-encrypted PIN (LMK input)
///   EE  Derive PIN via IBM offset method (LMK-encrypted output)
///   FW  ABA PVV from customer-selected clear PIN (clear PIN, PCI violation)
///   JC/JE/JG  PIN translate to/from/via LMK (LMK concept absent in APC)
///   LE/LG/LO  Zone↔main key PIN translate (LMK-based)
///   NG  Decrypt PIN block to clear PIN (no APC op; clear PIN output violates PCI PIN)
///
/// Encrypt — no APC op:
///   EM/EU  Key block format conversion
///   EW/EY  RSA signature generate/verify
///   GM  Hash a block of data
///
/// Key management — LMK-based translate/import/export or out-of-proxy-scope key gen:
///   A0/IA/KG  Generate key (APC keys are provisioned externally, not via proxy)
///   A4/A6/FA/FC/FE/FK/GC/GE/BY/HY/MI  Import/translate under LMK
///   A8/AA/AC/AU/AW/DW/DY/FG/GG/GY/GK/KC/K8/LU/LW/MG  Export/translate from LMK
///   AS/BI/HA/HC  Generate CVK pair / BDK / TAK / TMK-PVK
///   B0/BG/BW/BS  LMK scheme management
///   B8  Export key under TR-34 (key management plane, not transaction proxy scope)
///   BU/KA  Generate key check value (no APC op)
///   CS  Modify key block header
///   KI  Derive card unique DES keys
///   L0  Generate HMAC secret key
///
/// Misc / admin:
///   N0  Generate random value (no APC op)
///   QH  Query host / connectivity test (not applicable to APC)
///   AE/AG/AK/AM/J6/J8/JK/NC/NI/NO/Q0/Q6/Q8/RA/SE/TG/TY/UI/VW/VY/WC/WQ/WW/WY
///       Administrative, diagnostic, and vendor-specific commands
pub struct NotAvailableHandler;

#[async_trait]
impl Handler for NotAvailableHandler {
    fn command_codes(&self) -> &'static [&'static str] {
        &[
            // PIN — no APC path
            "AQ", "BA", "BC", "BE", "BK", "CG", "DE", "DG", "EE", "EG", "FW", "JC", "JE", "JG",
            "LE", "LG", "LO", "NG", // Encrypt — no APC op
            "EM", "EU", "EW", "EY", "GM",
            // Key management — LMK-based or out of proxy scope
            "A0", "A4", "A6", "A8", "AA", "AC", "AE", "AG", "AK", "AM", "AS", "AU", "AW", "BI",
            "B0", "B8", "BG", "BU", "BW", "BS", "BY", "CS", "DW", "DY", "FA", "FC", "FE", "FG",
            "FK", "GC", "GE", "GG", "GK", "GY", "HA", "HC", "HY", "IA", "J6", "J8", "JK", "K8",
            "KA", "KC", "KG", "KI", "L0", "LU", "LW", "MG", "MI", // Misc / admin
            "N0", "NC", "NI", "NO", "Q0", "Q6", "Q8", "QH", "RA", "SE", "TG", "TY", "UI", "VW",
            "VY", "WC", "WQ", "WW", "WY",
        ]
    }

    fn grounding(&self) -> &'static [crate::handlers::grounding::Evidence] {
        use crate::handlers::grounding::{CryptoGrounding, Evidence, Proof, WireGrounding};
        // Category-level evidence; the per-command rationale is the doc-comment on
        // this struct (in-code, authoritative). Each category is a deliberate,
        // reasoned gate — not an untested gap.
        &[
            Evidence {
                decision: "PIN operations return 68 (AQ, BA, BC, BE, BK, CG, DE, DG, EE, EG, FW, \
                           JC, JE, JG, LE, LG, LO, NG).",
                because: "Each needs an APC path that does not exist: RSA-encrypted PIN decrypt, \
                          LMK-encrypted PIN I/O, decrypt-and-compare verification, or clear-PIN \
                          input/output (rejected under PCI PIN). APC PinVerificationAttributes is \
                          IBM3624/VisaPVV only and has no LMK concept.",
                wire: WireGrounding::None,
                crypto: CryptoGrounding::None,
                proof: Proof::Gated("no APC equivalent — RSA/LMK/clear-PIN paths"),
            },
            Evidence {
                decision: "Encrypt/hash operations return 68 (EM, EU, EW, EY, GM).",
                because: "Key-block format conversion, RSA signature generate/verify, and generic \
                          data hashing have no corresponding APC data-plane operation.",
                wire: WireGrounding::None,
                crypto: CryptoGrounding::None,
                proof: Proof::Gated("no APC op — key-block conv / RSA sig / hash"),
            },
            Evidence {
                decision: "Key-management operations return 68 (A0/A4/A6/A8/AA/AC/AE/AG/AK/AM/AS/\
                           AU/AW/BI/B0/B8/BG/BU/BW/BS/BY/CS/DW/DY/FA/FC/FE/FG/FK/GC/GE/GG/GK/GY/\
                           HA/HC/HY/IA/J6/J8/JK/K8/KA/KC/KG/KI/L0/LU/LW/MG/MI).",
                because:
                    "These generate, import, export, translate, or manage keys under an LMK, or \
                          compute key check values / derive card-unique keys. APC keys are \
                          provisioned externally through the control plane, not minted or wrapped \
                          via this transaction proxy, so none map to a data-plane call.",
                wire: WireGrounding::None,
                crypto: CryptoGrounding::None,
                proof: Proof::Gated("key management is control-plane / LMK — out of proxy scope"),
            },
            Evidence {
                decision:
                    "Administrative/diagnostic operations return 68 (N0, NC, NI, NO, Q0, Q6, \
                           Q8, QH, RA, SE, TG, TY, UI, VW, VY, WC, WQ, WW, WY).",
                because: "Random-value generation, host/connectivity queries, and vendor-specific \
                          admin/diagnostic commands have no APC data-plane equivalent.",
                wire: WireGrounding::None,
                crypto: CryptoGrounding::None,
                proof: Proof::Gated("admin/diagnostic — no APC data-plane equivalent"),
            },
        ]
    }

    async fn handle(
        &self,
        _command_code: &[u8],
        _payload: &[u8],
        _state: &Arc<AppState>,
    ) -> HandlerResult {
        HandlerResult::err(*b"68")
    }
}
