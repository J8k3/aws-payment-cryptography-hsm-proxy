//! Outbound KCV probe against the source HSM — the `--verify-only` HSM-side
//! cross-check (#15) and the foundation for slot discovery (#13).
//!
//! # What this does
//!
//! `key_mappings` keys are the LMK-encrypted key forms exactly as they appear on
//! the wire (`16H`, `'U'+32H`, `'T'+48H`, or `'S'+`key block). The payShield can
//! be asked for the KCV of that same material with host command `BU` ("Generate
//! a Key Check Value", response `BV`) — so we can confirm that the key an
//! application presents to the proxy and the APC key the operator mapped it to
//! actually contain the same clear key, before the first live transaction does
//! the confirming for us.
//!
//! # Grounding (verified against manuals; see docs/grounding-report.md conventions)
//!
//! - `BU` (`BV`): PUGD0537-004 Rev A — "Generate a check value for a key
//!   encrypted under an LMK pair". Key Block LMK form uses reserved fields
//!   `FF` / `F` / `FFF`; DES KCV = encryption of a zero block, AES KCV = CMAC of
//!   a zero block (matching APC's `KeyCheckValue` for both algorithms); a
//!   6-digit KCV needs no authorization, 16-digit does. With a Key Block LMK the
//!   response always carries 6 valid digits.
//! - `KA` (`KB`): PUGD0538-003 p.73 — the legacy equivalent. NOT used here: its
//!   own spec says it is superseded by `BU`, it cannot do double-length ZMKs,
//!   and it is disabled when "Enforce key type 002 separation for PCI HSM
//!   compliance" is set to the compliant value.
//! - Variant-LMK `BU` needs a 2-digit Key Type Code the mapping does not carry.
//!   We iterate exactly the four codes documented in the `KA` spec — `00` ZMK,
//!   `01` ZPK, `02` TMK/TPK/PVK, `03` TAK — and accept the first `00` response.
//!   A wrong code decrypts under the wrong LMK pair/variant and fails key
//!   parity, so a false positive would require a parity-valid wrong decrypt.
//!   Keys of other types (e.g. BDK) come back [`ProbeOutcome::KeyTypeUnknown`]
//!   and are reported as warnings, not silently passed.
//! - Futurex `GPKR` is intentionally NOT implemented. The command exists
//!   (docs.futurex.com lists it as "General Purpose Key settings get (read
//!   only)") but no source available to this repo documents its field layout —
//!   the MCP registry built from the Futurex General Payment HSM Integration
//!   Guide (2024) does not contain it. Gated rather than guess a wire format;
//!   lifting the gate needs the Excrypt command reference or a capture from a
//!   real unit.
//!
//! Proof: mock-HSM round-trip tests in `tests/hsm_probe.rs`. There is no live
//! payShield in the test environment, so unlike the handler differentials this
//! is framing-level verification only — the KCV semantics rest on the manual.

use crate::config::DiscoverConfig;
use crate::protocol::thales::ThalesPayShield;
use crate::server::forward_to_hsm;

/// Message header used on probe frames; the HSM echoes it back and we check
/// the echo to catch cross-talk on the connection.
const PROBE_HEADER: &[u8; 2] = b"PB";

/// Outcome of one HSM-side KCV probe for a single `key_mappings` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The HSM returned a KCV (uppercase hex, 6 or 16 digits as returned).
    Kcv(String),
    /// Every candidate key type code was rejected — the key parses as a Thales
    /// wire form but is not one of the four types `BU` lets us name blind.
    KeyTypeUnknown,
    /// The HSM refused the command itself ('68' — disabled by security
    /// settings). Retrying with other keys cannot succeed.
    CommandDisabled,
    /// The HSM answered with an unexpected error code or a malformed frame.
    HsmError(String),
    /// The mapping key is not an LMK-encrypted Thales wire form (e.g. a plain
    /// label or an ARN) — there is nothing to send in a `BU`.
    UnsupportedForm,
    /// Could not connect / talk to the HSM at all.
    Unreachable(String),
}

/// Probe the source payShield for the KCV of one `key_mappings` key form.
pub async fn thales_kcv(cfg: &DiscoverConfig, key_form: &str) -> ProbeOutcome {
    let Some(candidates) = bu_candidates(key_form) else {
        return ProbeOutcome::UnsupportedForm;
    };

    let protocol = ThalesPayShield;
    let mut last_error: Option<String> = None;

    for payload in candidates {
        let frame = frame_command(*b"BU", payload.as_bytes());
        let resp = match forward_to_hsm(&frame, cfg, &protocol).await {
            Ok(bytes) => bytes,
            Err(e) => return ProbeOutcome::Unreachable(e.to_string()),
        };
        match parse_bv(&resp) {
            BvParse::Kcv(kcv) => return ProbeOutcome::Kcv(kcv),
            BvParse::Error(code) if code == "68" => return ProbeOutcome::CommandDisabled,
            // Any other error (parity '10', bad key type, …): this candidate
            // type code was wrong for this key — try the next one.
            BvParse::Error(code) => last_error = Some(format!("HSM error {code}")),
            BvParse::Malformed(why) => return ProbeOutcome::HsmError(why),
        }
    }

    match last_error {
        Some(_) => ProbeOutcome::KeyTypeUnknown,
        // Unreachable in practice: bu_candidates never returns an empty list.
        None => ProbeOutcome::HsmError("no BU candidates produced".into()),
    }
}

/// True when an APC `KeyCheckValue` and an HSM-returned KCV agree. APC KCVs
/// are 6 hex digits (zero-block encrypt for DES/TDES, zero-block CMAC for
/// AES); `BU` returns 6 or, in the legacy 16-digit mode, 16 of which the
/// leftmost 6 are the comparable part.
pub fn kcv_matches(apc: &str, hsm: &str) -> bool {
    let a = apc.to_ascii_uppercase();
    let h = hsm.to_ascii_uppercase();
    let n = a.len().min(h.len()).min(6);
    n > 0 && a.as_bytes()[..n] == h.as_bytes()[..n]
}

/// Build the ordered `BU` payload candidates for a wire key form, or `None`
/// when the form cannot be probed. Field order per PUGD0537-004 Rev A:
/// [2-digit Key Type][Key Length Flag][Key][';'+3-digit type iff 2-digit=='FF']
/// [';' + reserved '0' '0' + KCV type '1' (6-digit)].
fn bu_candidates(key_form: &str) -> Option<Vec<String>> {
    // Key Block LMK: reserved type/length fields, single unambiguous candidate.
    if key_form.starts_with('S') && key_form.len() > 1 {
        return Some(vec![format!("FFF{key_form};FFF;001")]);
    }

    let (len_flag, hex) = match key_form.as_bytes().first() {
        Some(b'U') => ('1', &key_form[1..]),
        Some(b'T') => ('2', &key_form[1..]),
        _ => ('0', key_form),
    };
    let expected = match len_flag {
        '0' => 16,
        '1' => 32,
        _ => 48,
    };
    if hex.len() != expected || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    // The four 2-digit key type codes documented in the KA spec (PUGD0538-003
    // p.73) — the only ones we can claim blind. Order puts the most common
    // proxy key types first to keep the average probe at one round-trip.
    Some(
        ["01", "02", "03", "00"]
            .iter()
            .map(|t| format!("{t}{len_flag}{key_form};001"))
            .collect(),
    )
}

/// Frame a host command: [2B BE length][2B header][2B command][payload].
fn frame_command(cmd: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let body_len = 2 + 2 + payload.len();
    let mut out = Vec::with_capacity(2 + body_len);
    out.extend_from_slice(&(body_len as u16).to_be_bytes());
    out.extend_from_slice(PROBE_HEADER);
    out.extend_from_slice(&cmd);
    out.extend_from_slice(payload);
    out
}

enum BvParse {
    Kcv(String),
    Error(String),
    Malformed(String),
}

/// Parse a `BV` response: [2B len][2B header]['B''V'][2A error][KCV 6/16 H].
fn parse_bv(resp: &[u8]) -> BvParse {
    if resp.len() < 8 {
        return BvParse::Malformed(format!("response too short ({} bytes)", resp.len()));
    }
    let body_len = u16::from_be_bytes([resp[0], resp[1]]) as usize;
    if resp.len() < 2 + body_len || body_len < 6 {
        return BvParse::Malformed("response length prefix inconsistent".into());
    }
    let body = &resp[2..2 + body_len];
    if &body[..2] != PROBE_HEADER {
        return BvParse::Malformed("response header does not echo probe header".into());
    }
    if &body[2..4] != b"BV" {
        return BvParse::Malformed(format!(
            "expected response code BV, got {:?}",
            String::from_utf8_lossy(&body[2..4])
        ));
    }
    let error_code = String::from_utf8_lossy(&body[4..6]).to_string();
    if error_code != "00" {
        return BvParse::Error(error_code);
    }
    let kcv: String = String::from_utf8_lossy(&body[6..]).to_string();
    let kcv = kcv.trim_end().to_ascii_uppercase();
    if (kcv.len() != 6 && kcv.len() != 16) || !kcv.bytes().all(|b| b.is_ascii_hexdigit()) {
        return BvParse::Malformed(format!("KCV field not 6/16 hex digits: {kcv:?}"));
    }
    BvParse::Kcv(kcv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyblock_form_single_candidate() {
        let c = bu_candidates("SD0016P0TE00N0000ABCD").expect("key block probeable");
        assert_eq!(c.len(), 1);
        assert!(c[0].starts_with("FFFS"));
        assert!(c[0].ends_with(";FFF;001"));
    }

    #[test]
    fn variant_forms_iterate_documented_types() {
        for (form, flag) in [
            ("0123456789ABCDEF", '0'),
            ("U0123456789ABCDEF0123456789ABCDEF", '1'),
            ("T0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", '2'),
        ] {
            let c = bu_candidates(form).expect("variant form probeable");
            assert_eq!(c.len(), 4);
            for cand in &c {
                assert_eq!(cand.as_bytes()[2] as char, flag);
                assert!(cand.ends_with(";001"));
            }
        }
    }

    #[test]
    fn non_key_forms_are_unsupported() {
        for form in [
            "arn:aws:payment-cryptography:us-east-1:0:key/abc",
            "alias/foo",
            "MY_LABEL",
            "0123",              // too short
            "0123456789ABCDEG",  // not hex
            "U0123456789ABCDEF", // U with single-length body
            "",
        ] {
            assert!(
                bu_candidates(form).is_none(),
                "{form:?} should be unsupported"
            );
        }
    }

    #[test]
    fn parse_bv_happy_and_error_paths() {
        let ok = ThalesPayShieldFrame::response(*b"00", b"D5D44F");
        assert!(matches!(parse_bv(&ok), BvParse::Kcv(k) if k == "D5D44F"));

        let parity = ThalesPayShieldFrame::response(*b"10", b"");
        assert!(matches!(parse_bv(&parity), BvParse::Error(c) if c == "10"));

        let sixteen = ThalesPayShieldFrame::response(*b"00", b"D5D44F0000000000");
        assert!(matches!(parse_bv(&sixteen), BvParse::Kcv(k) if k.len() == 16));

        assert!(matches!(parse_bv(b"\x00\x01x"), BvParse::Malformed(_)));
    }

    #[test]
    fn kcv_match_semantics() {
        assert!(kcv_matches("d5d44f", "D5D44F"));
        assert!(kcv_matches("D5D44F", "D5D44F0000000000")); // 16-digit HSM reply
        assert!(!kcv_matches("D5D44F", "B12345"));
        assert!(!kcv_matches("", "D5D44F"));
    }

    /// Test helper mirroring the HSM's response framing.
    struct ThalesPayShieldFrame;
    impl ThalesPayShieldFrame {
        fn response(error: [u8; 2], kcv: &[u8]) -> Vec<u8> {
            let body_len = 2 + 2 + 2 + kcv.len();
            let mut out = Vec::new();
            out.extend_from_slice(&(body_len as u16).to_be_bytes());
            out.extend_from_slice(PROBE_HEADER);
            out.extend_from_slice(b"BV");
            out.extend_from_slice(&error);
            out.extend_from_slice(kcv);
            out
        }
    }
}
