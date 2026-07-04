//! In-code evidence grounding for command handlers.
//!
//! This is the **single source of truth** for *why* each handler is implemented
//! the way it is and *how* that behaviour was verified. Each handler returns its
//! evidence from `Handler::grounding()`; the human-readable report
//! (`docs/grounding-report.md`) is *generated* from this data by the audit test
//! in `tests/grounding.rs` — it is never hand-edited, so it cannot drift from the
//! code. The evidence lives **only** here, not duplicated in handler doc-comments
//! (those keep the wire layout + a pointer to this).
//!
//! What the audit enforces: every `Proof::LiveTest` names a test that exists,
//! and **every registered handler carries grounding** — all handler structs now
//! do, so a handler added without evidence fails the audit rather than slipping
//! in ungrounded. Grounding *strength* still varies (see the grade vocabulary
//! below) and raising a handler's grade is ongoing, but coverage is complete.
//!
//! The vocabulary (`vec`/`vec-thru`/`2impl`/`apc`/`diff-xprov`/`cited`/`none`) is
//! the same one the original test-grounding inventory used. Claims are framed as
//! "verified against APC / cited to the manual", never "correct".

/// Wire-layout grounding — is the byte layout author-independent?
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireGrounding {
    /// A published crypto vector run *through the wire* (strongest; needs known
    /// input→output vectors). Not yet achieved by the live differentials.
    VecThru,
    /// Different-provenance differential: a from-the-manual encoder vs the handler,
    /// checked against live APC. A wrong field offset makes proxy ≠ APC, so this
    /// catches the wire/offset bug class. The strength the live harness reaches.
    DiffXprov,
    /// Manual-cited layout + human review only (weakest executable-free grounding).
    Cited,
    /// Not grounded on the wire.
    None,
}

/// Crypto grounding — is the expected value author-independent?
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CryptoGrounding {
    /// Published standard test vector (strongest — neither APC nor we computed it).
    Vec,
    /// A second implementation agrees (e.g. a from-spec check, `pyemv`/`psec`, or
    /// CyberChef Payments). Strength depends on independence: a from-spec or
    /// third-party impl is an independent anchor; a same-author impl cross-checks
    /// the code but can share blind spots — see the per-evidence `because`.
    TwoImpl,
    /// APC only — a single implementation. We verify the proxy *agrees with APC*,
    /// not that the crypto matches a published standard. Weakest crypto grounding.
    Apc,
    /// Not grounded.
    None,
}

/// Where the proof of a piece of evidence lives.
pub enum Proof {
    /// The live-APC differential test (function name in `tests/proptest_live.rs`)
    /// that re-proves this on every live run. The audit checks the name exists.
    LiveTest(&'static str),
    /// A manual page/field citation, with no executable proof of behaviour.
    ManualCite(&'static str),
    /// Deliberately unsupported / gated (returns payShield 68); the string is the
    /// sourced reason.
    Gated(&'static str),
}

/// One verified decision about a handler: what was decided, the evidence for it,
/// the grounding strength, and where the proof is.
pub struct Evidence {
    /// What the handler does / how a wire field is handled. One line, no `|`.
    pub decision: &'static str,
    /// The evidence — manual cite and/or live-APC observation. One line, no `|`.
    pub because: &'static str,
    pub wire: WireGrounding,
    pub crypto: CryptoGrounding,
    pub proof: Proof,
}

impl WireGrounding {
    pub fn label(self) -> &'static str {
        match self {
            WireGrounding::VecThru => "vec-thru",
            WireGrounding::DiffXprov => "diff-xprov",
            WireGrounding::Cited => "cited",
            WireGrounding::None => "none",
        }
    }
}

impl CryptoGrounding {
    pub fn label(self) -> &'static str {
        match self {
            CryptoGrounding::Vec => "vec",
            CryptoGrounding::TwoImpl => "2impl",
            CryptoGrounding::Apc => "apc",
            CryptoGrounding::None => "none",
        }
    }
}

impl Proof {
    pub fn label(&self) -> String {
        match self {
            Proof::LiveTest(t) => format!("live test `{t}`"),
            Proof::ManualCite(c) => format!("manual: {c}"),
            Proof::Gated(r) => format!("gated (68): {r}"),
        }
    }
    /// The live-test function name, if this proof is a live test.
    pub fn live_test(&self) -> Option<&'static str> {
        match self {
            Proof::LiveTest(t) => Some(t),
            _ => None,
        }
    }
}

/// One handler's report entry: its command codes and its evidence.
pub struct Entry {
    pub codes: Vec<&'static str>,
    pub evidence: &'static [Evidence],
}

/// Render the generated grounding report (Markdown). Deterministic in `entries`.
/// Grounded handlers get a detailed section; the rest are listed compactly as the
/// tracked documentation/testing gap (never silent blanks).
#[must_use]
pub fn format_report(entries: &[Entry]) -> String {
    use std::fmt::Write as _;
    let grounded: Vec<&Entry> = entries.iter().filter(|e| !e.evidence.is_empty()).collect();
    let ungrounded: Vec<&Entry> = entries.iter().filter(|e| e.evidence.is_empty()).collect();

    let mut s = String::new();
    s.push_str(
        "<!-- GENERATED by tests/grounding.rs (grounding_report_is_current). DO NOT EDIT. -->\n",
    );
    s.push_str("<!-- Source of truth: each handler's Handler::grounding(); see src/handlers/grounding.rs. -->\n\n");
    s.push_str("# Grounding report\n\n");
    s.push_str(
        "Evidence for *why* each handler behaves as it does and *how* it was \
         verified. Generated from `Handler::grounding()` — do not edit by hand. \
         Grounding labels: wire `vec-thru` > `diff-xprov` > `cited` > `none`; \
         crypto `vec` > `2impl` > `apc` > `none`.\n\n",
    );
    let _ = writeln!(
        s,
        "**Coverage:** {} of {} handlers carry grounding; {} not yet grounded \
         (tracked at the end). This reflects current state — it does not claim the \
         rest are verified.\n",
        grounded.len(),
        entries.len(),
        ungrounded.len()
    );

    for e in &grounded {
        let _ = writeln!(s, "## `{}`\n", e.codes.join("`, `"));
        for ev in e.evidence {
            let _ = writeln!(s, "- **{}**", ev.decision);
            let _ = writeln!(
                s,
                "  - wire `{}` · crypto `{}` · {}",
                ev.wire.label(),
                ev.crypto.label(),
                ev.proof.label()
            );
            let _ = writeln!(s, "  - {}", ev.because);
        }
        s.push('\n');
    }

    if !ungrounded.is_empty() {
        s.push_str("## Not yet grounded\n\n");
        s.push_str(
            "These handlers have no `grounding()` yet — the open documentation/testing \
             gap. Grounding them is the ongoing work (documentation + test added together).\n\n",
        );
        for e in &ungrounded {
            let _ = writeln!(s, "- `{}`", e.codes.join("`, `"));
        }
    }
    s
}
