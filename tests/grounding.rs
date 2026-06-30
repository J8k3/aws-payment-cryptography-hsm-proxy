//! Grounding audit — enforces the in-code evidence scheme and keeps the generated
//! report in sync with the code. The source of truth is each handler's
//! `Handler::grounding()` (see `src/handlers/grounding.rs`); this test generates
//! `docs/grounding-report.md` from it, so the doc can never drift.
//!
//! Regenerate the report after changing any `grounding()`:
//!   GROUNDING_REGEN=1 cargo test --test grounding grounding_report_is_current

use apc_proxy::handlers::Registry;

fn manifest(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// The generated report must match the committed `docs/grounding-report.md`. If a
/// `grounding()` changed without regenerating, this fails (no silent drift).
#[test]
fn grounding_report_is_current() {
    let generated = Registry::build().grounding_report();
    let path = manifest("docs/grounding-report.md");

    if std::env::var("GROUNDING_REGEN").as_deref() == Ok("1") {
        std::fs::write(&path, &generated).expect("write grounding report");
        eprintln!("regenerated {}", path.display());
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        committed, generated,
        "\n\ndocs/grounding-report.md is stale (a Handler::grounding() changed). \
         Regenerate it:\n  GROUNDING_REGEN=1 cargo test --test grounding grounding_report_is_current\n"
    );
}

/// Every `Proof::LiveTest` must name a test that actually exists in
/// `tests/proptest_live.rs` — so a proof pointer can't dangle.
#[test]
fn live_test_proofs_reference_real_tests() {
    let live_src = std::fs::read_to_string(manifest("tests/proptest_live.rs"))
        .expect("read tests/proptest_live.rs");
    for entry in Registry::build().grounding_entries() {
        for ev in entry.evidence {
            if let Some(t) = ev.proof.live_test() {
                assert!(
                    live_src.contains(&format!("fn {t}")),
                    "grounding proof references live test `{t}`, which is not defined in tests/proptest_live.rs",
                );
            }
        }
    }
}

/// Coverage: handlers we've verified against live APC must carry grounding, so a
/// future edit that drops the evidence is caught.
#[test]
fn verified_handlers_carry_grounding() {
    let reg = Registry::build();
    for code in ["CW", "M6", "C2", "CA", "GO"] {
        let h = reg.get(code.as_bytes()).expect("handler registered");
        assert!(
            !h.grounding().is_empty(),
            "handler for {code} is verified by a live test but records no grounding"
        );
    }
}
