<!--
Keep this lean. Delete sections that don't apply.
-->

## Summary

<!-- What changed and why. -->

## Checklist

- [ ] `cargo fmt` + `cargo clippy --all-targets -- -D warnings` clean
- [ ] Offline suite green (`cargo test`) — parsing, framing, mock-APC, no-panic fuzz
- [ ] Grounding updated if behavior or evidence changed, and `docs/grounding-report.md` regenerated (`GROUNDING_REGEN=1 cargo test --test grounding grounding_report_is_current`)
- [ ] Public surface clean — no private references, account IDs, ARNs, or wrong-turn narrative in the diff

## Live APC differential

The live differentials in `tests/proptest_live.rs` are `#[ignore]` and **not run in CI on purpose** — they need real AWS credentials and each run costs money. They are the only check that verifies the proxy hands APC the *right inputs* (the wire mapping / `diff-xprov` grade), so run the affected handler's differential when its field mapping or crypto attributes change — you don't need the whole suite, just the one test.

Depth vs. breadth (cost-aware):
- **One handler's mapping changed** → run *that* differential at the default depth (`APC_LIVE_CASES=32` is thorough and cheap for one command).
- **A shared parser changed** (`common.rs`, `key_map`, framing) → run *all* handlers at shallow depth (`APC_LIVE_CASES=4`) to catch a cross-handler regression cheaply, rather than 32 cases on everything.

- [ ] **No handler field-mapping or crypto-attribute change** — N/A, skipped.
- [ ] **A handler mapping changed** — ran its differential against APC and pasted the result:

<!--
  Example:
    cargo test --test proptest_live <handler_differential> -- --ignored
  Paste the pass/fail line, e.g.:
    test issuer_script_mac_differential ... ok  (15/15)
-->

```
(paste result, or "N/A")
```
