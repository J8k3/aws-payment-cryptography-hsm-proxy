# Property-testing plan (live APC, per-run varying keys)

Status: design agreed; implementation next. Supersedes the original ARQC-era
draft. Captures the design after the systemic handler audit
(`fix/pin-block-format-mapping`).

## Why (the problem is bigger than ARQC)

The original draft framed this around the EMV ARQC derivation/padding bug. The
later audit showed the same failure mode is **pervasive**: a whole family of
handlers had been written from a fabricated wire spec, with wrong field offsets
and a wrong PIN-block-format-code scheme. Confirmed and fixed/gated this round:
CVV `CW`/`CY`/`NY`/`RY`, dynamic CVV `QY`/`PM`, PIN translate `CA`/`CC`/`BQ`/`G0`
(plus a non-existent `CI`), DUKPT verify `GO`/`GQ`, Diebold `GA`/`CE`/`GS`,
random PIN `JA`, HMAC `LQ`/`LS`, issuer-script MAC `JU`/`KU`/`KY`, and the MAC
`M6` size / `C2` alignment bugs.

Every one of these was a **parse/map** bug — the handler decoded the wire wrong
or called APC with the wrong parameters. None were caught by the existing tests,
because:

- Unit tests use a mock APC, so they never exercise real translation.
- The live integration tests (`tests/integration.rs`) are `#[ignore]`, pinned to
  a **fixed standing key pool**, and — critically — **encode the same fabricated
  wire formats the handlers did**, so they could never have flagged the bugs.
  They are now doubly stale (old formats + the standing keys were deleted) and
  must be rewritten, not trusted.

What actually caught the bugs was reading the authoritative manual and checking
the proxy against **live APC**. Property testing generalizes that into a
repeatable suite instead of one-off manual audits.

## Two requirements that shape everything

1. **Vary the keys *and* the inputs every run.** A fixed key set hides a class of
   bugs (a handler that ignores the wire key field, or crypto that only works for
   one key value). So each run creates fresh, randomly-generated keys. The old
   standing pool (`LTEST_*` / `LIVETEST_*`, KCVs `D5D44F`/`A68CDC`/`85A8D3`/
   `664CDA`/`08D7B4`/`57860B`, …) has been deleted and must not return.

2. **Teardown is part of the test, not a follow-up.** Keys created in setup are
   deleted in teardown on *every* exit path (success, failure, panic) via an RAII
   guard, and the suite asserts zero surviving `CREATE_COMPLETE` keys at the end.
   A prior run leaked the standing pool; that must never recur. (APC `DeleteKey`
   has a 3-day minimum window — that's fine, the keys are decommissioned
   immediately; the assertion checks they're no longer `CREATE_COMPLETE`.)

## Two oracle tiers

### Tier 1 — differential vs APC (build this first)

For each command, generate random *valid* field values, encode them into the
real Thales wire frame, run the handler, and compare its APC result against a
**direct APC SDK call built from the same field values**:

```
fields            = random_valid(command)      # PAN, expiry, service code, KSN, …
result_proxy      = handler.handle(cmd, encode_wire(fields), state)
result_oracle     = direct_apc_call(fields, key_arn)   # same op, params by hand
assert result_proxy == result_oracle
```

- **Catches every bug found this session** (field offsets, format-code mapping,
  mode handling, MAC size) because the test's encoder is written independently
  from the manual; if the handler's decoder disagrees, the APC results diverge.
- **Needs no known key material** — APC is the reference. Uses freshly created
  keys whose clear value we never need to know.
- The encoder must be written *from the manual*, not by reading the handler, so
  the two don't share a wrong assumption. Randomizing PAN length, format codes,
  key prefixes (`16H`/`U+32H`), and service codes exposes offset bugs a fixed
  input would mask.
- **Edge-biased generation.** Each input is varied within its known bounds with
  the boundary and structurally-interesting values *over-sampled* (`edge_biased`),
  not uniformly random — a small live sweep would otherwise rarely hit the exact
  edges where fixed-offset parse bugs live. Document the bounds and the
  interesting values per variable: e.g. PAN length 13..19 with edges
  {13, 15 (Amex), 16 (default), 19}; MAC message 1..32 bytes with edges around
  the 8-byte DES block {1, 7, 8, 9, 16, 32}. When a handler adds an axis (PIN
  block format code, KSN length, key prefix), give it the same treatment.

### Tier 2 — second-implementation spec oracle (later; the `2impl` story)

Generate fresh key material whose clear value we *do* know (create exportable
test keys, or import known material under a per-run KEK), compute the expected
CVV/PVV/MAC/ARQC with a *second* implementation, and assert APC (and therefore
the proxy) matches. This corroborates crypto correctness against the spec, not
just "matches APC."

**CyberChef Payments** is the natural fit here: a purpose-built,
inspectable payment-cryptography implementation whose operations already cover
CVV, PIN-block, DUKPT, MAC and EMV crypto (the oracle), and whose
input-generation code can drive the generators. Honest caveat: it shares an
author with this proxy, so it cross-checks the implementation rather than being
a neutral oracle — APC (AWS) and, where present, a from-spec computation are the
independent anchors. Aspirational, not required for Tier 1.

## Harness architecture (in-process, because the crate is a bin)

`apc-proxy` is a `[[bin]]` with no `lib.rs`, so `tests/integration.rs` can only
reach it over TCP — which cannot register per-run keys (static `proxy.yaml`).
The differential harness therefore runs **in-process as an in-crate
`#[cfg(test)]` module** (e.g. `src/proptest/differential.rs`, `#[ignore]`), which
can access `crate::handlers::*` and `crate::key_map::*` directly:

```rust
// setup (once per run)
let cpc = aws_sdk_paymentcryptography::Client::new(&cfg);        // control plane
let dpc = aws_sdk_paymentcryptographydata::Client::new(&cfg);    // data plane
let keys = TestKeys::create(&cpc, &[C0_CVK, P0_ZPK, V2_PVK, ...]).await; // RAII guard
let mut labels = HashMap::new();
labels.insert("CVK".into(), keys.arn(C0_CVK));                   // per-run mapping
let state = Arc::new(AppState { key_map: KeyMap::new(labels), data: dpc.clone() });

// per case (seeded RNG, ~N cases — not proptest's hundreds; live calls cost)
for _ in 0..N {
    let f = gen_cw_fields(&mut rng);                 // random PAN/expiry/service
    let wire = encode_cw(&f, "CVK");                 // from-manual encoder
    let proxy = CvvHandler.handle(b"CW", &wire, &state).await;  // -> CVV
    let oracle = dpc.generate_card_validation_data()
        .key_identifier(keys.arn(C0_CVK))
        .primary_account_number(&f.pan)
        .generation_attributes(cvv1(&f.expiry, &f.service))
        .send().await?;
    assert_eq!(proxy.payload, oracle.validation_data().as_bytes());
}
// teardown: TestKeys::drop deletes every created key; suite asserts zero remain
```

Notes:
- Use a **seeded** RNG (reproducible) and *not* proptest shrinking for the live
  tier (shrinking re-runs cases → cost). Proptest fits Tier 2's fast local oracle.
- Case count (`APC_LIVE_CASES`, default 32) is a cheap knob: keys are created
  once per test, not per case, so each extra case is only a few data-plane calls
  (~60 ms; measured 64 cases × 2 tests in ~8 s). Crank it for thorough runs.
- **Many cases per run + single-case replay.** Each test runs `APC_LIVE_CASES`
  randomized cases (the sweep). Each case is seeded *independently* from
  `(base seed, command label, case index)` via SplitMix64, so cases don't couple
  and any one can be re-run alone with `APC_LIVE_REPLAY=<idx>` (comma-separated
  for several). On failure the test prints the exact replay command. Replay
  reproduces the **wire inputs** deterministically — it does **not** pin the key
  (keys still rotate per run by requirement #1). That is sufficient for the
  parse/offset/mapping bug class this tier targets: such a bug makes
  proxy ≠ oracle for the reproduced input regardless of key. Reproducing a
  key-specific failure needs known key material (Tier 2).
- `TestKeys` is an RAII guard: `create` provisions and polls to `CREATE_COMPLETE`;
  `Drop` schedules deletion of each ARN. A final check lists `CREATE_COMPLETE`
  keys and fails if any test key survives.
- Gated behind `#[ignore]` + an env flag (e.g. `APC_LIVE=1`); never part of
  `cargo test`. Nightly / on-demand only.

## First slice, then fan out

1. CVV `CW` (generate) + `CY` (verify round-trip) — proves the harness end to end
   on a path already fixed and live-validated.
2. PIN translate `CC`, DUKPT `GO`/`GQ`, MAC `M6`/`C2` — the other paths fixed this
   round.
3. The un-audited handlers: `legacy_mac`, `dukpt_mac`, `mac_translate`,
   `emv_decrypt`, `encrypt_decrypt`, and `CK`/`CM`. The differential harness is
   how we reach a genuine "clean round."

## Cleanup of the old suite

`tests/integration.rs` must be rewritten or removed: it encodes pre-fix wire
formats (`C2 [mode][32H key]`, `CW` mode byte, `CA 00/01/03/04` formats, old M6
half-MAC = 2 bytes) and references the deleted standing key pool. Keep only the
generic framing helpers (`make_thales_frame`, `parse_thales_response`) if a TCP
end-to-end smoke test is still wanted; move correctness coverage to the
differential harness.

## Known coverage gap — EMV/ARQC PAN length is fixed at 12

An audit of the generators found one real gap. The generators are otherwise
strongly boundary-aware (`edge_biased` oversamples MAC padding edges
`[1,7,8,9,16,24,32]`, ATC `[1,0x2A,0xFFFF]`, PSN `[0,1,99]`, etc.), but every
EMV/ARQC differential fixes the PAN at 12 digits (`gen_pan(&mut rng, 12)`).

The 8-byte PAN/PSN field is a **14-nibble-PAN field**: EMV Option A packs it as
the PAN left-zero-padded to 14 digits, then the 2-digit PSN. `decode_bcd_pan_seq`
inverts that by stripping the pad zeros (`hex[..14].trim_start_matches('0')`). A
fixed 12-digit PAN therefore always packs *exactly two* pad zeros — so the strip
is exercised at one point only. The untested boundaries:

- **PAN = 14** — PAN‖PSN is exactly 16 digits, so **no padding, no strip**. This
  is the strip/no-strip boundary and is never hit today.
- **Shorter PANs** (e.g. 8) pad with more zeros, exercising that the strip
  removes the right count.

(Note: the field holds at most 14 PAN digits, so PAN > 14 is *not* representable
here — an earlier framing of this gap as "test up to 19" was wrong; 8/13/14 are
the meaningful edges.)

**Recipe (validate live before merging — a PAN=14 failure is a real Option-A
no-pad-boundary finding, not a test bug):**

1. Generalize the packer, keeping it backward-compatible (a 12-digit PAN yields
   the same bytes as today):
   ```rust
   fn pan_seq_bcd(pan: &str, seq2: &str) -> Vec<u8> {
       assert!(pan.len() <= 14 && seq2.len() == 2);
       hex_str_to_bytes(&format!("{pan:0>14}{seq2}")) // left-pad PAN to 14 nibbles
   }
   ```
2. At the **`pan_seq_bcd` callers only** (emv_decrypt `K0`, cap_arqc, ARQC
   `ks`/`js`/`kq`/`kw`/`k2`), replace `gen_pan(&mut rng, 12)` with an edge-biased
   length, e.g. `gen_pan(&mut rng, edge_biased(&mut rng, 8, 14, &[8, 13, 14]))`.
3. **Do not touch the ISO-0 PIN sites** (`pin_verify`, `pin_change`, `tpin`,
   `pin_translate`, DUKPT) — their `gen_pan(…, 12)` is a 12-digit account tied to
   the ISO-0 PIN block, not the EMV field.

The oracle already builds its APC call from the original `pan` string, so
consistency holds for any PAN ≤ 14 (decode(pack(pan)) == pan, since `gen_pan`'s
first digit is non-zero). Minor add while there: oversample `ATC = 0x0000` in the
EMV counter edge set (currently reachable but not oversampled, unlike `PSN = 0`).
