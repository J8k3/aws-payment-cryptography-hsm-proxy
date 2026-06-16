# Property-testing plan (live APC, per-run keys)

Status: planned, not started. Capture of the design agreed after the EMV ARQC
derivation/padding fix (`fix/emv-arqc-apc-correctness`).

## Why

The ARQC derivation and transaction-data padding bugs were invisible to the
existing tests by construction, not by oversight:

- Unit tests use a mock APC, so they never exercise real cryptography.
- The live integration tests use an APC-generated (random-material) IMK, so they
  cannot compute a matching cryptogram. They only assert "not error 68" /
  round-trip success — they never actually verify a real ARQC.

The proxy and its tests therefore shared the same wrong assumption. What caught
the bugs was the one thing both lack: an **independent oracle** (a reference
library computing the expected result from *known* key material) checked against
**live APC**. A returned error `00` cannot be faked.

Property testing generalizes exactly that, so it is the structural fix rather
than adding hand-written variants forever.

## Shape

1. **Per-run known-material keys.** Import a fixed-but-known IMK / BDK / ZPK / CVK
   / MAK into APC at suite setup; schedule deletion at teardown. Material is known
   to the oracle. (`scripts/import_test_keys.py` already does most of this.)
2. **Independent oracle.** Use `pyemv` / `psec` to compute the expected ARQC,
   ARPC, MAC, PIN block, and CVV from that material.
3. **Generators.** Randomize inputs within valid domains: PAN (and its length, to
   exercise EMV Option A vs B), PAN sequence, ATC, UN, amounts, EMV tags, the
   Thales scheme/CVN, PIN, expiry, service code.
4. **Drive the real proxy end-to-end.** Build the actual wire frame, send over
   TCP, read and parse the response (reuse the framing in `tests/integration.rs`).
5. **Assert and shrink.** Proxy result must equal the oracle's expectation (`00`
   plus any returned value). Use proptest-style shrinking to reduce a failure to a
   minimal reproducing case.

This covers the scheme x derivation x padding x PAN-length matrix that hand-written
variants cannot.

## Operational notes

- Makes real APC calls (cost + latency) and creates/deletes keys, so it is a
  **gated / nightly** suite, never part of `cargo test`. Gate behind an env var
  and `#[ignore]`, or a separate harness.
- Always tear keys down (the existing `scripts/delete_test_keys.py` pattern).

## First targets (open suspicions from the ARQC work)

- **MAC-handler padding.** `mac` / `legacy_mac` / `hmac` / `issuer_script_mac` /
  `dukpt_mac` / `mac_translate` forward message data to APC. Padding is assumed
  algorithm-intrinsic (APC pads per the MAC algorithm), unlike the EMV ARQC case.
  Likely correct, but unverified against a reference MAC.
- **cap K2 Option B + PAN length.** K2 uses EMV Option B; APC requires a PAN > 16
  digits for Option B. Confirm real Mastercard CAP PANs satisfy that, or the call
  is rejected.
- **unionpay JS derivation.** JS maps to `Emv2000`; confirm that matches real
  UnionPay / PBOC session-key derivation (APC has no UnionPay-specific mode).
