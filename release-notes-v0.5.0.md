# apc-hsm-proxy v0.5.0

This release adds **UnionPay session-key derivation**, puts the **forward leg behind an extension seam**, and closes a set of build configurations that were advertised but never tested.

## Highlights

### UnionPay session key derivation
AWS Payment Cryptography added UnionPay session-key derivation on 2026-07-15 — to `GenerateAuthRequestCryptogram`, `VerifyAuthRequestCryptogram`, `GenerateMac`, and `VerifyMac`. There was no announcement post, and the AWS API reference still lists the older set; the change is visible only in the SDK, where `SessionKeyDerivationMode` gains exactly one variant. Three gates written when APC lacked the primitive are now resolved:

- **`JS`** (UnionPay/CUP ARQC verify) maps to APC's native UnionPay method instead of the EMV2000 approximation it used before.
- **`KW` scheme `'C'`** (Union Pay Vers 4.2) — previously rejected as *unsupported (68)* — now verifies.
- **`KU` scheme `'6'`** (UnionPay issuer-script MAC) — previously rejected as *unsupported (68)* — now generates.

All three are validated against live APC by the differential harness, and the `KU` and `KW` sweeps were extended to cover the new schemes.

One result worth stating plainly: a live cross-check confirms **APC's UnionPay derivation is functionally identical to EMV2000** over PAN + PAN sequence + ATC. The previous `JS` mapping was therefore *not* wrong, and that change carries no behavioural difference — the real capability gains are `KW 'C'` and `KU '6'`.

### Pluggable forward leg
New **`ForwardLeg`** seam — "send one framed command to the backend HSM, return its complete response" — alongside the existing `VendorModule`. The core ships a single-endpoint implementation (a fresh connection per command, exactly as before); a deployment can substitute a different one, such as a pooled multi-endpoint leg, without forking the core.

The trait documents the contract its signature cannot carry: **exclusivity** (one logical request owns a connection until its complete response is read), **zero residual** (no unread bytes may survive an exchange — leftovers become the next request's response), and **poison-on-anomaly** (a connection is reusable only if provably clean). The core satisfies all three by never reusing a connection; the obligations bind implementations that do.

### Build configurations are now tested
The `thales` and `ring` / `aws-lc-rs` features existed so the core could be built without payShield and against either crypto provider, but CI only ever built the default set. **All three non-default configurations were broken** — the library compiled, the test targets did not. Fixed, and a `feature-matrix` CI job now covers no-vendor, `aws-lc-rs`, and `--all-features` on every push.

### Test-suite correctness
Two defects that presented as flaky tests were real bugs in the fixtures, both surfaced by running the suite far more often:

- Listen ports came from a **per-test-binary** counter seeded identically in every binary, so concurrently running test crates handed out the same port — and the readiness check would connect to another binary's proxy and assert against the wrong process.
- Two test crates generated TLS material into a directory keyed by a **wall-clock timestamp**, which is not unique at microsecond resolution. Colliding tests overwrote each other's CA and leaf certificates, so a client verified a certificate signed by a different CA.

Together these cut the integration-suite failure rate by roughly 5×.

### Dependencies and licensing
- AWS SDK crates advanced (`aws-sdk-paymentcryptographydata` 1.110 → 1.116), plus `rcgen` 0.14 and `rand` 0.10, each requiring an API migration in the test fixtures.
- Automated weekly dependency updates, grouped, with the AWS crates called out — a new session-key derivation arrives as an SDK bump, which is exactly how the UnionPay gap went unnoticed for six weeks.
- `LICENSE` restored to the canonical Apache-2.0 text, with copyright and scope-of-rights notices moved to `NOTICE`.

## Upgrade / breaking notes

- **`server::run_with` and `verify::run` each take an additional argument.** Pass `None` to keep current behaviour (the core's single-endpoint forward leg). This affects code that builds on the extension seams — a bolt-on vendor calling `run_with(cfg, modules)` becomes `run_with(cfg, modules, None)`. `server::run` is unchanged.
- `hsm_client::forward_to_hsm` is removed; its behaviour is now `forward::SingleEndpointLeg`.
- `hsm_probe::thales_kcv` takes `&dyn ForwardLeg` rather than `&HsmClient`.
- **`KW` scheme `'C'` and `KU` scheme `'6'` no longer return error 68.** Deployments that relied on those being refused should confirm the new behaviour is what they want.

## Install
Download the `apc-proxy` binary attached to this release, or build from source with `cargo build --release`.
