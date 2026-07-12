# apc-hsm-proxy v0.4.0

This release turns the proxy into an **extensible, single-vendor open core validated against live AWS Payment Cryptography**, and establishes a clean boundary for vendor and enterprise add-ons.

## Highlights

### Pluggable vendor architecture
- New **`VendorModule`** extension seam: a vendor contributes its wire `Protocol` + `Handler`s as a module. The built-in Thales support ships as `ThalesModule`, registered through the exact same seam any add-on uses — no special-casing.
- **`server::run_with(cfg, modules)`** selects the module matching `vendor` in config.
- **`Protocol::redact_discovery`**: per-vendor, log-safe discovery-log redaction (Thales default: command code + payload length only — no values).

### Thales-only open core + compile-time vendor removal
- The open-source core is now **Thales payShield 10K only**. Futurex support has moved to a separately licensed [**Enterprise edition**](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy#enterprise-edition).
- New default **`thales`** cargo feature. Build the framework with no vendor code compiled in via `--no-default-features --features ring` — a reduced attack surface for deployments that don't need a given vendor.

### Validated against live APC
- A live-APC **differential property-test harness**: each handler is exercised through its wire frame and compared byte-for-byte against a direct APC SDK call built from the same field values, across randomized inputs, with per-case seeding + single-case replay and a zero-surviving-test-key invariant.
- An in-code **grounding scheme** is the single source of truth for why each handler behaves as it does (manual citation + proof), enforced for full coverage in CI.
- Coverage spans PIN translate, PIN verify (IBM 3624 + Visa PVV, DUKPT and static), MAC (ISO 9797 Alg 1/3, CMAC, HMAC, DUKPT), CVV generate/verify, data encrypt/decrypt, EMV ARQC verify + ARPC generate, EMV issuer-script MAC, and the wrapped-key (KCV-indexed) resolution path.

### Correctness & explicit gating
- Numerous handler fixes grounded against the payShield manuals — EMV PAN/PSN decode, PIN-block-format forwarding, MAC sizes, CA/CC wire format, K2 derivation, GO/GQ offsets, and more.
- Operations that APC does not support (or that are not yet validated) now **fail explicitly as unsupported** rather than silently mis-handling — dynamic CVV, random-PIN generation, Diebold PIN commands, HMAC (LQ/LS), RTKS/AS2805.6.2, and Visa-PVV-DUKPT (GQ).

### Robustness & security hardening
- Registry-wide malformed/oversized/hostile-input sweeps; every handler survives malformed input.
- Inbound availability hardening (per-connection accumulation cap, idle read-timeout eviction, bounded concurrent connections) and rejection of unknown config keys.
- `--verify-only` cross-checks the source HSM's KCV via a `BU` probe against APC's KCV.

### Documentation
- A deployer **threat model** and PCI P2PE / PIN scope obligations; AWS Payment Cryptography's compliance posture referenced.
- Corrected key-presentation reference (wire forms → APC resolution) and clear **Enterprise edition** advertising in the README and CLI `--help`.

## Upgrade / breaking notes
- **Futurex is no longer in the open core.** Deployments that used `vendor: futurex_excrypt` need the licensed Enterprise edition.
- The default build no longer compiles any non-Thales vendor.
- Some commands that previously attempted a best-effort translation now return an explicit *unsupported* error pending validation (see the gating list above). Review against your command set before upgrading.

## Install
Download the `apc-proxy` binary attached to this release, or build from source with `cargo build --release`.
