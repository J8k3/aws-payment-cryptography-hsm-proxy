# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

A Rust TCP proxy that translates Thales payShield 10K and Futurex Excrypt wire-protocol commands to AWS Payment Cryptography (APC) API calls. Target use case: migrating payment applications that can't be refactored to call APC directly. The application sends the same commands to the same address; the proxy translates them on the outbound side without touching application code.

## Setup and Running

```bash
cargo build                          # debug build
cargo build --release                # release build
cargo run -- --config proxy.yaml     # start proxy
```

AWS credentials are consumed via the standard AWS credential chain (IAM role, `~/.aws/credentials`, environment variables). Set `AWS_REGION` as needed.

## Testing

```bash
cargo test          # unit and integration tests
cargo test -- --nocapture   # with stdout
```

## Architecture

```
src/
├── main.rs         — entry point, CLI args (--config, --verify-only), config load, dispatch
├── server.rs       — TCP listener, connection dispatch, passthrough (incl. outbound TLS) logic
├── verify.rs       — --verify-only mode: APC inventory + key_mappings sanity check
├── config.rs       — proxy.yaml schema (vendor, listen{tls}, aws, key_mappings, discover{tls})
├── key_map.rs      — two-path resolver: labels via config, wrapped keys via startup APC KCV scan
├── error.rs        — error types
├── protocol/       — wire-protocol parsers: thales.rs, futurex.rs
└── handlers/       — per-command APC translators: thales/, futurex/, noop.rs
```

### Test suite layout

```
tests/
├── integration.rs       — live APC tests (gated with #[ignore]; require running proxy)
├── passthrough.rs       — discover/passthrough mode against an in-test mock HSM
├── tls.rs               — inbound TLS + mTLS handshake / rejection
├── forward_tls.rs       — outbound TLS/mTLS on the forward leg to the HSM
└── common/              — shared fixtures: mock_hsm.rs, proxy_process.rs, tls_certs.rs
```

**Adding a new command handler:**
1. Create handler in `handlers/thales/` or `handlers/futurex/` — payload parsing happens here, not in `protocol/`
2. Declare the module in `handlers/thales/mod.rs` or `handlers/futurex/mod.rs`
3. Register the command code in `Registry::build()` in `handlers/mod.rs`
4. Add a test covering the happy path and a known-bad-input case
5. Update `README.md` command support table
6. Update the implementation table in `AGENTS.md`
   (Only modify `protocol/thales.rs` or `protocol/futurex.rs` if the command requires a framing change — rare.)

**Key-field parsing decisions live in `docs/key-presentation.md`** — the wire-form matrix says which commands accept the `'S'` prefix (wrapped key blocks) and which are fixed-width per spec. Check it before assuming a new handler can use `parse_legacy_key` / `parse_bdk` / `parse_key_32`; if the command's wire spec defines a fixed-width key field, hardcode the slice and use `resolve` rather than `resolve_descriptor`.

**Operator-facing setup procedure** lives in `docs/setup.md` — the full prerequisites, discovery, key inventory, import, validation (`--verify-only`), cutover, and production hardening flow. When the user asks setup-shaped questions ("how do I deploy this", "how do I migrate my keys"), point them at that doc and the matching phase rather than reconstructing the procedure inline.

## Session Start

- At the start of a session, sync with `origin/master` before doing substantive work.
- Preferred command: `git pull --rebase origin master`
- Only do this automatically when the worktree is clean. If local changes are already present, inspect before rebasing.

## Commit Scope

- Keep commits small and reviewable by default.
- Prefer one commit per logical change — a single coherent unit a reviewer can evaluate independently.
- Group related changes (e.g., a new feature + its test + the knowledge-base entry it required) into one commit when they can't be evaluated independently.
- Prefer squash or amend for iterative follow-ups — if a second commit only fixes or extends the immediately preceding one, squash rather than leaving noise in the log.
- Do not split a change just to make it look smaller; split when a reviewer would genuinely benefit from evaluating the pieces independently.
- When CI flags a lint or test failure after a push, fix locally and **amend or squash into the failing commit** (using `git push --force-with-lease`) rather than adding a new fix commit on top.

## Knowledge Contribution

When working in this repo and new HSM command behavior surfaces — protocol edge cases, APC API constraints, key mapping requirements — write it back into the MCP server in the same session:

| Discovered in | Write it to |
|---|---|
| HSM command protocol detail | `W:\aws-payment-cryptography-mcp\src\apc_agent\hsm_analysis.py` (command registry) |
| APC API constraint or gap | `W:\aws-payment-cryptography-mcp\payment-knowledge-base.md` |
| PCI compliance rule | `W:\aws-payment-cryptography-mcp\src\apc_agent\compliance.py` |

Do not defer knowledge updates. The proxy and the MCP server are a knowledge loop.

## Code Quality

After every implementation or edit, run clippy and fix all output before reporting the work as done:

```bash
cargo clippy -- -D warnings
cargo test
```

Both must exit 0. A warning is a bug waiting to happen — treat it as one.

**What the lint config enforces** (`Cargo.toml [lints]`):
- `unwrap_used = "deny"` — bare `.unwrap()` is a hard error; use `.expect("reason")` with a message explaining the invariant, or propagate with `?`
- `dead_code = "deny"` — unused fields and functions must be removed, not commented out
- `pedantic = "warn"` — full pedantic lint set, with targeted suppressions for intentional patterns (see Cargo.toml comments)

**When clippy fires on something you want to keep**, add a targeted `#[allow(clippy::lint_name)]` at the smallest scope (the item, not the module), with a comment explaining why:
```rust
#[allow(clippy::too_many_lines)] // 120-line parser is justified: step-by-step field layout matches spec
```

Never add a blanket `#![allow(...)]` at the file or crate level without explicit user approval.

## Implementation State and Gap Analysis

### How to determine what is implemented

Do not rely on memory or KB output alone. Cross-reference three sources:

1. **Grep `fn command_codes`** across `src/handlers/` — list every command string in every handler's `command_codes()` return value.
2. **Grep `HandlerResult::err.*68`** across `src/handlers/thales/` — commands that appear in `command_codes()` but immediately return error 68 in `handle()` are explicitly unsupported (e.g. CO/CQ in `dukpt_pin_verify.rs`, GS/GU in `dukpt_pin_verify_aes.rs`).
3. **Read `src/handlers/noop.rs`** — these commands are also explicitly registered as unsupported (returns error 68). They are NOT gaps; they are documented decisions.
4. **Subtract (implemented + error-68 stubs + noop)** from the full `hsm_list_commands(vendor="Thales")` output to find the true gap.

KB `apc_operation` and `confidence` fields can be misleading at the **algorithm** level — the correct APC API call may be named but the algorithm variant may not exist. Always verify against the APC API before implementing.

### Implemented Thales command families (as of May 2026)

| Family | Commands | Handler file |
|--------|----------|--------------|
| Heartbeat | B2 | `thales/heartbeat.rs` |
| PIN translate | CA, CC, BQ, CI, G0 | `thales/pin.rs` |
| PIN verify (DUKPT TDES) | CK, CM | `thales/dukpt_pin_verify.rs` |
| PIN verify (DUKPT AES) | GO, GQ | `thales/dukpt_pin_verify_aes.rs` |
| PIN verify (non-DUKPT) | DA, DC, EA, EC | `thales/pin_verify_non_dukpt.rs` |
| PIN change | CU, DU | `thales/pin_change.rs` |
| PIN generate (Diebold) | GA, CE | `thales/diebold_pin.rs` |
| PIN generate (random IBM 3624) | JA | `thales/random_pin.rs` |
| CVV / CVC | CW, CY, NY, RY | `thales/cvv.rs` |
| Dynamic CVV | PM, QY | `thales/dynamic_cvv.rs` |
| Encrypt/decrypt | HE, HG | `thales/encrypt_decrypt.rs` |
| International encrypt | M0, M2, M4 | `thales/international_encrypt.rs` |
| EMV counter decrypt | K0 | `thales/emv_decrypt.rs` |
| MAC (AS2805 + International) | C2, C4, M6, M8 | `thales/mac.rs` |
| MAC translate | MY | `thales/mac_translate.rs` |
| Legacy TAK MAC | MA, MC, ME, MK, MM, MO, MQ, MS, MU, MW | `thales/legacy_mac.rs` |
| DUKPT MAC | GW | `thales/dukpt_mac.rs` |
| HMAC | LQ, LS | `thales/hmac.rs` |
| ARQC/ARPC (Visa/Amex + Mastercard, standard EMV) | KQ | `thales/kq_arqc.rs` |
| ARQC verify (Mastercard CAP / EMV2000) | K2, KS | `thales/cap_arqc.rs` |
| ARQC/ARPC (Visa CVN14/CVN18/CVN22 + Mastercard M/Chip SKD) | KW | `thales/kw_arqc.rs` |
| ARQC/ARPC (UnionPay) | JS | `thales/unionpay_arqc.rs` |
| Issuer script MAC | JU, KU, KY | `thales/issuer_script_mac.rs` |
| Noop (error 68) | See `handlers/noop.rs` | `handlers/noop.rs` |

### Key APC algorithm constraints (not in KB confidence scores)

- **BC/BE** (PIN verify, comparison method): APC `PinVerificationAttributes` union has no comparison method. PCI PIN §3.5 prohibits clear PIN. → error 68.
- **CG/EG** (PIN verify, Diebold method): APC `PinVerificationAttributes` has no Diebold variant. Same gap for DUKPT variants CO/CQ (TDES) and GS/GU (AES). → error 68.
- **AQ** (RSA-encrypted PIN translate): APC `TranslatePinData` `IncomingTranslationAttributes` accepts only ISO 9564 formats 0/1/3/4 — no RSA input path. → error 68.
- **M6/M8/MY, MU/MW/MQ/MS** (continuation MAC modes): APC `GenerateMac`/`VerifyMac` are single-call only — no multi-block session state. Mode 0 (single-block, complete message) is the only supported mode; mode 1 (continuation) returns error 15. Applies to both the extended MAC handler (M6/M8/MY) and the legacy binary MAC handler (MU/MW/MQ/MS).
- **JC/JE/JG** (LMK-encrypted PIN translate): LMK is Thales-internal; no APC equivalent. → error 68.
- **KQ/KW CVN variant** (Visa CVN17/CVN18/CVN22): both handlers use APC `SessionKeyDerivation::EmvCommon` (PAN+PanSeq+ATC), which is correct for standard EMV and Visa CVN10/CVN14. Visa CVN17/18/22 require `SessionKeyDerivation::Visa` (PAN+PanSeq only); Mastercard M/Chip SKD requires `SessionKeyDerivation::Mastercard` with Unpredictable Number. These variants are not auto-selected from the wire format — ARQC verify will fail with error 01 for those card types.

### Known remaining gaps (true unimplemented commands)

| Command(s) | APC operation | Notes |
|------------|--------------|-------|
| RI RK RM RO RQ RS RU RW, HI HK HM HO HQ HS HU HW | mixed | AS2805/RTKS combined MAC+translate; deferred |

## Live APC Testing

This procedure provisions real APC keys, runs the proxy against them, captures latency, and tears down the keys. Run it before a public release or when validating a new handler family against real APC behaviour. It is **not** part of the routine `cargo test` cycle.

### Prerequisites

- AWS credentials resolving to an account with `payment-cryptography:*` permissions.
- Region: `us-east-1` (default for this project; override with `AWS_DEFAULT_REGION`).
- The proxy binary built: `cargo build --release`.

### Step 1 — Provision test keys

```powershell
python scripts/import_test_keys.py
```

Imports six known-material keys via KEY_CRYPTOGRAM (P0 src/dst, V1, V2, B0 BDK, E0 IMK) and creates six APC-generated keys (M1, M3, M6 CMAC, M7 HMAC, C0 CVK, D0 DEK). Prints the full `key_mappings` block to paste into `proxy.yaml`. The script is idempotent — re-run after every cleanup; ARNs change on every re-import, labels are stable.

### Step 2 — Update proxy.yaml

Paste the `key_mappings` block printed by Step 1 over the existing block in `proxy.yaml`.

### Step 3 — Validate the config before starting

```powershell
cargo run --release -- --config proxy.yaml --verify-only
```

Exits 0 only if every `key_mappings` entry resolves to a `CREATE_COMPLETE`, enabled APC key. Catches typos, DELETE_PENDING ARNs, disabled keys, missing cert files, half-configured mTLS. Always run this after editing `proxy.yaml` and before starting the listener.

### Step 4 — Start the proxy

```powershell
# Copy first to free target/debug/apc-proxy.exe for the test build:
Copy-Item .\target\debug\apc-proxy.exe .\target\debug\apc-proxy-live.exe
$env:RUST_LOG = "apc_proxy=info"
.\target\debug\apc-proxy-live.exe --config proxy.yaml
```

The proxy is ready when it logs `proxy listening`. The startup log shows `scanned=N indexed=N skipped_disabled=0` — confirms the APC inventory scan worked.

### Step 5 — Run the integration tests

In a second terminal (proxy stays running):

```powershell
$env:PROXY_HOST = "127.0.0.1"
$env:PROXY_PORT = "1500"
cargo test --test integration -- --ignored --nocapture
```

23 Thales tests must pass; the 2 Futurex tests are expected to fail when the proxy is in `thales_payshield` mode and skip when in `futurex_excrypt` mode. Re-run with `vendor: futurex_excrypt` in `proxy.yaml` to exercise those.

The in-process suites (`cargo test --test passthrough --test tls --test forward_tls`) run without a separately-started proxy — they spawn `apc-proxy` as a subprocess per test and don't need AWS credentials to pass.

### Step 5 — Capture latency

Every handled command emits a structured log line in the proxy terminal:

```
INFO apc_proxy::server: command handled cmd=B2 error_code=00 latency_us=41
INFO apc_proxy::server: command handled cmd=MA error_code=00 latency_us=8712
INFO apc_proxy::server: command handled cmd=MC error_code=00 latency_us=7834
```

The `latency_us` field is wall-clock time from completed frame parse to APC response — i.e., APC round-trip plus proxy encoding overhead. Collect representative values across command families and record them in the README latency table (see README § Performance).

### Step 6 — Delete test keys (critical — avoids ongoing charges)

If you used the full integration test key set committed in `proxy.yaml`, run:

```powershell
python scripts/delete_test_keys.py
```

This reads all ARNs from `proxy.yaml key_mappings` and schedules each for deletion (7-day waiting period). Keys already in `DELETE_SCHEDULED` state are skipped cleanly. Re-run is idempotent.

For ad-hoc keys created outside `proxy.yaml`, use `mcp__apc-agent__delete_key` per ARN, or add the ARNs to `proxy.yaml` first and then run the script.

### Step 7 — Restore proxy.yaml

**For the committed integration test key set:** `proxy.yaml` intentionally commits ARNs for the full integration test suite — these are documented non-production keys with known material (see the comment block above `key_mappings`). Leave them in place.

**For ad-hoc keys added for a one-off test:** remove those entries from `proxy.yaml` before committing. Do not commit ARNs that are not part of the documented test key set.

### What constitutes a passing live test

- `thales_b2_heartbeat_returns_success`: error code `00` (proxy liveness, no APC call)
- At least one MAC command (MA or M6): error code `00` from APC
- At least one encrypt command (HE or M0): error code `00` from APC
- All `latency_us` values under 100 ms (100,000 µs) for a same-region deployment
- Zero keys remaining in the account after Step 6

## Critical Behavioral Rules

- **Never intercept live traffic in test code.** Protocol parsers and handlers are tested against crafted byte buffers only. Do not write tests that open real sockets to production systems.
- **Passthrough is the safety net.** Unhandled commands forward to the real HSM (if configured). Do not remove passthrough behavior without explicit user direction.
- **Key map correctness is the user's responsibility.** The proxy translates key labels to APC key IDs via the `key_mappings:` section of `proxy.yaml`. Do not generate or modify key maps without explicit user instruction — a wrong mapping sends live cryptographic operations to the wrong key.
- **Zeroize sensitive buffers.** PIN blocks, key material, and MAC values must use `zeroize` on drop. Do not hold sensitive data in `String` or unzeroized `Vec<u8>`.
