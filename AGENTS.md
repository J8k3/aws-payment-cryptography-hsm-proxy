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
├── main.rs         — entry point, CLI args, config load, server start
├── server.rs       — TCP listener, connection dispatch, passthrough logic
├── config.rs       — proxy.yaml schema (vendor, listen, aws, key_mappings, discover)
├── key_map.rs      — maps local HSM key labels to APC key identifiers
├── error.rs        — error types
├── protocol/       — wire-protocol parsers: thales.rs, futurex.rs
└── handlers/       — per-command APC translators: thales/, futurex/
```

**Adding a new command handler:**
1. Create handler in `handlers/thales/` or `handlers/futurex/` — payload parsing happens here, not in `protocol/`
2. Declare the module in `handlers/thales/mod.rs` or `handlers/futurex/mod.rs`
3. Register the command code in `Registry::build()` in `handlers/mod.rs`
4. Add a test covering the happy path and a known-bad-input case
5. Update `README.md` command support table
6. Update the implementation table in `AGENTS.md`
   (Only modify `protocol/thales.rs` or `protocol/futurex.rs` if the command requires a framing change — rare.)

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

## Critical Behavioral Rules

- **Never intercept live traffic in test code.** Protocol parsers and handlers are tested against crafted byte buffers only. Do not write tests that open real sockets to production systems.
- **Passthrough is the safety net.** Unhandled commands forward to the real HSM (if configured). Do not remove passthrough behavior without explicit user direction.
- **Key map correctness is the user's responsibility.** The proxy translates key labels to APC key IDs via the `key_mappings:` section of `proxy.yaml`. Do not generate or modify key maps without explicit user instruction — a wrong mapping sends live cryptographic operations to the wrong key.
- **Zeroize sensitive buffers.** PIN blocks, key material, and MAC values must use `zeroize` on drop. Do not hold sensitive data in `String` or unzeroized `Vec<u8>`.
