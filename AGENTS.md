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
├── config.rs       — proxy.yaml schema (vendor, listen, upstream, key_map)
├── key_map.rs      — maps local HSM key labels to APC key identifiers
├── error.rs        — error types
├── protocol/       — wire-protocol parsers: thales.rs, futurex.rs
└── handlers/       — per-command APC translators: thales/, futurex/
```

**Adding a new command handler:**
1. Add parser support in `protocol/thales.rs` or `protocol/futurex.rs`
2. Create handler in `handlers/thales/` or `handlers/futurex/`
3. Register the command code in `handlers/mod.rs`
4. Add a test covering the happy path and a known-bad-input case
5. Update `README.md` command support table

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

## Critical Behavioral Rules

- **Never intercept live traffic in test code.** Protocol parsers and handlers are tested against crafted byte buffers only. Do not write tests that open real sockets to production systems.
- **Passthrough is the safety net.** Unhandled commands forward to the real HSM (if configured). Do not remove passthrough behavior without explicit user direction.
- **Key map correctness is the user's responsibility.** The proxy translates key labels to APC key IDs via `key_map.yaml`. Do not generate or modify key maps without explicit user instruction — a wrong mapping sends live cryptographic operations to the wrong key.
- **Zeroize sensitive buffers.** PIN blocks, key material, and MAC values must use `zeroize` on drop. Do not hold sensitive data in `String` or unzeroized `Vec<u8>`.
