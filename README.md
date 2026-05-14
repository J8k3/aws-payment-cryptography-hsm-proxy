# apc-hsm-proxy

A Rust TCP proxy that sits between HSM-dependent payment applications and [AWS Payment Cryptography (APC)](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/what-is.html). It speaks the wire protocol your application already sends — Thales payShield host commands or Futurex Excrypt — and translates them into APC API calls on the outbound side.

The intent is migration, not emulation. You point your application at the proxy instead of the HSM. Commands with registered handlers go to APC. Commands without one either pass through to a real HSM (discovery mode) or return an unsupported error — your choice, configurable per deployment.

This is not a full HSM replacement and it is not production-hardened out of the box. It is a migration bridge and a template for building one command handler at a time as you move off hardware.

---

## Supported Protocols

**Thales payShield** (`thales_payshield`) — 2-byte command code framing. Implemented handlers: CA/CC/CI/G0 (PIN translate), C2/C4/M6/M8 (MAC generate/verify), CW/CY (CVV generate/verify), B2 (diagnostics).

**Futurex Excrypt** (`futurex_excrypt`) — `[AOCCCC;param;param;]` framing. Implemented handlers: TPIN (PIN translate).

Coverage is intentionally narrow. Each handler maps one HSM command to one APC data plane call with the correct key type and parameter mapping. The handler registry is the extension point — add a file under `src/handlers/<vendor>/`, register it in `src/handlers/mod.rs`, and the proxy picks it up.

---

## Architecture

```
Application → TCP (TLS/mTLS) → apc-proxy → AWS Payment Cryptography API
                                   │
                              proxy.yaml
                              key_mappings
                                   │
                              (no handler?)
                                   └── discovery mode: forward to real HSM
                                       (log redacted) + return response
```

The `key_mappings` table in `proxy.yaml` is the translation layer for key identifiers. Your application sends whatever it already sends — a 32-char LMK-encrypted blob, a TR-31 key block, a label — and the proxy maps it to the APC key ARN before making the API call. Values that already look like ARNs or `alias/` names pass through unchanged.

Sensitive parameters (key blocks, PIN blocks) are never written to logs. In discovery mode, Futurex `AX`, `BT`, and `AL` parameters are replaced with `[REDACTED]`. Thales payloads log only command code and length.

---

## Configuration

```yaml
listen:
  host: 0.0.0.0
  port: 1500

vendor: thales_payshield   # thales_payshield | futurex_excrypt

aws:
  region: us-east-1
  # profile: apc-proxy     # omit to use default chain: IAM role → env → instance metadata

key_mappings:
  ZPK_INBOUND:  arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123
  ZPK_OUTBOUND: alias/zpk-outbound
```

**TLS** — add a `tls:` block under `listen:` with `cert_file` and `key_file`. Add `ca_file` to require client certificates (mTLS). Omit for plaintext; acceptable for local development, not for production.

**FIPS** — swap the `ring` feature for `aws-lc-rs` in `Cargo.toml` and recompile. No code changes needed.

**Discovery mode** — when `discover.enabled: true` and `discover.hsm_host` is set, unhandled commands are forwarded to the real HSM and the response is returned to the caller. Use this to observe what your application actually sends before writing handlers for it.

---

## Build and Run

```bash
cargo build --release
./target/release/apc-proxy --config proxy.yaml
```

AWS credentials are consumed via the standard AWS SDK chain: IAM role, environment variables, `~/.aws/credentials`. Set `aws.profile` in `proxy.yaml` to use a named profile.

---

## Adding a Handler

1. Create `src/handlers/<vendor>/<command>.rs`. Implement the `Handler` trait — `handle()` receives the parsed command code and payload, returns a `HandlerResult`.
2. Add the file to `src/handlers/<vendor>/mod.rs`.
3. Register an instance in `Registry::build()` in `src/handlers/mod.rs`.

The Futurex `parse_params()` helper in `src/protocol/futurex.rs` splits Excrypt payloads into a `HashMap<[u8; 2], Vec<u8>>` keyed by 2-char parameter code. The Thales protocol struct handles length-prefixed framing and response code derivation.

Sensitive fields should be wrapped in `Zeroizing<Vec<u8>>` so they are wiped from memory on drop.

---

## What This Is Not

- Not a PCI-certified cryptographic boundary
- Not a drop-in replacement for a full HSM command set
- Not a live traffic interceptor — it translates commands it has handlers for; everything else either passes through or errors

Production deployments need TLS configured, IAM scoped to least privilege, CloudTrail enabled on the APC endpoint, and review by someone who understands what the command handlers are doing cryptographically.
