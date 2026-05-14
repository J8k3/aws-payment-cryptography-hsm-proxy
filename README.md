# apc-hsm-proxy

A Rust TCP proxy that sits between HSM-dependent payment applications and [AWS Payment Cryptography (APC)](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/what-is.html). It speaks the wire protocol your application already sends — Thales payShield host commands or Futurex Excrypt — and translates them into APC API calls on the outbound side, without changing the application.

**If you are refactoring the application, use the APC SDK directly.** That is the better path: lower latency, simpler deployment, no protocol translation layer. This proxy exists for the case where refactoring is not on the table — the application is a black box, a third-party system, or the migration budget doesn't cover application changes. In that case, the proxy lets you move key management and cryptographic operations to APC while leaving the application untouched.

I spent years working on AWS Payment Cryptography. The question of how existing HSM-dependent applications could move to APC without a rewrite came up constantly. It was never something I could build while working on the service. This is that tool.

APC removes the hardware dependency, the key ceremony overhead, and the operational burden of running physical HSMs. Customers on Thales, Futurex, or Atalla who want those benefits — API-based cryptography as a service, managed key storage, no hardware to rack — now have a path that doesn't require touching application code. That lift-and-shift path is what this proxy is for.

---

## Status

**This has not been tested against a real HSM client application.** The protocol parsers are built from specification and reference documentation, not from live traffic. There are known areas of uncertainty — TLS cipher suite compatibility with older HSM SDKs, Thales length field variants across payShield versions, APC API latency vs. the sub-millisecond response times applications may expect from hardware. These are solvable problems, but they require someone with access to a real application and a real HSM to work through them.

If you use this and hit a protocol issue, a connection failure, or a handler bug, please open an issue or a PR. The core architecture is sound; the gaps are in the edge cases that only show up under real traffic.

---

## How It Works

```
Application → TCP (TLS/mTLS) → apc-proxy → AWS Payment Cryptography API
                                   │
                              proxy.yaml
                              key_mappings
                                   │
                              (no handler?)
                                   └── discovery mode: forward to real HSM
                                                        + log (redacted)
                                                        + return response
```

Commands with registered handlers are translated to APC. Commands without a handler either return an unsupported error or — when discovery mode is enabled — are forwarded transparently to a real HSM while the proxy logs the command code and non-sensitive parameters. Discovery mode is a temporary migration tool: run it between your application and a real HSM to observe what commands are actually being sent before you write handlers for them. Once handlers exist, discovery mode can be disabled.

The `key_mappings` table in `proxy.yaml` maps whatever key identifiers your application sends — a 32-char LMK-encrypted blob, a TR-31 key block value, a label — to the APC key ARN or alias. Key references that already look like ARNs or `alias/` names pass through unchanged.

Sensitive parameters are never written to logs. In discovery mode, Futurex `AX` (inbound key block), `BT` (outbound key block), and `AL` (PIN block) parameters are replaced with `[REDACTED]`. Thales payloads log only command code and payload length.

---

## Supported Protocols

**Thales payShield** (`thales_payshield`) — 2-byte command code framing. Implemented handlers: CA/CC/CI/G0 (PIN translate), C2/C4/M6/M8 (MAC generate/verify), CW/CY (CVV generate/verify), B2 (diagnostics).

**Futurex Excrypt** (`futurex_excrypt`) — `[AOCCCC;param;param;]` framing. Implemented handlers: TPIN (PIN translate).

Coverage is narrow by design. Each handler maps one HSM command to one APC data plane call. The handler registry is the extension point — add a file under `src/handlers/<vendor>/`, register it in `src/handlers/mod.rs`, and the proxy routes that command code to it.

---

## Known Risks Before You Deploy

**TLS compatibility** — The proxy uses rustls 0.23, which requires TLS 1.2 minimum. Older HSM client SDKs compiled against old OpenSSL versions may only offer TLS 1.0 or 1.1, or cipher suites rustls doesn't support. If your application fails the TLS handshake, this is the likely cause. Start without TLS (`tls:` block omitted) to rule it out.

**Latency** — Hardware HSMs respond in under a millisecond. APC API calls are network round-trips — typically 20–100ms depending on region and load. Applications with tight socket timeouts will time out. Check your application's HSM connection timeout before assuming the proxy is broken.

**Thales length field** — The 2-byte length prefix in the payShield framing may or may not include the header bytes depending on the host API version your application was written against. If commands parse incorrectly, this is the first thing to check in `src/protocol/thales.rs`.

**Session state** — The proxy is stateless per command. HSM integrations that rely on keyed sessions or sequence numbers across multiple commands will not work without extending the server to track connection state.

**Key map gaps** — Every key reference your application sends must have an entry in `key_mappings`. Missing entries cause handler failures. Discovery mode against a real HSM is the reliable way to enumerate what key references your application actually uses.

---

## Configuration

```yaml
listen:
  host: 0.0.0.0
  port: 1500
  # tls:
  #   cert_file: /etc/apc-proxy/server.crt
  #   key_file:  /etc/apc-proxy/server.key
  #   ca_file:   /etc/apc-proxy/client-ca.crt  # present = require mTLS

vendor: thales_payshield   # thales_payshield | futurex_excrypt

aws:
  region: us-east-1
  # profile: apc-proxy     # omit to use default chain: IAM role → env → instance metadata

# discover:
#   enabled: true
#   hsm_host: 192.168.1.10
#   hsm_port: 1500

key_mappings:
  ZPK_INBOUND:  arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123
  ZPK_OUTBOUND: alias/zpk-outbound
```

**FIPS** — swap the `ring` feature for `aws-lc-rs` in `Cargo.toml` and recompile. No code changes needed.

---

## Build and Run

```bash
cargo build --release
./target/release/apc-proxy --config proxy.yaml
```

AWS credentials are consumed via the standard AWS SDK chain: IAM role, environment variables, `~/.aws/credentials`. Set `aws.profile` in `proxy.yaml` to use a named profile.

---

## Adding a Handler

1. Create `src/handlers/<vendor>/<command>.rs`. Implement the `Handler` trait — `handle()` receives the parsed command code and payload bytes, returns a `HandlerResult`.
2. Add the file to `src/handlers/<vendor>/mod.rs`.
3. Register an instance in `Registry::build()` in `src/handlers/mod.rs`.

The Futurex `parse_params()` helper in `src/protocol/futurex.rs` splits Excrypt payloads into a `HashMap<[u8; 2], Vec<u8>>` keyed by 2-char parameter code. Wrap sensitive fields in `Zeroizing<Vec<u8>>` so they are wiped from memory on drop.

---

## Contributing

If you have access to a Thales payShield or Futurex KMES and can test this against a real application, that is the most valuable contribution you can make. Protocol edge cases, TLS compatibility issues, latency behavior under load, and handler correctness against real hardware are all things that cannot be validated without the equipment. Open an issue with what you found, or a PR with the fix.
