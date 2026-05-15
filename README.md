# apc-hsm-proxy

**GitHub:** [github.com/J8k3/aws-payment-cryptography-hsm-proxy](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy)

A Rust TCP proxy that sits between HSM-dependent payment applications and [AWS Payment Cryptography (APC)](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/what-is.html). It speaks the wire protocol your application already sends — Thales payShield 10K host commands or Futurex Excrypt Enterprise SSP v.2 — and translates them to APC API calls on the outbound side, without changing the application.

**If you are refactoring the application, use the APC SDK directly.** That is the better path: lower latency, simpler deployment, no protocol translation layer. This proxy exists for the case where refactoring is not on the table — the application is a black box, a third-party system, or the migration budget doesn't cover application changes.

I spent years working on AWS Payment Cryptography. The question of how existing HSM-dependent applications could move to APC without a rewrite came up constantly. It was never something I could build while working on the service. This is that tool.

APC removes the hardware dependency, the key ceremony overhead, and the operational burden of running physical HSMs. Customers on Thales, Futurex, or Atalla who want those benefits — API-based cryptography as a service, managed key storage, no hardware to rack — now have a path that doesn't require touching application code. That lift-and-shift path is what this proxy is for.

---

## Status

**This has not been tested against a real HSM client application.** The protocol parsers are built from specification and reference documentation, not from live traffic. There are known areas of uncertainty covered in the [Known Risks](#known-risks) section below. If you use this against a real application and hit a protocol issue, open an issue or PR. The core architecture is sound; the gaps are in edge cases that only surface under real traffic.

---

## How to Use This

There are two phases: **discovery** and **translation**.

### Phase 1 — Discovery

Run the proxy in passthrough mode between your application and the real HSM. The proxy forwards unhandled commands to the real HSM and returns the response, logging what it sees. The goal is to build a complete map of which commands your application actually uses before writing a single handler.

**Passthrough limitations:** The proxy opens a fresh TCP connection per forwarded command and reads a single response chunk. This is sufficient for stateless single-exchange commands but will not work correctly for multi-read responses or applications that rely on persistent connection state to the HSM. See [Known Risks](#known-risks) for details.

**Configure `proxy.yaml`:**
```yaml
vendor: futurex_excrypt    # or thales_payshield
discover:
  enabled: true
  hsm_host: 192.168.1.10  # your real HSM
  hsm_port: 1500
  log_file: discovery.jsonl
```

**Point your application at the proxy instead of the HSM.** Run it through a representative set of transactions — enough to exercise every command path you care about.

**Stop the proxy.** Open `discovery.jsonl`. It contains one JSON record per unique command code your application sent:

```json
{"ts":1715688000,"vendor":"futurex_excrypt","cmd":"TPIN","params":{"AW":"3","AK":"1234567890","AX":"[REDACTED]","BT":"[REDACTED]","AL":"[REDACTED]"}}
{"ts":1715688001,"vendor":"futurex_excrypt","cmd":"GKEY","params":{"BC":"01","AK":"9876543210"}}
```

For Futurex commands, parameters are parsed and logged by name. Key blocks (`AX`, `BT`) and PIN blocks (`AL`) are replaced with `[REDACTED]`; all other parameter names and values are preserved. For Thales commands, only the command code and payload length are logged — Thales payloads are positional and command-specific, so field-level parsing is not attempted in discovery mode.

**Feed `discovery.jsonl` to the [AWS Payment Cryptography MCP](https://github.com/J8k3/aws-payment-cryptography-mcp).** Call `hsm_analyze_discovery_log` with the file contents. The tool returns: which commands already have handlers in this repo, which need to be written, the APC operation and key type for each, and the exact file path and handler structure to implement. Claude writes the Rust handler code for each command you need.

### Phase 2 — Translation

Once handlers are written and registered, disable discovery mode and run the proxy in production configuration:

```yaml
vendor: futurex_excrypt
aws:
  region: us-east-1
listen:
  host: 0.0.0.0
  port: 1500
  # tls:              — add for production; see TLS section below
  #   cert_file: ...
  #   key_file:  ...
key_mappings:
  ZPK_INBOUND:  arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123
  ZPK_OUTBOUND: alias/zpk-outbound
  BDK_TERMINAL: arn:aws:payment-cryptography:us-east-1:123456789012:key/ghi789
```

Commands with registered handlers are translated to APC. Commands without a handler return error 68 (unsupported). The `key_mappings` table resolves whatever key identifiers your application sends — LMK-encrypted blobs, TR-31 key block values, labels — to the APC key ARN or alias before making the API call.

---

## Supported Protocols

**Thales payShield 10K** (`thales_payshield`) — 2-byte length prefix + 2-byte command code framing. Implemented handlers: CA/CC/CI/G0 (PIN translate), C2/C4/M6/M8 (MAC generate/verify), CW/CY (CVV generate/verify), B2 (diagnostics).

**Futurex Excrypt Enterprise SSP v.2** (`futurex_excrypt`) — `[AOCCCC;param;param;]` bracket-delimited framing. Implemented handlers: TPIN (PIN translate).

Coverage is intentionally narrow. Each handler maps one HSM command to one APC data plane call. The handler registry is the extension point — add a file under `src/handlers/<vendor>/`, register it in `src/handlers/mod.rs`, and the proxy routes that command to it.

---

## TLS

HSM connections in production use TLS, often mTLS. Configure it under the `listen:` block:

```yaml
listen:
  host: 0.0.0.0
  port: 1500
  tls:
    cert_file: /etc/apc-proxy/server.crt
    key_file:  /etc/apc-proxy/server.key
    ca_file:   /etc/apc-proxy/client-ca.crt   # present = require client cert (mTLS)
```

Omit `tls:` for plaintext. Acceptable for local development; not for production. For FIPS-compliant TLS, swap the `ring` feature for `aws-lc-rs` in `Cargo.toml` and recompile — no other code changes needed. The crypto provider is selected at compile time via the feature flag.

---

## Build and Run

```bash
cargo build --release
./target/release/apc-proxy --config proxy.yaml
```

AWS credentials via the standard chain: IAM role, environment variables, `~/.aws/credentials`. Set `aws.profile` in `proxy.yaml` to use a named profile.

---

## Adding a Handler

1. Create `src/handlers/<vendor>/<command>.rs`. Implement the `Handler` trait — `handle()` receives the command code and payload bytes, returns `HandlerResult`.
2. Add the module to `src/handlers/<vendor>/mod.rs`.
3. Register an instance in `Registry::build()` in `src/handlers/mod.rs`.

The Futurex `parse_params()` helper (`src/protocol/futurex.rs`) splits Excrypt payloads into a `HashMap<[u8; 2], Vec<u8>>` keyed by 2-char parameter code. Wrap sensitive fields (key blocks, PIN blocks) in `Zeroizing<Vec<u8>>` so they are wiped from memory on drop. Look at `src/handlers/futurex/tpin.rs` as the reference implementation.

---

## Known Risks

**TLS cipher compatibility** — The proxy requires TLS 1.2 minimum (rustls 0.23). Older HSM client SDKs built against old OpenSSL may only offer TLS 1.0/1.1 or unsupported cipher suites. If the TLS handshake fails, omit the `tls:` block first to rule this out, then investigate the client's TLS version and cipher support.

**APC latency** — Hardware HSMs respond in under a millisecond. APC API calls are network round-trips — typically 20–100ms. Applications with tight socket timeouts will time out. Check the application's HSM connection timeout before assuming the proxy is broken.

**Thales length field variants** — The 2-byte length prefix may or may not include the header bytes depending on which payShield host API version the application was built against. If commands parse incorrectly, check the length calculation in `src/protocol/thales.rs`.

**Discovery passthrough is single-chunk** — In discovery mode, the proxy opens a fresh TCP connection per forwarded command and reads exactly one response chunk. Stateful protocols, multi-read responses, and commands that require connection continuity will not work correctly in discovery mode. For complex command sequences, capture them with a network sniffer instead.

**PAN representation in PIN translation** — Thales CA/CC commands supply 12 digits (the rightmost digits of the PAN excluding the check digit). Futurex TPIN supplies the same via the `AK` parameter. The proxy passes this 12-digit value as `primary_account_number` to APC `TranslatePinData`. This matches the field APC uses internally to reconstruct the ISO PIN block, but it has not been verified against a live APC endpoint with real traffic. If PIN translation returns an error related to the PAN value, check whether your APC configuration expects the full PAN instead.

**Session state** — The proxy is stateless per command. HSM integrations that rely on keyed sessions or sequence numbers across multiple commands will not work without extending the server to track connection state.

**Key map completeness** — Every key reference the application sends must appear in `key_mappings`. Discovery mode against a real HSM is the reliable way to enumerate them — look for parameter codes that carry key material (`AX`, `BT` in Futurex; the key field in Thales commands) and make sure each value has a mapping.

---

## Contributing

If you have access to a Thales payShield 10K or Futurex Excrypt Enterprise SSP v.2 and can test this against a real application, that is the most valuable contribution possible. Protocol edge cases, TLS compatibility, latency behavior, and handler correctness against real hardware can't be validated without the equipment. Open an issue with what you found or a PR with the fix.
