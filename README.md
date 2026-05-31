# AWS Payment Cryptography HSM Proxy

[![CI](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/actions/workflows/ci.yml)
[![Release](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/actions/workflows/release.yml/badge.svg)](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/actions/workflows/release.yml)
[![Rust](https://img.shields.io/badge/rust-stable-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Rust TCP proxy that sits between HSM-dependent payment applications and [AWS Payment Cryptography (APC)](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/what-is.html). It speaks the wire protocol your application already sends — Thales payShield 10K host commands or Futurex Excrypt Enterprise SSP v.2 — and translates them to APC API calls on the outbound side, without changing the application.

**If you are refactoring the application, use the APC SDK directly.** That is the better path: lower latency, simpler deployment, no protocol translation layer. This proxy exists for the case where refactoring is not on the table — the application is a black box, a third-party system, or the migration budget doesn't cover application changes.

I spent years working on AWS Payment Cryptography. The question of how existing HSM-dependent applications could move to APC without a rewrite came up constantly. It was never something I could build while working on the service. This is that tool.

The standard path to cloud migration leaves payment teams with two options: refactor the application to call a cloud cryptography API directly, or move the HSM to cloud-hosted infrastructure that still speaks the same wire protocol. The first requires application changes and budget to match. The second moves the hardware dependency to a managed environment but preserves the same operational model — hardware partitions, key ceremonies, HSM-specific administration — without the cost or operational improvements that motivated the migration in the first place.

This proxy is a third path. The application keeps sending the same commands to the same address. The proxy translates them to APC on the outbound side. You get the full benefit of APC — API-native key management, no hardware to provision, no key ceremonies, substantially lower operational cost — without touching application code and without the overhead of hardware-based alternatives, managed or otherwise.

**Compliance boundary:** This proxy operates inside your existing PCI compliance boundary. You are responsible for reviewing its behavior as part of your security and compliance process — validating handler implementations, key mapping correctness, and protocol fidelity against your specific application before deploying in a production cardholder data environment. If you take this through a formal compliance assessment, sharing what you found — gaps, confirmations, compensating controls — via a GitHub issue or PR helps others on the same path.

---

## Status

**APC integration tested live (2026-05-30, us-east-1).** The proxy was run against real AWS Payment Cryptography keys. MA→MC (MAC generate + verify, ISO 9797 Alg 1) and HE→HG (data encrypt + decrypt, TDES ECB) completed end-to-end at the wire-frame level — raw Thales frames in, APC round-trip, correct response framing out. See [Performance](#performance) for measured latency.

**Not yet tested against a real HSM client application.** The protocol parsers are built from specification and reference documentation, not from live traffic. There are known areas of uncertainty covered in the [Known Risks](#known-risks) section below. If you use this against a real application and hit a protocol issue, open an issue or PR. The core architecture is sound; the gaps are in edge cases that only surface under real traffic.

### Test procedure

The live test procedure is documented in `AGENTS.md` (§ Live APC Testing) and is repeatable: it provisions the minimum key set, runs the proxy, executes the integration suite, captures latency, and deletes the keys. The two integration tests that exercise real APC are `thales_ma_mc_roundtrip_live` and `thales_he_hg_roundtrip_live` in `tests/integration.rs`.

---

## How to Use This

There are two phases: **discovery** and **translation**.

### Phase 1 — Discovery

Run the proxy in passthrough mode between your application and the real HSM. The proxy forwards unhandled commands to the real HSM and returns the response, logging what it sees. The goal is to build a complete map of which commands your application actually uses before writing a single handler.

**Passthrough limitations:** The proxy opens a fresh TCP connection per forwarded command and reads a single response chunk. This is sufficient for stateless single-exchange commands but will not work correctly for multi-read responses or applications that rely on persistent connection state to the HSM. See [Known Risks](#known-risks) for details.

**Configure `proxy.yaml`:**
```yaml
vendor: futurex_excrypt    # or thales_payshield
aws:
  region: us-east-1
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

**Feed `discovery.jsonl` to the [AWS Payment Cryptography MCP](https://github.com/J8k3/aws-payment-cryptography-mcp).** Call `hsm_analyze_discovery_log` with the file contents. The tool returns: which commands already have handlers in this repo, which need to be written, the APC operation and key type for each, and the exact file path and handler structure to implement. The AI writes the Rust handler code for each command you need.

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

### Wire-format key support

The proxy resolves keys via two paths: operator-provided `key_mappings` for label / variant-LMK / fixed-width references, and an automatic startup APC scan keyed on `(KeyUsage, KeyAlgorithm, KCV)` for X9.143 / TR-31 wrapped key blocks that carry a `KC` optional block. Wrapped-block resolution requires the corresponding key to be already imported into APC. Several legacy Thales commands (CA / CC / BQ / CI / G0 / C2 / C4 / CW / CY / QY / PM) have fixed-width key fields per the wire spec and do not accept the `'S'` prefix — applications needing wrapped keys for MAC should target M6 / M8.

Full matrix — which wire forms work, which don't, and why — is in [`docs/key-presentation.md`](docs/key-presentation.md). Operators choosing between the proxy and a refactor should read it before settling on a deployment plan.

---

## Supported Commands

### Thales payShield 10K (`thales_payshield`)

Wire framing: `[2B length][2B header][2B command code][payload]` — length counts every byte that follows it (header + command + payload).

| Commands | Function | APC Operation |
|----------|----------|---------------|
| CA CC BQ CI G0 | PIN translate (ZPK/TPK/PEK, DUKPT) | `TranslatePinData` |
| DA DC EA EC | PIN verify — non-DUKPT (IBM 3624 and Visa PVV) | `VerifyPinData` |
| CK CM | PIN verify — DUKPT 3DES single-length (IBM 3624 and Visa PVV) | `VerifyPinData` |
| GO GQ | PIN verify — DUKPT 3DES/AES (IBM 3624 and Visa PVV) | `VerifyPinData` |
| CU DU | PIN change — verify current + generate new verification datum (Visa PVV / IBM offset) | `VerifyPinData` + `GeneratePinData` |
| GA CE | PIN generate / offset — Diebold method | `GeneratePinData` |
| JA | Random PIN generate — IBM 3624 | `GeneratePinData` |
| CW CY | CVV generate / verify (CVV1, CVV2, iCVV) | `GenerateCardValidationData` / `VerifyCardValidationData` |
| NY | Static CVC3 and IVCVC3 generate (Mastercard contactless) | `GenerateCardValidationData` |
| RY | CVV2 / CVC2 calculate or verify | `GenerateCardValidationData` / `VerifyCardValidationData` |
| QY PM | Dynamic CVV (dCVV) generate / verify | `GenerateCardValidationData` / `VerifyCardValidationData` |
| M6 M8 | MAC generate / verify | `GenerateMac` / `VerifyMac` |
| C2 C4 | AS2805 MAC generate / verify | `GenerateMac` / `VerifyMac` |
| MY | MAC verify and translate (re-key) | `VerifyMac` → `GenerateMac` |
| MA MC ME | Legacy TAK MAC generate / verify / translate (ANSI X9.9) | `GenerateMac` / `VerifyMac` |
| MK MM MO | Legacy binary MAC generate / verify / translate (ISO9797 Alg1) | `GenerateMac` / `VerifyMac` |
| MU MW | Legacy binary MAC generate / verify with mode (ISO9797 Alg1) | `GenerateMac` / `VerifyMac` |
| MQ | Legacy binary MAC generate — ZAK key (ISO9797 Alg1) | `GenerateMac` |
| MS | Legacy binary MAC generate — ANSI X9.19 / Retail MAC | `GenerateMac` |
| LQ LS | HMAC generate / verify (SHA-1/256/384/512) | `GenerateMac` / `VerifyMac` |
| JU KU KY | EMV issuer script MAC — integrity only, mode 0 | `GenerateMac` |
| GW | DUKPT MAC generate / verify (3DES & AES) | `GenerateMac` / `VerifyMac` |
| M0 M2 M4 | Data encrypt / decrypt / translate | `EncryptData` / `DecryptData` / `ReEncryptData` |
| HE HG | Legacy TAK encrypt / decrypt | `EncryptData` / `DecryptData` |
| K0 | EMV counter / application data decrypt | `DecryptData` |
| KQ | ARQC verify + ARPC generate (Visa/Amex + Mastercard, standard EMV) | `VerifyAuthRequestCryptogram` |
| K2 | ARQC verify — Mastercard CAP / Dynamic CAP | `VerifyAuthRequestCryptogram` |
| KS | ARQC verify — EMV2000 dynamic data authentication | `VerifyAuthRequestCryptogram` |
| KW | ARQC verify + ARPC generate (Visa CVN14/CVN18/CVN22 + Mastercard M/Chip SKD) | `VerifyAuthRequestCryptogram` |
| JS | ARQC verify + ARPC generate (UnionPay / CUP) | `VerifyAuthRequestCryptogram` |
| B2 | Heartbeat / diagnostics | Echo response |

### Futurex Excrypt Enterprise SSP v.2 (`futurex_excrypt`)

Wire framing: `[AOCCCC;param;param;]` bracket-delimited with 2-byte parameter codes.

| Commands | Function | APC Operation |
|----------|----------|---------------|
| ECHO | Connectivity heartbeat | Echo response |
| TPIN | PIN translate | `TranslatePinData` |

### Atalla / NCR Payments

Not currently supported. The companion [AWS Payment Cryptography MCP](https://github.com/J8k3/aws-payment-cryptography-mcp) includes Atalla command mappings at directory quality (names and APC equivalents; no parameter detail), but no protocol framing or handlers exist in this proxy. If you have access to Atalla hardware and documentation and want to contribute, the handler registry is the extension point.

---

Each handler maps one HSM command to one APC data plane call. The handler registry is the extension point — add a file under `src/handlers/<vendor>/`, register it in `src/handlers/mod.rs`, and the proxy routes that command to it.

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

Omit `tls:` for plaintext. Acceptable for local development; not for production. To use a FIPS-capable TLS backend, swap the `ring` feature for `aws-lc-rs` in `Cargo.toml` and recompile — no other code changes needed. The crypto provider is selected at compile time via the feature flag. Note: `aws-lc-rs` provides a FIPS-capable backend but FIPS mode must be enabled at build time (`AWS_LC_SYS_FIPS=1`); a full FIPS validation requires review beyond this flag.

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
4. Add the command to the Supported Commands table above.

**Thales reference:** `src/handlers/thales/cvv.rs` — handles CW/CY (CVV generate/verify), NY (static CVC3 generate), and RY (CVV2 calculate or verify) and shows the standard parse → key-map resolve → APC call → `HandlerResult` pattern. Most Thales handlers follow this structure.

**Futurex reference:** `src/handlers/futurex/tpin.rs` — uses `parse_params()` from `src/protocol/futurex.rs` to split the Excrypt `[AOCCCC;param;param;]` payload into a `HashMap<[u8; 2], Vec<u8>>` keyed by 2-char parameter code.

Wrap sensitive fields (key blocks, PIN blocks) in `Zeroizing<String>` or `Zeroizing<Vec<u8>>` so they are wiped from memory on drop. After implementing, run `cargo clippy -- -D warnings` and `cargo test` — both must pass before committing.

---

## Performance

Measured on 2026-05-30, us-east-1, proxy co-located with the calling process (loopback), AWS credentials via default profile.

| Command | Scenario | `latency_us` |
|---------|----------|-------------|
| B2 (heartbeat) | No APC call — proxy responds locally | 1,359 µs (~1 ms) |
| HE (data encrypt) | First call — HTTPS connection establishment | 341,029 µs (~341 ms) |
| HG (data decrypt) | Subsequent call — connection reused | 20,216 µs (~20 ms) |
| MA (MAC generate) | First call — concurrent with HE above | 401,551 µs (~402 ms) |
| MC (MAC verify) | Subsequent call — connection reused | 12,746 µs (~13 ms) |

**Cold start:** The first APC call establishes an HTTPS connection to the APC endpoint. Expect 300–400 ms for the first call per proxy instance. Connection reuse applies to subsequent calls on the same underlying HTTP/2 transport.

**Steady state:** 13–20 ms per APC operation at same-region loopback latency. Cross-region deployments or higher network latency will add the round-trip delta. Applications with socket timeouts under 500 ms should extend them to at least 2 seconds to absorb both cold start and APC latency variance.

**No-APC commands** (B2 heartbeat, future passthrough in discovery mode): sub-millisecond — no network call involved.

The `latency_us` field is logged for every handled command:

```
INFO apc_proxy::server: command handled cmd=MA error_code=00 latency_us=401551
INFO apc_proxy::server: command handled cmd=MC error_code=00 latency_us=12746
```

This is wall-clock time from completed frame parse to response encoding — i.e., APC round-trip plus proxy encoding overhead.

---

## Known Risks

**TLS cipher compatibility** — The proxy requires TLS 1.2 minimum (rustls 0.23). Older HSM client SDKs built against old OpenSSL may only offer TLS 1.0/1.1 or unsupported cipher suites. If the TLS handshake fails, omit the `tls:` block first to rule this out, then investigate the client's TLS version and cipher support. Certificate key type also matters: some HSM configurations restrict cipher suites in ways that require an ECDSA cert rather than RSA, or vice versa — this is a function of the HSM's TLS policy and varies by device configuration. If the handshake fails after ruling out TLS version, verify that the cert/key pair in `proxy.yaml` matches the key type the connecting client expects.

**APC latency** — Hardware HSMs respond in under a millisecond. APC API calls are network round-trips — 13–20 ms at steady state, 300–400 ms on first call (HTTPS connection establishment). See [Performance](#performance) for measured values. Applications with tight socket timeouts will time out; extend HSM connection timeouts to at least 2 seconds before assuming the proxy is broken.

**Thales length field variant** — The proxy implements the standard payShield 10K framing where the 2-byte big-endian length prefix counts every byte that follows it — header (2 bytes) + command code (2 bytes) + payload. Some older payShield host API versions count only the payload, excluding the header. If commands parse incorrectly or responses are misframed, that is the first place to look: compare the value in `src/protocol/thales.rs` against the length field definition in your payShield Host Programmer's Guide.

**Discovery passthrough is stateless** — In discovery mode, the proxy opens a fresh TCP connection per forwarded command, sends the frame, and reads until the response is complete (per the protocol's length/framing check). There is no connection state between commands. Stateful protocols and commands that require persistent connection state across multiple exchanges will not work correctly in discovery mode. For complex command sequences, capture them with a network sniffer instead.

**PAN representation in PIN translation** — Thales CA/CC commands supply 12 digits (the rightmost digits of the PAN excluding the check digit). Futurex TPIN supplies the same via the `AK` parameter. The proxy passes this 12-digit value as `primary_account_number` to APC `TranslatePinData`. This matches the field APC uses internally to reconstruct the ISO PIN block, but it has not been verified against a live APC endpoint with real traffic. If PIN translation returns an error related to the PAN value, check whether your APC configuration expects the full PAN instead.

**Futurex error codes** — When the proxy returns an error on a Futurex connection (key not found, malformed payload, APC failure), the `BB` status field carries a payShield-style error code (10, 15, 23, 41) rather than a Futurex-native code. These values are not defined in the Futurex Excrypt protocol. Most applications treat any non-`Y` status as failure and log the raw value, so this usually does not cause incorrect behavior — but an application that pattern-matches on specific `BB` codes will not recognize them as expected Futurex error codes.

**Session state** — The proxy is stateless per command. HSM integrations that rely on keyed sessions or sequence numbers across multiple commands will not work without extending the server to track connection state.

**ARQC session key derivation variant** — KQ and KW use APC's `EmvCommon` session key derivation (PAN + PAN Sequence + ATC), which is correct for standard EMV and Visa CVN10/CVN14. Visa CVN17/CVN18/CVN22 use a different derivation formula (PAN + PAN Sequence only, no ATC) that requires APC's `Visa` session key derivation variant; Mastercard M/Chip SKD uses a separate derivation that requires the `Mastercard` variant with the Unpredictable Number. If your deployment uses these card types and ARQC verification returns error 01 (mismatch) for valid transactions, the session key derivation variant is the first place to investigate.

**Key map completeness** — Every key reference the application sends must appear in `key_mappings`. Discovery mode against a real HSM is the reliable way to enumerate them — look for parameter codes that carry key material (`AX`, `BT` in Futurex; the key field in Thales commands) and make sure each value has a mapping.

---

## Development Note

This project was built with AI-assisted development. AI was used to accelerate implementation, testing, documentation, and research synthesis. Architecture, scope, source selection, review, and final publish decisions were made by the author.

The protocol parsers are derived from specification and reference documentation rather than live traffic capture. Known gaps and uncertainties are documented explicitly in the [Known Risks](#known-risks) section and in inline code comments. If you have access to real HSM hardware and can validate behavior against it, that is the most valuable contribution possible — see Contributing below.

---

## Contributing

If you have access to a Thales payShield 10K or Futurex Excrypt Enterprise SSP v.2 and can test this against a real application, that is the most valuable contribution possible. Protocol edge cases, TLS compatibility, latency behavior, and handler correctness against real hardware can't be validated without the equipment. Open an issue with what you found or a PR with the fix.
