# AWS Payment Cryptography HSM Proxy

[![CI](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/actions/workflows/ci.yml)
[![Release](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/actions/workflows/release.yml/badge.svg)](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/actions/workflows/release.yml)
[![Rust](https://img.shields.io/badge/rust-stable-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Rust TCP proxy that sits between HSM-dependent payment applications and [AWS Payment Cryptography (APC)](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/what-is.html). It speaks the wire protocol your application already sends — Thales payShield 10K host commands — and translates them to APC API calls on the outbound side, without changing the application.

> **Two editions.** This repository is the **open-source core** (Apache-2.0), covering Thales payShield 10K. **APC Proxy Enterprise** is a separately licensed, commercial add-on for teams that need more — additional HSM vendors (Futurex Excrypt today; Atalla on the roadmap) and production-scale capabilities such as multi-HSM connection pooling. It is built on this exact core through a stable extension seam, so nothing is forked. See [**Enterprise edition**](#enterprise-edition).

**If you are refactoring the application, use the APC SDK directly.** That is the better path: lower latency, simpler deployment, no protocol translation layer. This proxy exists for the case where refactoring is not on the table — the application is a black box, a third-party system, or the migration budget doesn't cover application changes.

I spent years working on AWS Payment Cryptography. The question of how existing HSM-dependent applications could move to APC without a rewrite came up constantly. It was never something I could build while working on the service. This is that tool.

The standard path to cloud migration leaves payment teams with two options: refactor the application to call a cloud cryptography API directly, or move the HSM to cloud-hosted infrastructure that still speaks the same wire protocol. The first requires application changes and budget to match. The second moves the hardware dependency to a managed environment but preserves the same operational model — hardware partitions, key ceremonies, HSM-specific administration — without the cost or operational improvements that motivated the migration in the first place.

This proxy is a third path. The application keeps sending the same commands to the same address. The proxy translates them to APC on the outbound side. You get the full benefit of APC — API-native key management, no hardware to provision, no key ceremonies, substantially lower operational cost — without touching application code and without the overhead of hardware-based alternatives, managed or otherwise.

**Compliance boundary:** The cryptographic backend — AWS Payment Cryptography — is a validated PCI service: a PCI P2PE Component Provider (Decryption, Key Management, and Key Loading Components) and in scope for PCI PIN and PCI DSS, with attestations available to AWS customers through [AWS Artifact](https://aws.amazon.com/artifact/). This proxy, by contrast, is an open-source translation layer that runs **inside your compliance boundary** and is **not itself a validated component**. You are responsible for reviewing its behavior as part of your security and compliance process — validating handler implementations, key mapping correctness, and protocol fidelity against your specific application before deploying in a production cardholder data environment — and for the deployer obligations in the [threat model](docs/threat-model.md#pci-p2pe--pin-scope-if-your-deployment-is-in-scope). If you take this through a formal compliance assessment, sharing what you found — gaps, confirmations, compensating controls — via a GitHub issue or PR helps others on the same path.

---

## Status

**Validated against live APC** — 23 live integration tests exercise the implemented handlers against real AWS Payment Cryptography in `us-east-1`. Coverage: PIN translate, PIN verify (IBM 3624 + Visa PVV, DUKPT and static), MAC (ISO 9797 Alg 1/3, CMAC, HMAC, DUKPT MAC), CVV generate/verify, data encrypt/decrypt, ARQC verify, EMV issuer script MAC, plus the wrapped-key resolution path end-to-end. See [Performance](#performance) for measured latency.

**Validated end-to-end in-process** — 12 additional integration tests cover passthrough/discovery mode (forwarding to a mock HSM, redaction of the discovery log, HSM unreachable / read timeout), inbound TLS and mTLS (client cert validation, plaintext rejection, wrong-CA rejection), and outbound TLS / mTLS on the forward leg to the HSM.

**Not yet validated against a real HSM-dependent client application.** Every test in this repo is either against APC or against an in-process mock HSM. The protocol parsers are built from specification and reference documentation, not from live wire captures. Real-application validation is the most valuable thing this project needs and the hardest gap to close from the author's side alone — see [Help test this](#help-test-this).

### Test procedure

The full operator setup procedure is in [`docs/setup.md`](docs/setup.md). The live-test procedure for the integration suite is in `AGENTS.md` (§ Live APC Testing): it provisions the test key set, runs the proxy, executes the suite, captures latency, and tears the keys down.

---

## Quickstart

The shortest path from `git clone` to a working B2 heartbeat. Five minutes, no HSM required.

```sh
git clone https://github.com/J8k3/aws-payment-cryptography-hsm-proxy.git
cd aws-payment-cryptography-hsm-proxy
cargo build --release
```

Write a minimal `proxy.yaml` — no TLS, no APC keys, just the listener:

```yaml
vendor: thales_payshield
listen:
  host: 127.0.0.1
  port: 1500
aws:
  region: us-east-1
key_mappings: {}
```

(The repo's existing `proxy.yaml` is the maintainer's test rig and references ARNs you don't own — don't use it as a starting template. For real deployments, copy from `proxy.example.yaml` and follow [`docs/setup.md`](docs/setup.md).)

```sh
./target/release/apc-proxy --config proxy.yaml
```

The proxy will warn that AWS credentials are missing and that the `list_keys` scan failed — both expected without an APC account configured, and neither affects the B2 heartbeat below.

In another terminal, send a B2 heartbeat (no APC call — proxy responds locally):

```sh
# macOS / Linux: frame is [0x00 0x04][0x00 0x00]"B2"
printf '\x00\x04\x00\x00B2' | nc 127.0.0.1 1500 | xxd
```

```powershell
# Windows PowerShell — nc isn't standard:
$c = [System.Net.Sockets.TcpClient]::new('127.0.0.1', 1500)
$s = $c.GetStream(); $s.Write([byte[]](0x00,0x04,0x00,0x00,0x42,0x32), 0, 6)
$buf = New-Object byte[] 16; $n = $s.Read($buf, 0, 16)
($buf[0..($n-1)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
$c.Close()
```

Expected response: `00 06 00 00 42 33 30 30` — length `0006`, header `0000`, response code `B3` (the B2 reply), error code `00` (success).

For anything beyond a heartbeat, follow [`docs/setup.md`](docs/setup.md) — APC keys, IAM, inbound/outbound TLS, discovery, validation via `--verify-only`, cutover.

---

## How to Use This

There are two phases: **discovery** and **translation**.

### Phase 1 — Discovery

Run the proxy in passthrough mode between your application and the real HSM. The proxy forwards unhandled commands to the real HSM and returns the response, logging what it sees. The goal is to build a complete map of which commands your application actually uses before writing a single handler.

**Passthrough limitations:** The proxy opens a fresh TCP connection per forwarded command and reads a single response chunk. This is sufficient for stateless single-exchange commands but will not work correctly for multi-read responses or applications that rely on persistent connection state to the HSM. See [Known Risks](#known-risks) for details.

**Configure `proxy.yaml`** (start from `proxy.example.yaml` — the schema is fully commented there):
```yaml
vendor: thales_payshield
aws:
  region: us-east-1
discover:
  enabled: true
  hsm_host: 192.168.1.10
  hsm_port: 1500
  log_file: discovery.jsonl
  # Most production HSMs are on TLS-only host ports. Without the tls: block
  # the forward connection is plaintext and the handshake will fail:
  tls:
    ca_file: /etc/apc-proxy/hsm-ca.crt
    # mTLS — proxy presents a client cert to the HSM:
    client_cert_file: /etc/apc-proxy/proxy.crt
    client_key_file:  /etc/apc-proxy/proxy.key
```

**Point your application at the proxy instead of the HSM.** Run it through a representative set of transactions — enough to exercise every command path you care about.

**Stop the proxy.** Open `discovery.jsonl`. It contains one JSON record per unique command code your application sent:

```json
{"ts":1715688000,"vendor":"thales_payshield","cmd":"NC","params":{"payload_len":16,"note":"fields are positional and command-specific; payload not parsed in discovery mode"}}
```

Each vendor's protocol produces its own log-safe view of the payload — command codes and byte lengths only, never values. Thales payloads are positional and command-specific, so only the command code and payload length are recorded. (A parameter-tagged vendor such as Futurex, via the enterprise bolt-on, logs each parameter's 2-char code and length with the value redacted.)

**Feed `discovery.jsonl` to the [AWS Payment Cryptography MCP](https://github.com/J8k3/aws-payment-cryptography-mcp).** Call `hsm_analyze_discovery_log` with the file contents. The tool returns: which commands already have handlers in this repo, which need to be written, the APC operation and key type for each, and the exact file path and handler structure to implement. The AI writes the Rust handler code for each command you need.

### Phase 2 — Translation

Once handlers are written and registered, disable discovery mode and run the proxy in production configuration:

```yaml
vendor: thales_payshield
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

### Enterprise edition

The open-source core in this repository is **Thales payShield 10K only**, and can
be built with no other vendor compiled in. **APC Proxy Enterprise** is a
separately licensed, closed-source add-on for organizations that need more. It
depends on this core as a library and plugs in through the same stable extension
seam the built-in Thales support uses (`VendorModule`) — the core is never forked.

**Available now:**

- **Futurex Excrypt** support — its wire protocol and handlers registered as a
  `VendorModule`, running against the same APC backend as the open core.

**On the roadmap:**

- **Atalla** HSM support, added the same way.
- **Multi-HSM connection pooling** — stateless proxy instances fronting a pool of
  redundant HSMs, with health-weighted routing and a cross-transaction integrity
  contract (exclusive checkout, poison-on-anomaly, correlation-token verification)
  that the single-endpoint open core does not need.
- Priority support and integration assistance for production migrations.

The two editions are wire-compatible and share one configuration model, so a
deployment can start on the open-source core and adopt Enterprise features
without re-architecting.

**Licensing & access:** APC Proxy Enterprise is available under a commercial
license. To request access, a trial, or a quote, open an issue on this
repository or contact the maintainer via their [GitHub profile](https://github.com/J8k3).

---

Each handler maps one HSM command to one APC data-plane call. A vendor plugs in as
a `VendorModule` (its `vendor` string, framing `Protocol`, and `Handler`s); the
built-in Thales support (`ThalesModule`) is registered through the exact same seam
a bolt-on uses. See [Adding a vendor or command](#adding-a-vendor-or-command).

---

## TLS

The proxy supports TLS on both legs — inbound (application → proxy) and outbound (proxy → real HSM during passthrough). Both support mTLS.

**Inbound** — applications connecting to the proxy:

```yaml
listen:
  host: 0.0.0.0
  port: 1500
  tls:
    cert_file: /etc/apc-proxy/server.crt
    key_file:  /etc/apc-proxy/server.key
    ca_file:   /etc/apc-proxy/client-ca.crt   # present = require client cert (mTLS)
```

**Outbound** — proxy forwarding to a real HSM in discovery / passthrough mode:

```yaml
discover:
  enabled: true
  hsm_host: 192.168.1.10
  hsm_port: 1500
  tls:
    ca_file: /etc/apc-proxy/hsm-ca.crt           # required — validates HSM's server cert
    client_cert_file: /etc/apc-proxy/proxy.crt   # optional — mTLS to HSM (typical for payShield)
    client_key_file:  /etc/apc-proxy/proxy.key
    # server_name: hsm.example.local             # optional — override if HSM cert SAN doesn't match host
```

Omit `tls:` on either side for plaintext. Acceptable for local development; not for production. To use a FIPS-capable TLS backend, swap the `ring` feature for `aws-lc-rs` in `Cargo.toml` and recompile — no other code changes needed. The crypto provider is selected at compile time via the feature flag. Note: `aws-lc-rs` provides a FIPS-capable backend but FIPS mode must be enabled at build time (`AWS_LC_SYS_FIPS=1`); a full FIPS validation requires review beyond this flag.

---

## Build and Run

```bash
cargo build --release
./target/release/apc-proxy --config proxy.yaml
```

AWS credentials via the standard chain: IAM role, environment variables, `~/.aws/credentials`. Set `aws.profile` in `proxy.yaml` to use a named profile.

### Validate the config before serving

```bash
./target/release/apc-proxy --config proxy.yaml --verify-only
```

Loads the config, calls `get_key` against APC for every `key_mappings` entry, and prints a per-entry report (state, enabled, KCV, usage, algorithm). Exits 0 only if every mapping resolves to a `CREATE_COMPLETE`, enabled APC key. Also checks AWS credentials, the startup `list_keys` scan, and TLS file paths. Run this after every config edit and as part of any deployment pipeline.

---

## Adding a vendor or command

**A new command for the Thales vendor:** create `src/handlers/thales/<command>.rs`, implement the `Handler` trait (`handle()` receives the command code and payload bytes, returns `HandlerResult`), add the module to `src/handlers/thales/mod.rs`, and list the handler in `ThalesModule::handlers()`. Add the command to the Supported Commands table above.

**A new vendor:** implement `VendorModule` (its `vendor` string, framing `Protocol`, and `Handler`s) in a crate that depends on this one, then pass it to `server::run_with(cfg, vec![...])`. That is exactly how the Futurex bolt-on is built — the core needs no change.

**Thales reference:** `src/handlers/thales/cvv.rs` — handles CW/CY (CVV generate/verify), NY (static CVC3 generate), and RY (CVV2 calculate or verify) and shows the standard parse → key-map resolve → APC call → `HandlerResult` pattern. Most Thales handlers follow this structure.

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

**No-APC commands** (B2 heartbeat): sub-millisecond — no network call involved.

**Startup** adds an APC `list_keys` scan (used to populate the wrapped-key resolution index) plus AWS credential resolution; typically under 300 ms total for an account with a few dozen keys. Not on the per-command path.

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

**PAN representation in PIN translation** — Thales CA/CC commands supply 12 digits (the rightmost digits of the PAN excluding the check digit). The proxy passes this 12-digit value as `primary_account_number` to APC `TranslatePinData`. This matches the field APC uses internally to reconstruct the ISO PIN block, but it has not been verified against a live APC endpoint with real traffic. If PIN translation returns an error related to the PAN value, check whether your APC configuration expects the full PAN instead.

**Session state** — The proxy is stateless per command. HSM integrations that rely on keyed sessions or sequence numbers across multiple commands will not work without extending the server to track connection state.

**ARQC session key derivation variant** — KQ and KW use APC's `EmvCommon` session key derivation (PAN + PAN Sequence + ATC), which is correct for standard EMV and Visa CVN10/CVN14. Visa CVN17/CVN18/CVN22 use a different derivation formula (PAN + PAN Sequence only, no ATC) that requires APC's `Visa` session key derivation variant; Mastercard M/Chip SKD uses a separate derivation that requires the `Mastercard` variant with the Unpredictable Number. If your deployment uses these card types and ARQC verification returns error 01 (mismatch) for valid transactions, the session key derivation variant is the first place to investigate.

**Key map completeness** — Key references the application sends fall into two paths. Wrapped key blocks in X9.143 / TR-31 format with a `KC` optional block resolve automatically against the startup APC scan — no `key_mappings` entry needed. Label-style and variant-LMK encrypted hex references must each appear as a `key_mappings` entry. Discovery mode against a real HSM is the reliable way to enumerate the label/hex references — look for the key field in the Thales commands and confirm every non-wrapped value has a mapping. See [`docs/key-presentation.md`](docs/key-presentation.md) for the full wire-form matrix.

---

## Development Note

This project was built with AI-assisted development. AI was used to accelerate implementation, testing, documentation, and research synthesis. Architecture, scope, source selection, review, and final publish decisions were made by the author.

The protocol parsers are derived from specification and reference documentation rather than live traffic capture. Known gaps and uncertainties are documented explicitly in the [Known Risks](#known-risks) section and in inline code comments. If you have access to real HSM hardware and can validate behavior against it, that is the most valuable contribution possible — see Contributing below.

---

## Help test this

The author does not have a Thales payShield 10K on hand. Everything in this repo is tested either against AWS Payment Cryptography directly or against an in-process mock HSM. **Real-application validation is the most valuable thing this project needs** and the only way to surface the protocol edge cases the spec inference left ambiguous.

If you have access to either HSM and can try this against a real application — even a non-production one — please report what you find. Concrete asks, in priority order:

1. **Run the discovery phase** ([setup guide](docs/setup.md#phase-1-discovery)) against a representative workload from a real application and post a sanitised `discovery.jsonl`. Even just confirming "every command code we hit is in the supported list" is signal.
2. **Try a single end-to-end command** through the proxy (PIN translate or MAC generate are good first candidates) and compare the result against what the HSM returns directly. Same vector in, same answer out, or document the divergence.
3. **TLS / mTLS handshake compatibility** — older HSM SDKs vary in TLS version and cipher suite support. If the handshake fails against `rustls 0.23` defaults, note the SDK version and what it offered.
4. **Wrapped key block resolution** — if your application sends `'S'`-prefix TR-31 blocks with the `KC` optional block populated, confirm the proxy resolves them against APC correctly.
5. **Latency under load** — the `latency_us` per-command log makes this easy. A small sustained-rate test would help calibrate the cold-start and steady-state numbers in [Performance](#performance).

### Filing reports

| What you found | Issue label | What to include |
|---|---|---|
| Worked end-to-end against real HSM | `needs-hsm-validation` | HSM model + firmware, application name (sanitised), commands exercised, anything surprising |
| Protocol parse error or response misframing | `protocol-edge-case` | The wire frame bytes (sanitised), expected response, what the proxy returned, payShield firmware version |
| TLS handshake fails | `tls-compat` | Client TLS version + cipher suites, cert key type, the rustls error from the proxy log |
| Wrong APC behavior or unexpected error 41 | `apc-behavior` | The handler that ran, the wire frame, the APC error in the proxy log |

If you take this through a formal compliance assessment, sharing what you found — gaps, confirmations, compensating controls — via a GitHub issue or PR helps others on the same path.

Bug fixes, handler implementations for currently-unsupported commands (see [`src/handlers/noop.rs`](src/handlers/noop.rs) for the "deliberately not implemented" list and the [open issues](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues) for "wanted"), documentation improvements, and additional tests are all welcome via PR.
