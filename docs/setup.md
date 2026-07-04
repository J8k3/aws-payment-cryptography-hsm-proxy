# Operator Setup Guide

End-to-end procedure to deploy `apc-proxy` between an existing HSM-dependent payment application and AWS Payment Cryptography (APC).

This guide assumes you already understand why you're doing this — your application can't be refactored to call APC directly, and you want to keep the same wire protocol while moving the cryptographic backend to APC. See the [README](../README.md) for the broader rationale.

> **Status reminder.** This proxy has been validated against live APC but **not yet against a real HSM-dependent client application in production.** The protocol parsers are built from specification, not live traffic. Until that gap is closed, deploy in staging first and report what you find. See "Help test this" in the README.

---

## Prerequisites

- AWS account with APC enabled in the target region (any APC region works; `us-east-1` is the default in the example config)
- IAM identity for the proxy — **prefer an IAM role** (EC2 instance profile, ECS task role, EKS service account). Long-lived access keys work but the proxy logs a warning at startup
- Rust toolchain to build (or use the release binary when one is published)
- Network reachability from the proxy host to APC (TLS 443 outbound)
- Source HSM with administrative access — needed to inventory keys and export them for migration. **Test environment only** for an initial rollout; production keys come later

### IAM policy

The minimum permissions for serve mode:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "payment-cryptography:ListKeys",
        "payment-cryptography:GetKey",
        "payment-cryptography-data:*"
      ],
      "Resource": "*"
    }
  ]
}
```

`ListKeys` and `GetKey` are control-plane calls used at startup (key inventory scan for wrapped-key resolution; `--verify-only` config check). Everything at request time is data-plane.

For `--verify-only` mode the same policy applies.

For key import scripts (`scripts/import_test_keys.py`) add `payment-cryptography:ImportKey`, `payment-cryptography:CreateKey`, `payment-cryptography:GetParametersForImport`, and `payment-cryptography:DeleteKey`.

---

## Phase 1: Discovery

If you already know exactly which HSM commands your application uses, skip to Phase 2. Otherwise run the proxy in passthrough mode to capture them.

### Configure passthrough

```yaml
# proxy-discover.yaml
vendor: thales_payshield   # or futurex_excrypt
listen:
  host: 0.0.0.0
  port: 1500
aws:
  region: us-east-1
key_mappings: {}            # empty during discovery — everything passes through
discover:
  enabled: true
  hsm_host: 192.168.1.10    # your real HSM
  hsm_port: 1500
  log_file: discovery.jsonl
  # If the HSM requires TLS on its host port (most production payShield does):
  # tls:
  #   ca_file: /etc/apc-proxy/hsm-ca.crt
  #   client_cert_file: /etc/apc-proxy/proxy-client.crt   # if HSM requires mTLS
  #   client_key_file:  /etc/apc-proxy/proxy-client.key
```

### Point your application at the proxy

Update the application's HSM endpoint from the real HSM's address to the proxy's. Run a representative set of transactions — enough to exercise every command path you care about.

### Read `discovery.jsonl`

One NDJSON record per **unique** command code. For Futurex, parameters are parsed and sensitive values (`AL`, `AX`, `BT`) are masked. For Thales the wire format is positional and command-specific, so only the command code and payload length are recorded.

```jsonl
{"ts":1717200000,"vendor":"futurex_excrypt","cmd":"TPIN","params":{"AW":"3","AK":"1234567890","AX":"[REDACTED]","BT":"[REDACTED]","AL":"[REDACTED]"}}
{"ts":1717200001,"vendor":"futurex_excrypt","cmd":"GKEY","params":{"BC":"01","AK":"9876543210"}}
```

### Decide which commands you need handlers for

Cross-reference against the [supported commands matrix](../README.md#supported-commands) in the README. Anything not already implemented becomes a gap — file an issue, contribute a handler, or feed `discovery.jsonl` to the [AWS Payment Cryptography MCP](https://github.com/J8k3/aws-payment-cryptography-mcp) (`hsm_analyze_discovery_log`) to scope the work.

---

## Phase 2: Key inventory

Before importing anything, build a spreadsheet of every key your application uses with the following columns:

| Source label/slot | Key type (TR-31) | Algorithm | KCV | Migration target |

### payShield

Host command `BU` ("Generate a Key Check Value", response `BV`, PUGD0537-004) returns the KCV for a key given the LMK-encrypted key material — the same hex your application presents on the wire and that you put in `key_mappings`. The legacy `KA` (PUGD0538) does the same for a narrower key-type set; its own spec marks it superseded by `BU`, and it is disabled under the PCI-HSM key-type-separation setting. There is no slot-enumeration command on payShield — the operator walks their own key list.

`--verify-only` automates exactly this check when `discover.hsm_host` is configured — see Phase 5.

### Futurex

Futurex documents `GPKR` ("General Purpose Key settings get, read only") in its command permission lists, and slot enumeration is expected to pair it with `KMAP` — but the wire field layout of both commands is not published anywhere this project can verify against. Until a capture from a real unit or the Excrypt command reference grounds them, build the inventory from Excrypt Manager / your key ceremony records instead. Automating this is [#13](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues/13).

### Migration target per key

For each key, decide:

- **Keep on HSM (variant LMK or TKB without KC optional block)** — proxy resolves it through operator-pinned `key_mappings`. Nothing imported; the proxy is just translating commands.
- **Migrate to APC (most cases)** — import the key into APC. Subsequent traffic uses the APC key by ARN.
- **Retire** — the application has it configured but doesn't actually use it. Discovery in Phase 1 will tell you.

---

## Phase 3: Import to APC

For known-material test keys (not production keys), `scripts/import_test_keys.py` is a working reference. For production keys use TR-34 (preferred for bulk) or TR-31. See the [MCP key migration KB entry](https://github.com/J8k3/aws-payment-cryptography-mcp/issues/11) for the detailed playbook.

### Key strength rule (important)

APC rejects RSA-wrapped imports where the wrapping key strength is below the working key strength:

- AES_128 → can wrap with RSA_2048 or larger
- AES_192 → needs RSA_3072 or larger
- AES_256 → **cannot be wrapped with KEY_CRYPTOGRAM** at any RSA size APC offers. Use TR-34 or `CreateKey`.

### Aliases vs ARNs

For each imported key, create a stable APC alias (`alias/zpk-inbound`, `alias/livemac-001`, etc.). Put the alias in `key_mappings` rather than the raw ARN — re-imports get new ARNs but the alias can be retargeted without touching `proxy.yaml`.

### Verify the imported KCV

After import, call `get_key` on the new ARN and confirm the KCV matches what you recorded in Phase 2. KCV mismatch means you imported wrong bytes.

---

## Phase 4: Write `proxy.yaml`

```yaml
vendor: thales_payshield
listen:
  host: 0.0.0.0
  port: 1500
  tls:
    cert_file: /etc/apc-proxy/server.crt
    key_file:  /etc/apc-proxy/server.key
    # For mTLS (the standard production deployment shape):
    # ca_file: /etc/apc-proxy/client-ca.crt

aws:
  region: us-east-1
  # profile: my-profile   # optional; default chain otherwise

key_mappings:
  # ASCII labels (16-char or 32-char, fixed by the wire spec for each command)
  # → APC aliases (preferred) or ARNs
  ZPK_INBOUND:        alias/zpk-inbound
  ZPK_OUTBOUND:       alias/zpk-outbound
  LIVETEST_MAC_001:   alias/live-mac-001
  # ...one line per label/key your application sends

# Discovery / passthrough — disable in production once handlers cover every
# command your application uses, or keep enabled to forward the long tail.
# discover:
#   enabled: true
#   hsm_host: 192.168.1.10
#   hsm_port: 1500
#   tls: ...
#   log_file: /var/log/apc-proxy/discovery.jsonl
#   hsm_read_timeout_secs: 30
```

### Wire-form-to-key-format quick reference

See [docs/key-presentation.md](key-presentation.md) for the full matrix. Short version:

- **TR-31 / X9.143 wrapped block with KC optional block** — automatic. No `key_mappings` entry needed. Proxy's startup scan resolves it by `(KeyUsage, Algorithm, KCV)`.
- **Variant LMK encrypted hex** — add a `key_mappings` entry with the exact hex string as the key.
- **ASCII label** — add a `key_mappings` entry with the label string as the key.
- **TKB without KC, AKB, Futurex cryptogram** — not currently auto-resolved; pin in `key_mappings` if supported at all.

---

## Phase 5: Validate

```sh
apc-proxy --config proxy.yaml --verify-only
```

What it checks:

- AWS credentials resolve
- `list_keys` scan succeeds (the same scan the proxy runs at startup for wrapped-key resolution)
- Every `key_mappings` entry resolves to a `CREATE_COMPLETE`, enabled APC key. Reports KCV / usage / algorithm per entry.
- **HSM-side KCV cross-check** (Thales, when `discover.hsm_host` is configured): asks the source HSM for the KCV of each LMK-encrypted mapping key (`BU` over the same TLS config as the forward leg) and compares it to APC's KCV. This catches the case a clean APC inventory cannot: a mapping that points at a *valid* APC key holding *different* clear material than the HSM key the application actually uses. Key mismatch is a `FAIL`; an unreachable HSM degrades to a single warning and the APC-side checks still run. Futurex is not yet covered (see Phase 2 note on `GPKR`).
- TLS file paths exist (parse happens at startup)
- mTLS config is internally consistent (client cert + key paired)
- Warns if inbound TLS is missing (plaintext listener) or if `discover.enabled=true` without `discover.tls` (plaintext forward leg)

Sample output:

```
apc-proxy verify-only against us-east-1
─────────────────────────────────────────────────────────────
  ok    AWS credentials resolved
  ok    APC list_keys scan succeeded
  ok    HSM-side KCV cross-check enabled against 10.0.4.20:1500 (BU probe)
  ok    LIVETEST_DEK_001                     → key/mbnnew5hljwmrelc (TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY/TDES_2KEY, KCV=57860B, HSM=57860B ✓)
  ok    LTEST_P0SRC_0001                     → key/idjhww6xxgz4gggd (TR31_P0_PIN_ENCRYPTION_KEY/TDES_2KEY, KCV=D5D44F, HSM=D5D44F ✓)
  FAIL  LTEST_OLD_LABEL                      → key/abc123xyz0000000 APC KCV=A68CDC, HSM KCV=B12345 — KEY MISMATCH
─────────────────────────────────────────────────────────────
5 ok, 0 warning(s), 1 error(s)
Verification FAILED — fix errors before starting the proxy.
```

Exit code is 0 only if every entry is `ok`. Run this after every `proxy.yaml` edit, after every APC key rotation, and as part of any deployment pipeline.

---

## Phase 6: Cutover

1. **Run the proxy in staging first.** Point one non-production application instance at it. Soak under a representative transaction mix.
2. **Compare results against the original HSM path for a deterministic subset** — PIN translate and MAC generate are good candidates because the same inputs produce the same outputs. If APC and the HSM disagree on a known vector, stop and investigate.
3. **Watch the logs.** Every handled command logs `cmd=… error_code=… latency_us=…`. APC errors come through as `error 41` to the application; the underlying APC error message is in the proxy log.
4. **Roll forward one application instance at a time.** Keep the original HSM path available as a rollback target until the new path has served production for an agreed observation window (a week is reasonable for a payments workload).
5. **Schedule the source HSM keys for deletion.** Don't delete immediately — keep them available for rollback for the same observation window.

---

## Production hardening checklist

Before exposing the proxy to production traffic. For the threats behind these
items — and the ones that are the deploying entity's responsibility to mitigate —
see the [Threat Model](threat-model.md).

- [ ] Inbound TLS configured (`listen.tls.cert_file` + `listen.tls.key_file`). mTLS (`listen.tls.ca_file`) if your application supports it.
- [ ] Outbound TLS configured if `discover.enabled=true` and the HSM is on a TLS-only port (`discover.tls.ca_file`, with `client_cert_file` + `client_key_file` for mTLS).
- [ ] AWS identity is an IAM role, not long-lived access keys. The proxy logs a warning on startup if it sees keys without an expiry.
- [ ] `--verify-only` exits 0 against the production `proxy.yaml`.
- [ ] APC aliases used in `key_mappings`, not raw ARNs — survives key rotation.
- [ ] Discovery log path is on a volume large enough for sustained operation; rotate or feed it to your log pipeline.
- [ ] Metrics: latency is logged per-command at INFO. Wire it into your observability stack.
- [ ] Tracing: every log line for one command carries a `req` id (a process-local counter) plus `client_ref` (the client's echoed correlation field — the Thales message header). Filter on `req` to trace a single transaction through the proxy; `client_ref` maps it back to the application's own reference. The `req` id is local to the proxy — never sent to the HSM, APC, or the client.
- [ ] Rollback path documented and tested. Until the proxy has served production traffic for the observation window, keep the original HSM reachable.

---

## What this guide does not yet cover

These are known gaps the project hasn't closed:

- **AS2805 / RTKS combined MAC+translate handlers** (RI/RK/RM/RO/RQ/RS/RU/RW, HI/HK/HM/HO/HQ/HS/HU/HW) — see [#12](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues/12). If your application uses these, you'll need to add handlers before cutover.
- **Futurex slot auto-discovery via `KMAP` + `GPKR`** — see [#13](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues/13). Until that ships, Futurex slot IDs must be pinned manually in `key_mappings`.
- **HSM connection pooling** — see [#1](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues/1). The forward leg currently opens a fresh TCP per forwarded command. Fine for discovery and low-volume; revisit for high-throughput production.
- **Real-HSM validation** — every test in this repo is either a unit test or an integration test against APC + an in-process mock HSM. The first cutover against a real upstream client application will surface protocol edge cases the spec inference left ambiguous. File what you find.

---

## Getting help

- **Bug or wrong behavior:** file an issue on [J8k3/aws-payment-cryptography-hsm-proxy](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues).
- **Protocol edge case:** include the offending wire frame (sanitised), the expected response, and what the proxy returned. Tag with `protocol-edge-case`.
- **Real-HSM validation report:** even a "it worked" report is valuable; we have no real-HSM coverage in CI. Tag with `needs-hsm-validation`.
