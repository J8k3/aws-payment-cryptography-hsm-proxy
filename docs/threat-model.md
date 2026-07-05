# Threat Model — Deployer Responsibilities

`apc-proxy` terminates a payment application's HSM wire protocol, translates it to
AWS Payment Cryptography (APC) API calls, and forwards commands it does not yet
handle to a real HSM. It therefore sits directly in the path of PINs, PAN data,
key material, and cryptograms. This document enumerates the threats whose
mitigation is **the responsibility of the entity deploying the proxy**, not of
the proxy code itself, so an operator can make an explicit decision about each
one before going live.

> **Status.** This is a living document covering known threats. It is not a PCI
> assessment and not a guarantee of completeness. It complements the
> [Production hardening checklist](setup.md#production-hardening-checklist) in the
> setup guide; where a control is a simple checklist item that guide is the
> operational reference and this document explains *why* it matters.

## Shared responsibility

The proxy is one component in a larger deployment. Responsibilities split roughly
as follows:

| Concern | Owner |
|---|---|
| Correct cryptographic translation to APC; no clear key/PIN in logs or on the wire; fail-closed verification | **Proxy** |
| Transport security configuration (TLS/mTLS on both legs) | **Deployer** — the proxy supports it; the deployer must enable it |
| Network placement and access control to the listener | **Deployer** |
| Protection, retention, and scope of the discovery log file | **Deployer** |
| AWS identity (IAM role vs long-lived keys) and its least-privilege policy | **Deployer** |
| Trust scoping of the CAs configured for each TLS leg | **Deployer** |
| APC-side key state, policies, and key strength | **Deployer** (see [setup.md](setup.md)) |
| Edge DoS protection / rate limiting | **Deployer** |

The proxy's obligation is to not undermine the deployer's controls and to fail
loudly where it safely can. Several items below note where the proxy could add a
guardrail; until those land, the control is entirely the deployer's.

## Trust boundaries

```
   payment application  ──(1)──▶  apc-proxy  ──(2)──▶  AWS Payment Cryptography
                                     │
                                     └────(3)────▶  source HSM (passthrough leg)
```

1. **Inbound leg** — the application connects to the proxy's listener. Optionally
   TLS, optionally mTLS. This is where client commands (with PIN blocks, key
   blocks, PANs) enter.
2. **APC leg** — outbound HTTPS to APC via the AWS SDK. TLS and auth are handled
   by the SDK; the deployer owns the IAM identity.
3. **Passthrough leg** — outbound to the source HSM for commands with no handler,
   when `discover` is configured. Optionally TLS/mTLS.

Legs 1 and 3 are the deployer-configured trust boundaries this document focuses
on. Assets crossing them: clear PIN blocks, LMK-/KEK-encrypted key material,
PANs and account numbers, ARQC/ARPC and MAC values.

## Threats

Each threat lists its impact, the deployer's mitigation, and what the proxy does
today (verified against the current source).

### T1 — Plaintext inbound listener

**Impact.** If `listen.tls` is omitted the listener runs in plaintext. The default
bind address is `0.0.0.0:1500`, so the out-of-the-box posture is unencrypted on
all interfaces. An on-path attacker reads PIN blocks, PANs, and key material; any
party with network reach can issue host commands that drive real APC operations,
because mTLS is the *only* client-authentication mechanism (there is no
application-layer auth — see T5).

**Deployer mitigation.** Configure `listen.tls.cert_file` + `listen.tls.key_file`.
Bind to a specific interface rather than `0.0.0.0` where possible. Place the
listener on a trusted, access-controlled network segment regardless.

**Proxy today.** Runs plaintext when unconfigured and records the mode only at
`info` level (not a warning). `--verify-only` reports a plaintext listener as a
*warning*, which does not fail the check — so a cleartext config can pass
verification. Hardening the proxy to warn at runtime and to fail `--verify-only`
under a strict/production profile is a candidate improvement; until then this is
entirely the deployer's control. One accidental route to plaintext *is* closed:
a misspelled `tls` block (or a typo'd field inside it) is now a hard config
error rather than being silently dropped to a plaintext listener.

### T2 — Plaintext passthrough leg to the source HSM (MITM)

**Impact.** If `discover.tls` is omitted, frames to the source HSM travel over
bare TCP. An on-path attacker between the proxy and the HSM can read or modify
key and PIN commands, or impersonate the HSM.

**Deployer mitigation.** Configure `discover.tls.ca_file` (and
`client_cert_file` + `client_key_file` for mTLS) whenever `discover.enabled` is
true and the HSM speaks TLS.

**Proxy today.** Sends over plaintext TCP when unconfigured, with no runtime
warning. `--verify-only` warns only when `discover.enabled` is set. The redaction
applied to the discovery *log* (see T7) does not protect data on this wire.

### T3 — Silent mTLS downgrade on the inbound listener

**Impact.** Inbound mTLS is enabled only when `listen.tls.ca_file` is present.
If it is omitted or misspelled, the listener falls back to server-auth-only TLS
and accepts **any** client with no certificate — while appearing to be "TLS
enabled." An operator who intended mTLS gets an unauthenticated listener.

**Deployer mitigation.** Verify that `listen.tls.ca_file` is set when mTLS is
intended, and test that a client without a valid certificate is actually
rejected after deployment.

**Proxy today.** The only signal of the downgrade is the startup mode string
changing from `mTLS` to `TLS`. `--verify-only` does not flag "server cert set but
no client-auth requirement." Adding that assertion is a candidate improvement.

### T4 — `--verify-only` can greenlight an insecure configuration

**Impact.** `--verify-only` is intended as a pre-go-live gate (including in CI).
It treats plaintext inbound (T1), plaintext passthrough (T2), and the mTLS
downgrade (T3) as warnings, not errors, so it can print "Verification PASSED —
config is ready to serve" for a proxy that will carry PINs and keys in cleartext.
An operator relying on the exit code deploys an insecure proxy with a green
check.

**Deployer mitigation.** Do not treat a passing `--verify-only` as sufficient
evidence of transport security. Independently confirm TLS/mTLS is enabled on both
legs (T1–T3) as part of the go-live checklist.

**Proxy today.** Exit status keys only off hard errors. A strict/production
profile that promotes T1–T3 to errors is a candidate improvement; until it
exists, the exit code is not a transport-security gate.

### T5 — Unauthenticated command execution

**Impact.** The proxy has no application-layer authentication. Any client that
can complete the transport handshake can issue commands that perform real
cryptographic operations against APC. Without mTLS, "complete the transport
handshake" means only "open a TCP (or one-way-TLS) connection."

**Deployer mitigation.** Treat mTLS on the inbound leg (T3) and network-level
access control (firewalling the listener to known application hosts) as the
authentication boundary. This is a deployment control by design.

**Proxy today.** By design; mTLS is the intended client-authentication mechanism.

### T6 — Network denial of service

**Impact.** Connection floods and slow/idle connections can tie up host
resources. The proxy now bounds several of these, but the network edge remains
the deployer's responsibility for volumetric protection.

**Deployer mitigation.** Rate-limit and connection-limit at the network edge
(load balancer, firewall, service mesh). Do not expose the listener to untrusted
networks. Set `listen.read_timeout_secs` to evict idle/slow connections on an
untrusted network (it closes a connection that sends nothing within the window;
it does not interrupt one that is actively sending, so a persistent client that
sends periodic traffic is unaffected).

**Proxy today.** Bounds per-connection memory (a 256 KiB accumulation cap) and
total concurrency (a hard ceiling of 1024 in-flight connections; further
connections wait in the kernel backlog rather than growing tasks/FDs/memory).
The accept loop logs and continues on a transient `accept()` error — notably
`EMFILE`/`ENFILE` under descriptor pressure — instead of propagating it and
crashing the process, so resource pressure degrades rather than kills.
Inbound TLS handshakes time out (10s). An idle read timeout is available but
**off by default** (`listen.read_timeout_secs`), so a truly-idle connection is
held until closed unless the operator enables it; that residual, and volumetric
flooding, remain edge concerns.

### T7 — Discovery log is sensitive data at rest

**Impact.** When `discover.log_file` is set, the proxy writes an NDJSON record for
each unique unhandled command. This file can contain cardholder data — notably
PANs / account numbers — and command metadata useful to an attacker. It is
PCI-scoped data on disk.

**Deployer mitigation.** Restrict file permissions to the proxy's service
account, keep the file off shared volumes and out of general log-shipping
pipelines, apply short retention, and disable discovery (`discover.enabled:
false` / omit `log_file`) once handlers cover the application's command set.

**Proxy today.** Redacts a fixed set of known-sensitive Futurex parameter codes
before logging. This is a blocklist, and discovery mode by definition fires on
commands whose field semantics are not modeled — so values under non-listed codes
(including PAN) can be written in the clear. Broadening redaction to a
log-safe-by-default model is a candidate code fix; regardless, the file must be
treated as sensitive at rest.

### T8 — Forward-leg CA trust scope

**Impact.** The passthrough leg validates the HSM's certificate against the
configured `discover.tls.ca_file` and checks the server name (optionally the
`server_name` override). Validation is correct — this is **not** a bypass — but
if the configured CA signs certificates for hosts other than the intended HSM,
any of those hosts presenting a valid certificate for the expected name would be
accepted, independent of the IP dialed.

**Deployer mitigation.** Scope the forward-leg CA so it signs only the source
HSM(s). Prefer a dedicated private CA over a broad organizational one. When using
`server_name` to connect by IP, understand that verification binds to the
asserted name.

**Proxy today.** Performs full chain and hostname validation; no accept-any-cert
path exists. The residual risk is entirely a function of how broadly the deployer
scopes the CA.

### T9 — AWS credential handling

**Impact.** Long-lived IAM user access keys, if compromised, grant standing
access to the APC operations the proxy can perform.

**Deployer mitigation.** Use an IAM role (EC2 instance profile, ECS task role,
EKS service account) with a least-privilege policy scoped to the specific APC
keys and operations in use. See the [IAM policy](setup.md#iam-policy) section.

**Proxy today.** Warns at startup when it detects credentials with no expiry
(i.e. long-lived keys). Never logs credential material.

### T10 — Sensitive material in third-party memory (residual risk)

**Impact.** The proxy copies clear PIN blocks and decrypted material into
zeroizing buffers, but the AWS SDK response types that originally carry them are
not zeroizing, so a translated PIN block transits SDK-owned heap that is not
scrubbed on drop.

**Deployer mitigation.** This is not fixable at the proxy layer. Treat the host
running the proxy as a PIN-processing environment: memory protection, restricted
access, no core dumps to shared storage, and the physical/logical controls PCI
PIN expects of such a host.

**Proxy today.** Zeroizes everything it owns; the residual is inherent to the SDK
types. Documented here as an accepted residual risk.

## PCI P2PE / PIN scope (if your deployment is in scope)

AWS Payment Cryptography is a validated **PCI P2PE Component Provider**
(Decryption, Key Management, and Key Loading Components) and is in scope for **PCI
PIN**; the current attestations are available to AWS customers through AWS
Artifact. If you run this proxy as part of a P2PE or PIN solution, several
obligations are the **deploying entity's**, not APC's — they follow the standard
P2PE component-provider responsibility split. This is a pointer, not compliance
advice; confirm scope and applicability with your Qualified PIN Assessor / QSA.

- **Authenticate the POI before decryption** ([PCI P2PE v3.2](https://www.pcisecuritystandards.org/) 4B-1.4) — verify a transaction comes from a POI valid for your solution (e.g. a known BDK ID + Derivation ID, or KSI + PED ID for TDEA DUKPT) before calling `DecryptData`.
- **Never return cleartext to the encryption environment** (4B-1.7) — cleartext that APC returns must not flow back to the POI or any encryption-side component.
- **Monitor for encryption / cryptographic failures** (4C-1.3) — watch for missing or invalid BDK IDs, API errors, and malformed results; your application has transaction context APC does not.
- **Keep shared keys unique between organizations** (17-1) — a key (including a KEK protecting a data key) shared between two entities must not be reused with a third; APC key tags can help track this.
- **Use approved initial key injection** (12-7) — load the initial TMK / DUKPT BDK to POI devices via approved asymmetric or manual techniques; APC supports TR-31 and TR-34 export for remote key-loading applications.
- **Own the key lifecycle outside APC** ([PCI PIN v3.1](https://www.pcisecuritystandards.org/) Control Objectives 2, 3, and 6) — APC protects keys once they are imported, but the generation, conveyance, loading, and destruction of key material *before it is imported and after it is exported* remain the deployer's. The proxy resolves a wire-form key reference to an **already-imported** APC key (by KCV or `key_mappings`); it neither holds the source HSM's master key nor manages that material's lifecycle, so nothing about inserting the proxy changes this responsibility.
- **Separate production and test keys** (19-4) — production keys must never be present or used in a test system, and vice versa. Because the proxy selects keys by ARN from its config, use **distinct AWS accounts** (at minimum distinct, clearly-scoped keys and `key_mappings`) for production versus test so traffic can never be pointed at the wrong key set.

## Deployer pre-production checklist

Cross-referenced with the [Production hardening
checklist](setup.md#production-hardening-checklist):

- [ ] Inbound TLS enabled; mTLS if the application supports it (T1, T3, T5)
- [ ] Client-without-certificate rejection tested, if mTLS is intended (T3)
- [ ] Passthrough-leg TLS/mTLS enabled whenever `discover.enabled` and the HSM speaks TLS (T2)
- [ ] Transport security confirmed independently of the `--verify-only` exit code (T4)
- [ ] Listener bound to a specific interface and firewalled to known application hosts (T1, T5, T6)
- [ ] Edge rate/connection limiting in place (T6)
- [ ] Discovery log permissions, retention, and pipeline scope reviewed; discovery disabled once no longer needed (T7)
- [ ] Forward-leg CA scoped to the source HSM(s) only (T8)
- [ ] AWS identity is a least-privilege IAM role, not long-lived keys (T9)
- [ ] Proxy host treated as a PIN-processing environment (T10)
- [ ] If in PCI P2PE / PIN scope: POI authentication, no-cleartext-return, crypto-failure monitoring, unique inter-org keys, and approved key injection are handled per your assessor (see [PCI P2PE / PIN scope](#pci-p2pe--pin-scope-if-your-deployment-is-in-scope))
- [ ] Production and test keys separated (distinct AWS accounts), and key material lifecycle outside APC owned end-to-end (PCI PIN scope)

## Reporting

Security-relevant findings in the proxy code (as opposed to deployment
configuration) should be reported per the process in the
[README](../README.md). Please do not include real key material, PANs, or PIN
blocks in any report or attached capture.
