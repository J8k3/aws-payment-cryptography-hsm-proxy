## apc-hsm-proxy v0.3.0

A Rust TCP proxy that sits between HSM-dependent payment applications and AWS Payment Cryptography. The application keeps sending Thales payShield 10K or Futurex Excrypt commands to the same address; the proxy translates them to APC API calls on the outbound side, without changing the application.

v0.3.0 is the first release intended for evaluation by operators outside the maintainer's own setup. The companion [AWS Payment Cryptography MCP](https://github.com/J8k3/aws-payment-cryptography-mcp) ships alongside this one.

### What's new since 0.2.0

**Wrapped key block support**
- X9.143 / TR-31 key blocks (`'S'` prefix in the wire) with a `KC` optional block now resolve automatically against a startup APC `list_keys` scan, indexed by `(KeyUsage, KeyAlgorithm, KCV)`. No per-application `key_mappings` entry needed for wrapped traffic.
- `docs/key-presentation.md` (new) — full matrix of which wire forms work and which don't, per vendor.
- Disabled APC keys are skipped at scan time and surfaced with a warning so operators notice unusable inventory.

**TLS on both legs**
- Inbound TLS and mTLS (already present) gain end-to-end test coverage: handshake, plaintext rejection, client-cert validation, wrong-CA rejection.
- Outbound TLS / mTLS on the forward leg to the real HSM (new) — `discover.tls` config block. Required to reach any production payShield (host command port is TLS-only there).

**Operator tooling**
- `--verify-only` CLI mode: validates `proxy.yaml` against APC without starting the listener. Per-entry report of state / enabled / KCV / usage / algorithm. Exits 0 only if every mapping resolves to a `CREATE_COMPLETE`, enabled APC key. Catches typos, DELETE_PENDING ARNs, half-configured mTLS, missing cert files.
- `discover.hsm_read_timeout_secs` — tunable read timeout when waiting for an HSM forward response.

**Documentation**
- `docs/setup.md` (new) — end-to-end operator procedure: prerequisites → discovery → key inventory → import → `proxy.yaml` → `--verify-only` → cutover → production hardening checklist.
- `proxy.example.yaml` (new) — clean template for new users. The committed `proxy.yaml` is the maintainer's test rig and is now labeled as such.
- README refresh: Quickstart, refreshed status section, contribution-priority asks with issue labels.

### Status

**Validated against live APC.** 23 live integration tests exercise every implemented handler against real AWS Payment Cryptography. 12 in-process integration tests cover passthrough/discovery mode, inbound TLS/mTLS, and outbound TLS/mTLS to a mock HSM.

**Not yet validated against a real HSM-dependent client application.** The protocol parsers are built from specification and reference documentation, not live wire captures. This is the most valuable gap to close — see [Help test this](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy#help-test-this) for what reports would help most.

### Known gaps (tracked)

- [#1](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues/1) HSM connection pooling on the forward leg
- [#12](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues/12) AS2805 / RTKS combined MAC+translate handlers (RI/HI families)
- [#13](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues/13) Futurex slot auto-discovery via `KMAP` + `GPKR`
- [#15](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues/15) HSM-side KCV cross-check in `--verify-only`

### Getting started

Quickstart (heartbeat, no AWS needed) and full operator procedure are in the [README](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy#quickstart) and [docs/setup.md](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/blob/master/docs/setup.md).

If you have access to a real Thales payShield 10K or Futurex Excrypt and can try this against your application, please file a report — see the contribution ask at the bottom of the README.
