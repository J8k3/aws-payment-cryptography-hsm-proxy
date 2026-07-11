# Key Presentation: Wire Forms and Proxy Behavior

How keys are referenced in inbound HSM commands, and what the proxy does with each form when resolving to an AWS Payment Cryptography (APC) key ARN.

This is operator-facing reference material. If you are deciding whether the proxy will work with your application's traffic, read this first.

## Why this matters

APC is ARN-addressed: every data-plane call references a key by `arn:aws:payment-cryptography:...:key/...` (or `alias/name`). Inbound HSM commands do not carry ARNs — they carry one of several vendor-specific key references. The proxy's job is to take the wire-form reference and produce an APC ARN.

There are two resolution paths:

1. **Label path** — operator-provided `key_mappings` in `proxy.yaml`. The proxy matches the raw bytes from the wire against the keys of the map and returns the configured ARN. KCV-blind.
2. **KCV path** — at startup the proxy calls `list_keys` against APC, filters to enabled CREATE_COMPLETE keys, and builds an in-memory `(KeyUsage, KeyAlgorithm, KCV) → ARN` index. Wrapped key blocks that carry a KCV optional block resolve through this index without any per-application config.

The choice of path depends on the wire form, not on operator preference.

### APC as the key store

APC exposes each key as an ARN, never the wrapped bytes, so the proxy *maps* a
wire-form reference to an ARN and lets APC do the unwrap — it never needs (or has)
the source HSM's master key. The migration effectively **swaps the customer's key
store for APC's key store.** It is still a store the customer owns and enumerates
— via the control-plane `list_keys`, which is exactly what the KCV path above does
at startup — just addressed by ARN rather than an HSM-resident slot. So a wire form that used to point at a key in the HSM
table (a Futurex slot, say — [#13](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues/13))
now has to resolve to the matching APC ARN.

---

## Thales payShield 10K

| Wire form | Encoding | What proxy does | Notes |
|---|---|---|---|
| **Variant LMK encrypted** | `16H` single, `U+32H` double, `T+48H` triple | Label-path lookup against the literal hex string | Most common in legacy deployments. Operator must pin the exact LMK-encrypted hex to an ARN in `key_mappings`. No metadata in the wire. |
| **X9.143 / TR-31 key block** | `S` + ASCII TR-31 block | Header parsed; if `KC` optional block present, KCV extracted and KCV-path lookup used | First-class support. Requires the corresponding key to be already imported into APC with matching usage, algorithm, and KCV. |
| **Thales Key Block (TKB) — with KC** | `S` + TKB block carrying a `KC` optional block | Same as X9.143 (header layout is identical) | Resolves cleanly via KCV path. |
| **Thales Key Block (TKB) — no KC** | `S` + TKB block, no `KC` optional block | Header parses but KCV is `None`; resolver falls back to label path against the raw block bytes | Falls back to operator-pinned label config. If no label entry, returns error 10 (KeyNotFound). The proxy does NOT attempt a `(usage, algorithm)`-only lookup — too risky in any account with multiple keys of the same type. |
| **Atalla Key Block (AKB)** | Different framing entirely | Not parsed | Returns error 15 (malformed payload). |
| **ASCII label** | Variable-width ASCII string in the key field | Label-path lookup against the label string | Application must be configured to send labels rather than LMK-encrypted hex. This is opt-in on payShield and depends on the Key Label Translation Table being enabled there; not all commands support it. Proxy treats this identically to variant LMK from a resolution standpoint — the wire bytes are the lookup key. |

### Commands that do not accept `'S'` prefix (wrapped key blocks)

The following Thales commands have **fixed-width** key fields per the payShield Host Command Reference. They predate Key Block LMK and the wire spec does not permit a prefix byte. The proxy parses them as fixed-width labels and never tries to detect a wrapped block:

| Command | Field offsets | Why fixed-width |
|---|---|---|
| `CA` / `CC` / `BQ` | source key `[2..34]`, dest key `[34..66]` | Legacy PIN-translate commands, designed for double-length TDES only. |
| `CI` / `G0` | Same as above + KSN | DUKPT variants of CA/CC. |
| `C2` / `C4` | key `[1..33]` | Original X9.9 / X9.19 single-message MAC. Use `M6` / `M8` (variable-width, wrapped-key capable) if your application can be switched. |
| `CW` / `CY` | CVK `[1..33]` | Original CVV generate / verify. |
| `QY` / `PM` | CVK `[0..32]` | Dynamic CVV. |

Applications that need wrapped keys for MAC operations should target `M6` / `M8` rather than `C2` / `C4`.

### Commands that do accept `'S'` prefix

Every Thales handler that uses `parse_legacy_key`, `parse_bdk`, or `parse_key_32` accepts wrapped key blocks. As of writing that includes:

`HE` `HG` `M0` `M2` `M4` `M6` `M8` `GW` `GO` `GQ` `CK` `CM` `K0` `K2` `KS` `KQ` `KW` `JS` `MA` `MC` `ME` `MK` `MM` `MO` `MU` `MW` `MQ` `MS` `LQ` `LS` `KU` `JU` `KY` `GA` `CE` `JA` `CU` `DU`

The `parse_*` helpers in `src/handlers/thales/common.rs` are the single source of truth; if you extend a handler to use one of those helpers, wrapped-key support comes with it.

---

## Futurex Excrypt Enterprise SSP

For payment transaction processing, the dominant key presentation is a **working
key carried in the request, wrapped under the HSM master key** — the same
stateless-at-scale model as Thales's LMK-encrypted keys. Passing the key per
request keeps HSMs in a cluster interchangeable; a resident key table would pin a
transaction to one box (and runs into the per-session limits — ~1 min idle / 15
min / 7,500 transactions — documented in the module's FIPS 140-2 security policy).
The proxy never unwraps these (it does not hold the source HSM's master key); it
resolves them to a pre-imported APC key by KCV match or operator `key_mappings`.

Presentation splits by **key lifetime**: long-lived keys (master keys, KEKs,
issuer master keys) are often resident in the HSM's **key table** and referenced
by slot — a management / general-purpose concern; per-transaction **working keys**
are carried wrapped in the request. It is the working-key path that dominates
transaction commands and that the proxy is built to resolve.

| Wire form | Encoding | What proxy does | Notes |
|---|---|---|---|
| **Cryptogram — working key wrapped under the master key** | Hex-encoded key wrapped under the HSM master key / KEK, carried in the request | Not parsed | The dominant transaction-key presentation (see above). Pre-TR-31 Futurex format. Not parsed today — this is the most impactful Futurex gap: KCV-based resolution of Futurex wrapped keys (as done for Thales) is the higher-value work, not slot discovery. Returns error if encountered. |
| **X9.143 / TR-31 key block** | Field carrying an ASCII TR-31 block | Not parsed | Newer Excrypt firmware supports inline TR-31 in some commands. Proxy does not parse Futurex's TR-31 wrappers today — the Thales `'S'` prefix detection in `parse_legacy_key` does not apply because Futurex fields are parameter-tagged, not positional. |
| **User-space key table slot reference** | Integer slot ID in `BD` field, or label resolved server-side | Label-path lookup against the parameter value | Secondary / management mode — the key table holds longer-lived keys; transaction commands more often carry a wrapped working key (rows above). `KMAP` + `GPKR` are *general-purpose* key-table commands (Key Map / General Purpose Key Read), not implemented today, so the operator pins the slot ID (or its label) to an ARN in `key_mappings`. |
| **Atalla Key Block (AKB)** | Different framing | Not parsed | |

For Futurex, the only resolution mechanism the proxy currently uses is operator-provided `key_mappings` matching the wire-form parameter value.

---

## KC optional block (X9.143)

The wrapped-key KCV path depends on the producer including a `KC` optional block in the TR-31 header. Layout the proxy expects:

```
[ID="KC"][Length 2 hex chars][KCV version 2 chars][KCV value 6+ hex chars]
```

The proxy reads:
- Length to know how many bytes the block occupies.
- KCV version is consumed but not validated.
- KCV value is uppercased and used as the third component of the `(usage, algorithm, KCV)` lookup key.

If the producer emits an extended-length optional block (length field `"00"` followed by an extended length sub-field), the proxy stops the optional-block scan and returns no KCV from that block. Resolution falls back to the label path.

## Startup APC scan

At startup the proxy paginates `list_keys` (data plane unaffected — this is a control-plane call) and builds the KCV index. Behavior:

- Only `CREATE_COMPLETE` keys are considered.
- Disabled keys (`Enabled=false`) are skipped and surfaced with a warning per key.
- Multiple keys sharing the same `(usage, algorithm, KCV)` (e.g., the same clear material imported under different ARNs) generate a warning naming all conflicting ARNs; the proxy picks the lexicographically smallest ARN deterministically.
- A failed scan logs a warning but does not abort startup — the proxy still serves label-path resolution. Wrapped-key requests will fail with KeyNotFound until the scan can run successfully.

## Operational implications

- **You always need `key_mappings` for variant-LMK and label-based wire forms.** The KCV path covers wrapped-block traffic only.
- **You never need `key_mappings` for X9.143 wrapped keys with KC.** Import the key once into APC, the proxy discovers it at startup.
- **The proxy will refuse to silently mis-route.** A wrapped block whose declared KCV doesn't match any APC key returns error 10 (KeyNotFound) rather than falling through to the label path. This is deliberate — silent misrouting under a wrong key would be a far worse failure than a clear error.
- **Collisions are an inventory hygiene issue.** If you re-import the same clear key under multiple ARNs, expect the warning at startup. Clean up duplicates with `scripts/delete_test_keys.py` or via APC directly.

## Known gaps

These are not bugs — they are documented limits of the current implementation. Tracked in GitHub issues where noted.

- **Atalla Key Block (AKB)** parsing — not implemented for either vendor. Open an issue if your application relies on AKB.
- **Futurex wrapped working keys (the higher-value gap)** — the dominant transaction-key presentation (a key wrapped under the HSM master key, carried in the request) is not parsed for Futurex, so the proxy can't extract a KCV to match a pre-imported APC key the way it does for Thales. Operators must pin the literal wire form in `key_mappings`. KCV-based resolution of Futurex wrapped keys is the most impactful Futurex work.
- **Futurex inline TR-31** — Excrypt commands that carry TR-31 blocks in parameter fields are not parsed. Falls back to label resolution against the raw parameter value.
- **Futurex slot auto-discovery** — `KMAP` + `GPKR` enumeration is not implemented ([#13](https://github.com/J8k3/aws-payment-cryptography-hsm-proxy/issues/13)). These are *general-purpose* key-table commands and address the secondary (resident-key) mode, not the per-request working-key path — a management convenience, not core transaction handling. Today operators pin slot IDs in `key_mappings`.
- **TKB without `KC`** — parses but yields no KCV, so KCV-path resolution is unavailable. Operator must pin the literal block bytes if they want it to resolve.
- **TDES DUKPT direction** — `dukpt_mac.rs` (GW) hardcodes `Request` variant. Host-response MACs would need `Response`. APC handles the variant derivation internally; the proxy just chooses which to ask for.
