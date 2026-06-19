# Test grounding inventory

Purpose: decide, *per command*, what authoritative source each test decision is
grounded in — so the property suite cannot re-create the original failure
(handlers written from a fabricated corpus, "validated" by tests that shared the
same assumption). Every decision must trace to a non-author authority, or it is
gated, not tested.

## Hard constraint

**No HSM available** (no payShield, no EFTSim, no Futurex sim/hardware). So there
is no un-fakeable wire oracle. We do not pretend differential-vs-APC proves wire
fidelity — it does not. We compensate with published vectors and explicit
labeling, and we are honest about the residual.

## What the manual gives us (PUGD0537-004)

Scanned for worked examples. Finding: the manual contains **no full
command/response hex vectors** — only *field-encoding* illustrations. Useful ones
to cite when encoding individual fields:

- **KSN field** (p.~30, l.1812): KSI+DID `303950+12342468` → KSN `F30395012342468`
  (3DES BDK, 15H, last char even); AES BDK example `30395059+12345678` →
  `3039505912345678` (16H, no parity).
- **PAN storage** (l.32926): a PAN `1234567890123` example for the stored form.
- **RSA exponent / certificate** encodings (l.33698 ff).

So the manual grounds *field encodings* (cite page+field), but **not** whole-command
wire layout end-to-end. Layout must be grounded another way (below) or gated.

## Grounding axes (every test carries both labels)

**Crypto grounding** — is the expected value author-independent?
- `vec` — published standard test vector (input→output fixed by the standard).
  Strongest: neither APC, the reference lib, nor I computed it.
- `2impl` — an independent implementation (e.g. `pyemv`/`psec`) agrees with APC.
  Strong: independent of APC and of me; `pyemv` is itself vector-validated.
- `apc` — APC only. Weakest crypto grounding (single implementation).

**Wire grounding** — is the byte layout author-independent?
- `vec-thru` — a published crypto vector run *through the wire*: a wrong offset
  feeds garbage to APC, so the output ≠ the known value. Best wire grounding we
  can get with no HSM. Strengthened by randomizing field lengths (a wrong fixed
  offset that works for one length breaks for another).
- `diff-xprov` — different-provenance differential: a manual-sourced test encoder
  vs. a corpus-sourced handler. Catches corpus wire bugs (this is how this
  session's bugs would surface). Only meaningful while the handler is still
  corpus-derived — see caveat.
- `cited` — manual-cited layout + human review only. Weakest; relies on you
  auditing the citation against the page. Acceptable only when no `vec-thru`
  exists; flagged for review.
- `none` — unsourced. Does **not** ship as a passing test; gated like an
  unsupported handler.

Caveat that we will not hide: for the handlers **already fixed from the manual
this session** (CVV, GO/GQ, CA/CC, M6/C2), a manual-sourced test shares my
reading, so `diff-xprov` degenerates to a regression guard. Those are only truly
re-validated by `vec`/`vec-thru`.

## Per-command grounding map

| Command(s) | Algorithm | Published vector source | Ref lib | Best achievable label |
|---|---|---|---|---|
| KQ/KW/CAP/UnionPay, EE (ARQC/ARPC) | EMV session key + AC | EMV 4.x Book 2 Annex A; CVN-specific | `pyemv` (Visa CVN10/18/22, MC CVN16) | crypto `vec`, wire `vec-thru` |
| GO/GQ, CK/CM, DA/DC/EA/EC (PIN verify) | IBM 3624 offset / Visa PVV | IBM 3624 & Visa PVV algorithm defs | `pyemv.pin`/derive | crypto `2impl`, wire `vec-thru` |
| CW/CY (CVV) | Visa CVV | Visa CVV algorithm; APC cross-checked | (algorithm) | crypto `2impl`/`apc`, wire `vec-thru` |
| M6/M8, C2/C4, MA/MC, legacy_mac, mac_translate | ISO 9797-1 Alg1/Alg3, CMAC | ISO/IEC 9797-1; NIST CMAC (SP800-38B) | `psec`/`pyemv` | crypto `vec`, wire `vec-thru` |
| GW, dukpt_mac, dukpt_pin (DUKPT) | X9.24 DUKPT (3DES/AES) | ANSI X9.24-1/-3 canonical DUKPT test data | `pyemv`/known set | crypto `vec`, wire `vec-thru` |
| M0/M2/M4, HE/HG, emv_decrypt, encrypt_decrypt | TDES/AES ECB/CBC | NIST FIPS-197 / SP800-38A | trivial | crypto `vec`, wire `vec-thru` |
| LQ/LS (HMAC) — currently gated | HMAC-SHA | RFC 4231 | hashlib | crypto `vec` (if un-gated) |
| JA, GA/CE/GS, NY/RY, QY/PM, GU, BQ, JU/KU/KY | (gated unsupported) | n/a | n/a | `none` — stays gated |

(DUKPT canonical set, widely published: BDK `0123456789ABCDEFFEDCBA9876543210`,
KSN `FFFF9876543210E00000`; reproduce, do not invent.)

## Confidence sizing (the honest answer)

Good news from the inventory: **published vectors exist for nearly every
*supported* command family** (ARQC, DUKPT, MAC, IBM 3624, PVV, cipher, HMAC). So
most of the suite can reach `vec`/`vec-thru` — strong crypto *and* wire grounding
without an HSM. The weak spots are narrow: anywhere only `apc`/`cited` is
achievable gets flagged for human citation review, never passed silently.

So: meaningful, sized confidence — strongest on the **un-audited corpus
handlers** (manual-sourced `vec-thru` vs corpus handler is a true cross-check),
solid on everything with a published vector, and explicitly weaker (regression
guard) on the already-fixed handlers until a `vec` covers them.

## Rules the suite enforces

1. Every field offset, length, and value-mapping **cites manual page+field**.
2. The word **"inferred" fails review** — it is the fingerprint of every bug found.
3. Every test prints its **crypto+wire grounding labels**; CI may fail a suite that
   contains `none`/`cited`-only coverage for a *supported* command.
4. Generators **randomize field lengths** (PAN, KSN, key prefix) so layout bugs
   surface structurally.
5. Anchor on `vec`/`vec-thru`; `apc`-only differential is a regression guard, not
   proof, and is labeled as such.

## Build order

1. A command with a clean published vector to prove the harness end-to-end
   (DUKPT or an ISO 9797 MAC — fixed BDK/known answer).
2. The **un-audited corpus handlers** (`legacy_mac`, `dukpt_mac`, `mac_translate`,
   `emv_decrypt`, `encrypt_decrypt`, `CK`/`CM`) — highest marginal value via
   `diff-xprov` + `vec-thru`.
3. Regression `vec-thru` coverage for the handlers fixed this session.
