//! Live-APC differential property tests.
//!
//! See: `docs/property-testing-plan.md`, `docs/test-grounding-inventory.md`.
//!
//! Every test in this file is `#[ignore]` AND gated on `APC_LIVE=1`. Both
//! guards must be lifted for a test to make a real APC call — `cargo test`
//! must never accidentally provision keys.
//!
//! Run:
//! ```sh
//! APC_LIVE=1 cargo test --test proptest_live -- --ignored --nocapture
//! ```
//!
//! Optional env vars:
//!   `AWS_REGION` (default `us-east-1`)
//!   `APC_LIVE_SEED` (u64, default `0xA5C3F00C0FFEE_u64`) — reproducible base seed
//!   `APC_LIVE_CASES` (usize, default `32`) — cases per command per run; cost is
//!     ~linear and cheap (keys are per-test, not per-case), so crank it for
//!     thorough runs (e.g. `256`) or lower it for a quick smoke check
//!   `APC_LIVE_REPLAY` (e.g. `5` or `3,5,7`) — run only these case indices
//!
//! Each test runs many randomized cases per invocation (the sweep). Every case
//! gets an independent RNG seeded from `(base seed, command, index)`, so a
//! failing case can be reproduced on its own without replaying the cases before
//! it — on failure the test prints the exact `APC_LIVE_REPLAY=…` command to do
//! so. Each case creates fresh APC keys via `TestKeys::create`, exercises a
//! handler through its wire frame, compares the handler's APC result against
//! a direct APC SDK call built from the same field values, and tears down
//! every test key before exiting. A final `assert_no_surviving` check
//! enforces the zero-surviving-key invariant the plan calls out.

// Tests live outside the prod source tree; panic IS the intended failure mode
// and the runner already reports file:line.
#![allow(clippy::unwrap_used)]
// Test-only file: pedantic noise about Vec<u8> args and `.expect` strings is
// not worth chasing here.
#![allow(clippy::missing_panics_doc)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use apc_proxy::handlers::{AppState, Registry};
use apc_proxy::key_map::KeyMap;
use aws_config::BehaviorVersion;
use aws_sdk_paymentcryptography::types::{
    KeyAlgorithm, KeyAttributes, KeyClass, KeyModesOfUse, KeyState, KeyUsage,
};
use aws_sdk_paymentcryptographydata::types::{
    CardGenerationAttributes, CardVerificationValue1, DukptAttributes, DukptDerivationType,
    DukptKeyVariant, Ibm3624NaturalPin, Ibm3624PinVerification, MacAlgorithm, MacAlgorithmDukpt,
    MacAttributes, PinBlockFormatForPinData, PinGenerationAttributes, PinVerificationAttributes,
    TranslationIsoFormats, TranslationPinDataIsoFormat034, VisaPin,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

// ── Gating ───────────────────────────────────────────────────────────────────

fn live_enabled() -> bool {
    std::env::var("APC_LIVE").as_deref() == Ok("1")
}

fn aws_region() -> String {
    std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .unwrap_or_else(|_| "us-east-1".into())
}

fn rng_seed() -> u64 {
    std::env::var("APC_LIVE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x000A_5C3F_00C0_FFEE_u64)
}

/// Cases per command per run. Default 32. Cost is ~linear and cheap: keys are
/// created once per test (setup), not per case, so each extra case is only a few
/// data-plane calls (~60 ms). Crank it for a thorough run — e.g.
/// `APC_LIVE_CASES=256` (~30 s) — or drop it for a quick smoke check.
fn case_count() -> usize {
    std::env::var("APC_LIVE_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32)
}

// ── Case selection & deterministic replay ─────────────────────────────────────
//
// Each test runs *many* randomized cases per invocation (the sweep). Every case
// gets its own RNG seeded from (base seed, command label, case index), so cases
// are independent and any single one can be reproduced in isolation — you don't
// have to replay the cases before it.
//
// Replay: when a case fails, the harness prints the exact command to re-run just
// that case. `APC_LIVE_REPLAY=5` (or `3,5,7`) runs only those indices, with the
// same per-case seed they had in the full sweep, so the failing **wire inputs**
// (PAN, format codes, message, KSN, …) are reproduced byte-for-byte. Pin
// `APC_LIVE_SEED` to the value the failing run printed.
//
// What replay does and does NOT pin: the *inputs* are deterministic; the *keys*
// are not — fresh random keys are created every run by design (a fixed key hides
// bugs; see the plan's requirement #1). So crypto outputs (CVV/MAC) differ
// run-to-run, but that is irrelevant to the differential property: a wire /
// parse / mapping bug makes proxy ≠ oracle for the reproduced input regardless
// of key value, so it reproduces identically. (A bug that only triggers for a
// specific key value is what the per-run key *rotation* surfaces — not what
// replay targets; reproducing that needs known key material, the Tier-2 path.)

/// SplitMix64 — a small, stable mixing function. Chosen over `DefaultHasher`
/// because its output is fixed forever (no dependence on std/Rust version), so a
/// recorded `(seed, index)` replays identically months later.
fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Per-case RNG seed: deterministic in `(base, command label, case index)`.
fn case_seed(base: u64, label: &str, idx: usize) -> u64 {
    let mut h = splitmix64(base);
    for b in label.bytes() {
        h = splitmix64(h ^ u64::from(b));
    }
    splitmix64(h ^ idx as u64)
}

/// Fresh RNG for one case, derived from the base seed + command label + index.
fn case_rng(label: &str, idx: usize) -> StdRng {
    StdRng::seed_from_u64(case_seed(rng_seed(), label, idx))
}

/// The case indices to run: `APC_LIVE_REPLAY` (comma-separated) if set,
/// otherwise `0..case_count()`.
fn cases_to_run() -> Vec<usize> {
    match std::env::var("APC_LIVE_REPLAY") {
        Ok(s) if !s.trim().is_empty() => s
            .split(',')
            .filter_map(|t| t.trim().parse::<usize>().ok())
            .collect(),
        _ => (0..case_count()).collect(),
    }
}

/// The command line that reproduces exactly one case of a failing test.
fn replay_hint(test_fn: &str, label: &str, idx: usize) -> String {
    format!(
        "REPLAY this case: APC_LIVE=1 AWS_REGION={region} APC_LIVE_SEED=0x{seed:016X} \
         APC_LIVE_REPLAY={idx} cargo test --test proptest_live {test_fn} -- --ignored --nocapture\n\
         (case label={label})",
        region = aws_region(),
        seed = rng_seed(),
    )
}

// ── AWS clients ──────────────────────────────────────────────────────────────

async fn aws_clients() -> (
    aws_sdk_paymentcryptography::Client,
    aws_sdk_paymentcryptographydata::Client,
) {
    let cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(aws_config::Region::new(aws_region()))
        .load()
        .await;
    (
        aws_sdk_paymentcryptography::Client::new(&cfg),
        aws_sdk_paymentcryptographydata::Client::new(&cfg),
    )
}

// ── TestKeys RAII guard ──────────────────────────────────────────────────────

/// Specification for one key the harness will provision before a test runs.
struct KeySpec {
    /// Human-readable role (e.g. "CVK") used by the test to look up the ARN.
    role: &'static str,
    /// 32-hex-char wire label the handler sees in the payload. Must match the
    /// `parse_key_32`/`parse_legacy_key`/etc. layout the handler expects.
    wire_label: &'static str,
    algorithm: KeyAlgorithm,
    key_usage: KeyUsage,
    modes: KeyModesOfUse,
}

/// RAII guard for live APC keys created during a test run.
///
/// `create` provisions each key and polls it to `CREATE_COMPLETE`. The happy
/// path consumes the guard via `teardown().await`, which calls `DeleteKey` on
/// every ARN and returns an error if any deletion fails. If the guard is
/// dropped without `teardown` (test panic), the `Drop` impl spawns a
/// best-effort deletion on the current Tokio handle and prints the leaked
/// ARNs to stderr so the operator can clean up — but the authoritative safety
/// net is the post-teardown `assert_no_surviving` check plus the standing
/// `scripts/delete_test_keys.py` script.
struct TestKeys {
    cpc: aws_sdk_paymentcryptography::Client,
    /// role → live ARN
    arns: HashMap<&'static str, String>,
    /// role → wire label (the 32-char string that goes into the wire payload)
    wire_labels: HashMap<&'static str, &'static str>,
    /// Cleared by `teardown`. If still set in `Drop`, we leaked.
    armed: bool,
}

impl TestKeys {
    async fn create(
        cpc: aws_sdk_paymentcryptography::Client,
        specs: &[KeySpec],
    ) -> anyhow::Result<Self> {
        let mut arns = HashMap::new();
        let mut wire_labels = HashMap::new();
        for s in specs {
            let attrs = KeyAttributes::builder()
                .key_algorithm(s.algorithm.clone())
                .key_class(KeyClass::SymmetricKey)
                .key_usage(s.key_usage.clone())
                .key_modes_of_use(s.modes.clone())
                .build()?;
            let resp = cpc
                .create_key()
                .key_attributes(attrs)
                .exportable(false)
                .enabled(true)
                .send()
                .await?;
            let key = resp
                .key
                .ok_or_else(|| anyhow::anyhow!("create_key: no Key in response"))?;
            let arn = key.key_arn.clone();
            eprintln!(
                "TestKeys: created role={} usage={:?} arn={}",
                s.role, s.key_usage, arn
            );
            arns.insert(s.role, arn);
            wire_labels.insert(s.role, s.wire_label);
        }
        for (role, arn) in &arns {
            for poll in 0..30 {
                let g = cpc.get_key().key_identifier(arn).send().await?;
                let k = g
                    .key
                    .ok_or_else(|| anyhow::anyhow!("get_key: no Key in response"))?;
                if matches!(k.key_state, KeyState::CreateComplete) {
                    break;
                }
                if poll == 29 {
                    anyhow::bail!("key {role} stuck in state {:?} after 30 polls", k.key_state);
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        Ok(Self {
            cpc,
            arns,
            wire_labels,
            armed: true,
        })
    }

    fn arn(&self, role: &str) -> &str {
        self.arns
            .get(role)
            .map(String::as_str)
            .expect("TestKeys::arn: unknown role")
    }

    fn wire_label(&self, role: &str) -> &str {
        self.wire_labels
            .get(role)
            .copied()
            .expect("TestKeys::wire_label: unknown role")
    }

    /// Snapshot of every provisioned ARN, in stable role order — for
    /// `assert_no_surviving` after teardown.
    fn arns(&self) -> Vec<String> {
        let mut roles: Vec<&&'static str> = self.arns.keys().collect();
        roles.sort();
        roles.into_iter().map(|r| self.arns[r].clone()).collect()
    }

    /// Build a `key_mappings` map suitable for `AppState.key_map`.
    fn key_mappings(&self) -> HashMap<String, String> {
        self.arns
            .iter()
            .map(|(role, arn)| (self.wire_labels[role].to_string(), arn.clone()))
            .collect()
    }

    /// Happy-path teardown: delete every provisioned key. Consumes the guard.
    async fn teardown(mut self) -> anyhow::Result<()> {
        self.armed = false;
        let mut failed = Vec::new();
        // `drain` empties the map before the SDK call so `Drop` will be a no-op
        // even if `delete_key` panics partway through.
        let arns: Vec<(&'static str, String)> = self.arns.drain().collect();
        for (role, arn) in arns {
            match self.cpc.delete_key().key_identifier(&arn).send().await {
                Ok(_) => eprintln!("TestKeys: deleted role={role} arn={arn}"),
                Err(e) => {
                    eprintln!("TestKeys: delete FAILED role={role} arn={arn}: {e}");
                    failed.push((role, arn));
                }
            }
        }
        if !failed.is_empty() {
            anyhow::bail!("TestKeys: {} key deletion(s) failed", failed.len());
        }
        Ok(())
    }
}

impl Drop for TestKeys {
    fn drop(&mut self) {
        if !self.armed || self.arns.is_empty() {
            return;
        }
        let leaked: Vec<String> = self.arns.values().cloned().collect();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let cpc = self.cpc.clone();
            let arns = leaked.clone();
            handle.spawn(async move {
                for arn in arns {
                    let _ = cpc.delete_key().key_identifier(arn).send().await;
                }
            });
            eprintln!(
                "TestKeys::drop fired without teardown(); spawned best-effort \
                 delete for {} key(s). Prefer keys.teardown().await on the happy path.",
                leaked.len()
            );
        } else {
            eprintln!("TestKeys::drop: WARNING: no tokio runtime; LEAKED keys: {leaked:?}");
        }
    }
}

/// Assert no ARN in `arns` is still in `CREATE_COMPLETE` state.
///
/// APC `DeleteKey` schedules deletion; the key state transitions to
/// `DeleteScheduled` immediately, so anything still `CREATE_COMPLETE` either
/// failed to delete or was never deleted — both are leaks.
async fn assert_no_surviving(
    cpc: &aws_sdk_paymentcryptography::Client,
    arns: &[String],
) -> anyhow::Result<()> {
    for arn in arns {
        let g = cpc.get_key().key_identifier(arn).send().await?;
        let k = g
            .key
            .ok_or_else(|| anyhow::anyhow!("get_key: no Key in response for {arn}"))?;
        if matches!(k.key_state, KeyState::CreateComplete) {
            anyhow::bail!("SURVIVING TEST KEY: {arn} still CREATE_COMPLETE after teardown");
        }
    }
    Ok(())
}

/// Build a live `AppState` for in-process handler calls.
fn live_state(data: aws_sdk_paymentcryptographydata::Client, keys: &TestKeys) -> Arc<AppState> {
    Arc::new(AppState {
        key_map: KeyMap::new(keys.key_mappings()),
        data,
    })
}

// ── Generators ───────────────────────────────────────────────────────────────
//
// Inputs are varied within each variable's *known bounds*, with the boundary and
// structurally-interesting values **over-sampled** (`edge_biased`). Uniform
// sampling over a range hits the endpoints only ~1/width of the time, so a small
// live sweep would routinely miss the exact edges where fixed-offset parse bugs
// live (shortest/longest PAN, the Amex-15 length, the 8-byte DES block boundary).
// Boundary coverage improves as `APC_LIVE_CASES` rises.

/// Sample the inclusive range `[lo, hi]` with `interesting` values
/// over-represented: ~60% of the time return one of them (clamped into range),
/// otherwise a uniform interior draw. Deterministic in the case RNG, so replay
/// reproduces the same value.
fn edge_biased(rng: &mut StdRng, lo: usize, hi: usize, interesting: &[usize]) -> usize {
    if !interesting.is_empty() && rng.random_bool(0.6) {
        interesting[rng.random_range(0..interesting.len())].clamp(lo, hi)
    } else {
        rng.random_range(lo..=hi)
    }
}

/// Random valid PAN: first digit 1..9 (no leading zero), rest 0..9. Length per
/// caller. ISO/IEC 7812 PANs are 8..19 digits; CVV practice spans 13..19.
fn gen_pan(rng: &mut StdRng, len: usize) -> String {
    let mut s = String::with_capacity(len);
    s.push(char::from(b'1' + rng.random_range(0..9_u8)));
    for _ in 1..len {
        s.push(char::from(b'0' + rng.random_range(0..10_u8)));
    }
    s
}

/// PAN length for CVV, edge-biased over its known bounds. Bounds: ISO/IEC 7812
/// 13..19. Interesting edges: 13 (min), 15 (Amex — the CW handler's documented
/// fixed-16 mis-read risk), 16 (Visa/MC default — must NOT be special-cased),
/// 19 (max).
fn gen_pan_len(rng: &mut StdRng) -> usize {
    edge_biased(rng, 13, 19, &[13, 15, 16, 19])
}

/// Random YYMM expiry (4N). Year 25..30, month 01..12, both edge-biased so the
/// month/year boundaries of the fixed 4-digit field are exercised.
fn gen_expiry(rng: &mut StdRng) -> String {
    let yy = edge_biased(rng, 25, 30, &[25, 30]) as u8;
    let mm = edge_biased(rng, 1, 12, &[1, 12]) as u8;
    format!("{yy:02}{mm:02}")
}

/// Pick a service code from the published Visa/Mastercard set covering the
/// distinct CVV product variants (magstripe / signature / chip).
fn gen_service_code(rng: &mut StdRng) -> &'static str {
    const CODES: &[&str] = &["201", "101", "120", "000", "999"];
    CODES[rng.random_range(0..CODES.len())]
}

// ── CVV CW/CY (live differential) ────────────────────────────────────────────

/// Wire label for the CVK in this test (32H, parsed by `parse_key_32` as a
/// bare double-length key label). The harness maps this string → live ARN in
/// `key_mappings` so the handler resolves it normally.
const CVK_WIRE_LABEL: &str = "00000000000000000000000000000001";

/// Encode the CW wire frame per PUGD0537-004 Rev A p.250.
///
/// Wire: CVK(32H) || PAN(nN) || ';' || expiry(4N) || service_code(3N)
///
/// The encoder is written from the manual independently of the handler's
/// decoder; if either is wrong, the proxy's CVV will not match the oracle.
fn encode_cw(cvk_label: &str, pan: &str, expiry: &str, service_code: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(cvk_label.len() + pan.len() + 1 + 4 + 3);
    v.extend_from_slice(cvk_label.as_bytes());
    v.extend_from_slice(pan.as_bytes());
    v.push(b';');
    v.extend_from_slice(expiry.as_bytes());
    v.extend_from_slice(service_code.as_bytes());
    v
}

/// Encode the CY wire frame per PUGD0537-004 Rev A p.303.
///
/// Wire: CVK(32H) || CVV(3N) || PAN(nN) || ';' || expiry(4N) || service_code(3N)
fn encode_cy(cvk_label: &str, cvv: &str, pan: &str, expiry: &str, service_code: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(cvk_label.len() + 3 + pan.len() + 1 + 4 + 3);
    v.extend_from_slice(cvk_label.as_bytes());
    v.extend_from_slice(cvv.as_bytes());
    v.extend_from_slice(pan.as_bytes());
    v.push(b';');
    v.extend_from_slice(expiry.as_bytes());
    v.extend_from_slice(service_code.as_bytes());
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn cvv_cw_cy_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }

    // Grounding labels — recorded in the test output per the inventory's
    // "every test prints its crypto+wire grounding labels" rule.
    //   crypto = apc        (differential vs APC, single implementation — Tier 1)
    //   wire   = diff-xprov (manual-sourced encoder vs corpus handler;
    //                       length-randomised PAN exposes fixed-offset bugs)
    eprintln!("cvv_cw_cy_differential: grounding crypto=apc wire=diff-xprov(length-randomised)");

    let (cpc, data) = aws_clients().await;

    let specs = [KeySpec {
        role: "CVK",
        wire_label: CVK_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31C0CardVerificationKey,
        modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let cvk_arn = keys.arn("CVK").to_string();
    let cvk_label = keys.wire_label("CVK").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let cw_handler = registry.get(b"CW").expect("CW handler registered");
    let cy_handler = registry.get(b"CY").expect("CY handler registered");

    const LABEL: &str = "cvv_cw_cy";
    let run = cases_to_run();
    eprintln!(
        "cvv_cw_cy_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan_len = gen_pan_len(&mut rng);
        let pan = gen_pan(&mut rng, pan_len);
        let expiry = gen_expiry(&mut rng);
        let service_code = gen_service_code(&mut rng);

        // 1) CW: proxy
        let cw_wire = encode_cw(&cvk_label, &pan, &expiry, service_code);
        let proxy_cw = cw_handler.handle(b"CW", &cw_wire, &state).await;
        if &proxy_cw.error_code != b"00" {
            eprintln!("{}", replay_hint("cvv_cw_cy_differential", LABEL, case_idx));
            result = Err(anyhow::anyhow!(
                "case={case_idx} CW error_code={} (PAN={pan} expiry={expiry} svc={service_code})",
                String::from_utf8_lossy(&proxy_cw.error_code),
            ));
            break;
        }
        let proxy_cvv = String::from_utf8(proxy_cw.payload.to_vec())?;

        // 2) CW: oracle (direct APC SDK call built from the same field values)
        let attrs = CardVerificationValue1::builder()
            .card_expiry_date(&expiry)
            .service_code(service_code)
            .build()?;
        let oracle = data
            .generate_card_validation_data()
            .key_identifier(&cvk_arn)
            .primary_account_number(&pan)
            .generation_attributes(CardGenerationAttributes::CardVerificationValue1(attrs))
            .send()
            .await?;
        let oracle_cvv = oracle.validation_data().to_string();

        if proxy_cvv != oracle_cvv {
            eprintln!("{}", replay_hint("cvv_cw_cy_differential", LABEL, case_idx));
            result = Err(anyhow::anyhow!(
                "case={case_idx} CW differential mismatch: proxy={proxy_cvv} oracle={oracle_cvv} \
                 PAN={pan} expiry={expiry} svc={service_code}"
            ));
            break;
        }

        // 3) CY round-trip: verify the proxy's CW output through the proxy's
        //    CY path. A success here proves CW→CY agree wire-side AND that the
        //    CY verifier accepts a CVV the CW generator produced.
        let cy_wire = encode_cy(&cvk_label, &proxy_cvv, &pan, &expiry, service_code);
        let proxy_cy = cy_handler.handle(b"CY", &cy_wire, &state).await;
        if &proxy_cy.error_code != b"00" {
            eprintln!("{}", replay_hint("cvv_cw_cy_differential", LABEL, case_idx));
            result = Err(anyhow::anyhow!(
                "case={case_idx} CY round-trip rejected proxy CW output: \
                 error_code={} CVV={proxy_cvv} PAN={pan} expiry={expiry} svc={service_code}",
                String::from_utf8_lossy(&proxy_cy.error_code),
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK PAN_len={pan_len} svc={service_code} CVV={proxy_cvv}");
    }

    // Always tear down, even on assertion failure above.
    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;

    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── MAC M6/M8 (live differential + verify round-trip) ─────────────────────────

/// Wire label for the MAK in this test. `parse_legacy_key` reads the 'U' prefix
/// + 32H as a double-length key; the harness maps this string → the live ARN.
const MAK_WIRE_LABEL: &str = "U0000000000000000000000000000000A";

/// Random hex message of `byte_len` bytes (uppercase, two chars per byte).
fn gen_hex_message(rng: &mut StdRng, byte_len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(byte_len * 2);
    for _ in 0..byte_len {
        let b: u8 = rng.random_range(0..=255_u8);
        s.push(char::from(HEX[(b >> 4) as usize]));
        s.push(char::from(HEX[(b & 0x0F) as usize]));
    }
    s
}

/// Encode an M6 (generate) wire frame per PUGD0537-004 Rev A p.363.
///
/// Wire: Mode(1N '0') || InputFormat(1N '1' hex) || MACSize(1N) || MACAlgo(1N)
///       || PadMethod(1N '1') || KeyType(3H, consumed) || Key || MsgLen(4H) || Msg(hex)
///
/// Written from the manual, independent of the handler's decoder — a wrong
/// offset in either feeds APC different bytes and the MACs diverge.
fn encode_m6(key_label: &str, algo: u8, mac_size: u8, msg_hex: &str) -> Vec<u8> {
    let mut v = vec![b'0', b'1', mac_size, algo, b'1'];
    v.extend_from_slice(b"003"); // key type 3H — consumed by the handler
    v.extend_from_slice(key_label.as_bytes());
    let byte_count = msg_hex.len() / 2;
    v.extend_from_slice(format!("{byte_count:04X}").as_bytes());
    v.extend_from_slice(msg_hex.as_bytes());
    v
}

/// M8 (verify) = the M6 frame with the MAC appended.
fn encode_m8(key_label: &str, algo: u8, mac_size: u8, msg_hex: &str, mac_hex: &str) -> Vec<u8> {
    let mut v = encode_m6(key_label, algo, mac_size, msg_hex);
    v.extend_from_slice(mac_hex.as_bytes());
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn mac_m6_m8_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }

    // crypto = apc        (differential vs APC generate_mac — single implementation)
    // wire   = diff-xprov (manual-sourced M6 encoder vs corpus handler;
    //                      length-randomised message exposes fixed-offset bugs)
    eprintln!("mac_m6_m8_differential: grounding crypto=apc wire=diff-xprov(length-randomised)");

    let (cpc, data) = aws_clients().await;

    // ISO 9797-1 Algorithm 3 (Retail MAC) with a double-length TDES MAK.
    let specs = [KeySpec {
        role: "MAK",
        wire_label: MAK_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31M3Iso97973MacKey,
        modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let mak_arn = keys.arn("MAK").to_string();
    let mak_label = keys.wire_label("MAK").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let m6_handler = registry.get(b"M6").expect("M6 handler registered");
    let m8_handler = registry.get(b"M8").expect("M8 handler registered");

    const LABEL: &str = "mac_m6_m8";
    let run = cases_to_run();
    eprintln!(
        "mac_m6_m8_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        // Message length (whole bytes), edge-biased over its bounds. Bounds: 1..32.
        // Interesting edges cluster around the 8-byte DES block boundary that
        // ISO 9797 pads/chains on: 1 (min), 7/8/9 (block ±1), 16 (two blocks),
        // 24 (three), 32 (max).
        let msg_bytes = edge_biased(&mut rng, 1, 32, &[1, 7, 8, 9, 16, 24, 32]);
        let msg_hex = gen_hex_message(&mut rng, msg_bytes);

        // 1) M6 generate via proxy. algo '3' = ISO9797 ALG3; MAC size '0' = a
        //    4-byte (8H) MAC. APC's generate_mac returns a 4-byte MAC for
        //    ISO9797_ALGORITHM3 (verified live), so '0' is the faithful size;
        //    '1' (8-byte) would have the proxy truncate APC's 4-byte output and
        //    is a separate, unsupported-by-APC case.
        let m6_wire = encode_m6(&mak_label, b'3', b'0', &msg_hex);
        let proxy_m6 = m6_handler.handle(b"M6", &m6_wire, &state).await;
        if &proxy_m6.error_code != b"00" {
            eprintln!("{}", replay_hint("mac_m6_m8_differential", LABEL, case_idx));
            result = Err(anyhow::anyhow!(
                "case={case_idx} M6 error_code={} (msg_bytes={msg_bytes})",
                String::from_utf8_lossy(&proxy_m6.error_code),
            ));
            break;
        }
        let proxy_mac = String::from_utf8(proxy_m6.payload.to_vec())?;

        // 2) Oracle: direct APC generate_mac with the same key + message.
        let oracle = data
            .generate_mac()
            .key_identifier(&mak_arn)
            .message_data(&msg_hex)
            .generation_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm3))
            .send()
            .await?;
        let oracle_mac = oracle.mac().to_string();

        if !proxy_mac.eq_ignore_ascii_case(&oracle_mac) {
            eprintln!("{}", replay_hint("mac_m6_m8_differential", LABEL, case_idx));
            result = Err(anyhow::anyhow!(
                "case={case_idx} M6 differential mismatch: proxy={proxy_mac} oracle={oracle_mac} \
                 msg_bytes={msg_bytes} msg={msg_hex}"
            ));
            break;
        }

        // 3) M8 round-trip: the proxy's own M8 verifier must accept the MAC M6 made.
        let m8_wire = encode_m8(&mak_label, b'3', b'0', &msg_hex, &proxy_mac);
        let proxy_m8 = m8_handler.handle(b"M8", &m8_wire, &state).await;
        if &proxy_m8.error_code != b"00" {
            eprintln!("{}", replay_hint("mac_m6_m8_differential", LABEL, case_idx));
            result = Err(anyhow::anyhow!(
                "case={case_idx} M8 round-trip rejected proxy M6 MAC: error_code={} mac={proxy_mac}",
                String::from_utf8_lossy(&proxy_m8.error_code),
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK msg_bytes={msg_bytes} MAC={proxy_mac}");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;

    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── MAC C2/C4 (live differential + verify round-trip) ─────────────────────────
//
// C2/C4 share the APC mapping with M6/M8 but have a DISTINCT wire header
// (PUGD0537-004 p.583): Block Number, Key Type, MAC generation Mode, Message
// Type — vs M6's Mode/InputFormat/MACSize/MACAlgo/PadMethod/KeyType. So the C2
// wire parse needs its own differential. The MAC generation Mode selects the
// algorithm: '0' = X9.9 → ISO9797 Algorithm 1; '1' = X9.19 → ISO9797 Algorithm 3.

const TAK_M1_WIRE_LABEL: &str = "U0000000000000000000000000000000B";
const TAK_M3_WIRE_LABEL: &str = "U0000000000000000000000000000000C";

/// Encode a C2 (generate) wire frame per PUGD0537-004 Rev A p.583.
///
/// Wire: BlockNumber(1N '0') || KeyType(1N '0'=TAK) || MACMode(1N) ||
///       MessageType(1N '1'=hex) || Key || MsgLen(4H) || Msg(hex)
fn encode_c2(key_label: &str, mac_mode: u8, msg_hex: &str) -> Vec<u8> {
    let mut v = vec![b'0', b'0', mac_mode, b'1'];
    v.extend_from_slice(key_label.as_bytes());
    let byte_count = msg_hex.len() / 2;
    v.extend_from_slice(format!("{byte_count:04X}").as_bytes());
    v.extend_from_slice(msg_hex.as_bytes());
    v
}

/// C4 (verify) = the C2 frame with the 8H (4-byte) MAC appended.
fn encode_c4(key_label: &str, mac_mode: u8, msg_hex: &str, mac_hex: &str) -> Vec<u8> {
    let mut v = encode_c2(key_label, mac_mode, msg_hex);
    v.extend_from_slice(mac_hex.as_bytes());
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn mac_c2_c4_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }

    // crypto = apc        (differential vs APC generate_mac)
    // wire   = diff-xprov (manual-sourced C2 encoder vs corpus handler;
    //                      mode + length randomised)
    eprintln!(
        "mac_c2_c4_differential: grounding crypto=apc wire=diff-xprov(mode+length-randomised)"
    );

    let (cpc, data) = aws_clients().await;

    // One key per algorithm: X9.9/ALG1 → M1 key; X9.19/ALG3 → M3 key.
    let specs = [
        KeySpec {
            role: "TAK_M1",
            wire_label: TAK_M1_WIRE_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31M1Iso97971MacKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
        KeySpec {
            role: "TAK_M3",
            wire_label: TAK_M3_WIRE_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31M3Iso97973MacKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
    ];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let arn_m1 = keys.arn("TAK_M1").to_string();
    let arn_m3 = keys.arn("TAK_M3").to_string();
    let label_m1 = keys.wire_label("TAK_M1").to_string();
    let label_m3 = keys.wire_label("TAK_M3").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let c2_handler = registry.get(b"C2").expect("C2 handler registered");
    let c4_handler = registry.get(b"C4").expect("C4 handler registered");

    const LABEL: &str = "mac_c2_c4";
    let run = cases_to_run();
    eprintln!(
        "mac_c2_c4_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        // Edge over both MAC modes (algorithms); edge-biased message length.
        let alg3 = rng.random_bool(0.5);
        let (mac_mode, key_label, key_arn, oracle_algo) = if alg3 {
            (b'1', &label_m3, &arn_m3, MacAlgorithm::Iso9797Algorithm3)
        } else {
            (b'0', &label_m1, &arn_m1, MacAlgorithm::Iso9797Algorithm1)
        };
        let msg_bytes = edge_biased(&mut rng, 1, 32, &[1, 7, 8, 9, 16, 24, 32]);
        let msg_hex = gen_hex_message(&mut rng, msg_bytes);

        // 1) C2 generate via proxy.
        let c2_wire = encode_c2(key_label, mac_mode, &msg_hex);
        let proxy_c2 = c2_handler.handle(b"C2", &c2_wire, &state).await;
        if &proxy_c2.error_code != b"00" {
            eprintln!("{}", replay_hint("mac_c2_c4_differential", LABEL, case_idx));
            result = Err(anyhow::anyhow!(
                "case={case_idx} C2 error_code={} (mode={} msg_bytes={msg_bytes})",
                String::from_utf8_lossy(&proxy_c2.error_code),
                mac_mode as char,
            ));
            break;
        }
        let proxy_mac = String::from_utf8(proxy_c2.payload.to_vec())?;

        // 2) Oracle: direct APC generate_mac with the matching algorithm.
        let oracle = data
            .generate_mac()
            .key_identifier(key_arn)
            .message_data(&msg_hex)
            .generation_attributes(MacAttributes::Algorithm(oracle_algo))
            .send()
            .await?;
        let oracle_mac = oracle.mac().to_string();

        if !proxy_mac.eq_ignore_ascii_case(&oracle_mac) {
            eprintln!("{}", replay_hint("mac_c2_c4_differential", LABEL, case_idx));
            result = Err(anyhow::anyhow!(
                "case={case_idx} C2 differential mismatch (mode={}): proxy={proxy_mac} \
                 oracle={oracle_mac} msg_bytes={msg_bytes} msg={msg_hex}",
                mac_mode as char,
            ));
            break;
        }

        // 3) C4 round-trip: the proxy's C4 verifier must accept the MAC C2 made.
        let c4_wire = encode_c4(key_label, mac_mode, &msg_hex, &proxy_mac);
        let proxy_c4 = c4_handler.handle(b"C4", &c4_wire, &state).await;
        if &proxy_c4.error_code != b"00" {
            eprintln!("{}", replay_hint("mac_c2_c4_differential", LABEL, case_idx));
            result = Err(anyhow::anyhow!(
                "case={case_idx} C4 round-trip rejected proxy C2 MAC: error_code={} mac={proxy_mac}",
                String::from_utf8_lossy(&proxy_c4.error_code),
            ));
            break;
        }

        eprintln!(
            "case={case_idx:02} OK mode={} alg={} msg_bytes={msg_bytes} MAC={proxy_mac}",
            mac_mode as char,
            if alg3 { "ALG3" } else { "ALG1" },
        );
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;

    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── PIN translate CA/CC (live differential, format-canonicalized) ─────────────
//
// CC translates a PIN block ZPK->ZPK; CA does TPK->ZPK (identical wire when the
// destination is a ZPK with no DUKPT key flag). Wire (PUGD0537-004 p.282/285):
// source key || dest key || Max PIN Length(2N) || source PIN block(16H) ||
// source fmt code(2N) || dest fmt code(2N) || PAN(12N). Format codes are the edge
// axis: 01=ISO0, 47=ISO3 (both PAN-based and generatable).
//
// SUBTLETY: ISO 9564-1 Format 3 uses RANDOM fill, so translating the same input
// to Format 3 twice yields different ciphertext — a naive proxy-vs-oracle
// compare would fail spuriously. Instead we canonicalize: decode both the
// proxy's output and the original input down to deterministic Format 0 under a
// shared CANON key, and compare those. This validates the proxy's full translate
// (source-format parse + dest-format encode) for any format combo, immune to the
// random fill. A valid encrypted input block is minted per case via
// generate_pin_data (APC rejects malformed blocks).

const SRC_ZPK_WIRE_LABEL: &str = "U0000000000000000000000000000000D";
const DST_ZPK_WIRE_LABEL: &str = "U0000000000000000000000000000000E";

/// (wire format code, APC generate/pin-block format, short name) for a format
/// index: 0 -> ISO format 0 (code "01"); 1 -> ISO format 3 (code "47").
fn translate_fmt(idx: usize) -> (&'static str, PinBlockFormatForPinData, &'static str) {
    if idx == 0 {
        ("01", PinBlockFormatForPinData::IsoFormat0, "ISO0")
    } else {
        ("47", PinBlockFormatForPinData::IsoFormat3, "ISO3")
    }
}

/// APC `TranslationIsoFormats` for a format index + PAN (ISO 0 and 3 carry PAN).
fn translate_iso(idx: usize, pan: &str) -> anyhow::Result<TranslationIsoFormats> {
    let attrs = TranslationPinDataIsoFormat034::builder()
        .primary_account_number(pan)
        .build()?;
    Ok(if idx == 0 {
        TranslationIsoFormats::IsoFormat0(attrs)
    } else {
        TranslationIsoFormats::IsoFormat3(attrs)
    })
}

/// Encode a CC/CA static translate frame (ZPK dest, no DUKPT flag) per
/// PUGD0537-004 p.282/285.
fn encode_translate(
    src_label: &str,
    dst_label: &str,
    pin_block: &str,
    src_fmt_code: &str,
    dst_fmt_code: &str,
    pan: &str,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(src_label.as_bytes());
    v.extend_from_slice(dst_label.as_bytes());
    v.extend_from_slice(b"12"); // Max PIN Length (2N), consumed
    v.extend_from_slice(pin_block.as_bytes()); // 16H source PIN block
    v.extend_from_slice(src_fmt_code.as_bytes());
    v.extend_from_slice(dst_fmt_code.as_bytes());
    v.extend_from_slice(pan.as_bytes()); // 12N
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn pin_translate_ca_cc_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }

    eprintln!(
        "pin_translate_ca_cc_differential: grounding crypto=apc \
         wire=diff-xprov(format-code+cmd-randomised, Format-0-canonicalized)"
    );

    let (cpc, data) = aws_clients().await;

    let zpk_modes = || {
        KeyModesOfUse::builder()
            .encrypt(true)
            .decrypt(true)
            .wrap(true)
            .unwrap(true)
            .build()
    };
    let specs = [
        KeySpec {
            role: "SRC_ZPK",
            wire_label: SRC_ZPK_WIRE_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31P0PinEncryptionKey,
            modes: zpk_modes(),
        },
        KeySpec {
            role: "DST_ZPK",
            wire_label: DST_ZPK_WIRE_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31P0PinEncryptionKey,
            modes: zpk_modes(),
        },
        KeySpec {
            role: "CANON_ZPK",
            wire_label: "CANON_UNUSED_IN_WIRE",
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31P0PinEncryptionKey,
            modes: zpk_modes(),
        },
        KeySpec {
            role: "PGK",
            wire_label: "PGK_UNUSED_IN_WIRE",
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V2VisaPinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
    ];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let src_arn = keys.arn("SRC_ZPK").to_string();
    let dst_arn = keys.arn("DST_ZPK").to_string();
    let canon_arn = keys.arn("CANON_ZPK").to_string();
    let pgk_arn = keys.arn("PGK").to_string();
    let src_label = keys.wire_label("SRC_ZPK").to_string();
    let dst_label = keys.wire_label("DST_ZPK").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let cc_handler = registry.get(b"CC").expect("CC handler registered");
    let ca_handler = registry.get(b"CA").expect("CA handler registered");

    const LABEL: &str = "pin_translate_ca_cc";
    let run = cases_to_run();
    eprintln!(
        "pin_translate_ca_cc_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let src_idx = rng.random_range(0..2_usize);
        let dst_idx = rng.random_range(0..2_usize);
        let use_ca = rng.random_bool(0.5);
        let (src_code, src_gen_fmt, src_name) = translate_fmt(src_idx);
        let (dst_code, _dst_gen_fmt, dst_name) = translate_fmt(dst_idx);

        // Mint a valid source-ZPK-encrypted PIN block in the source format.
        let gen = data
            .generate_pin_data()
            .generation_key_identifier(&pgk_arn)
            .encryption_key_identifier(&src_arn)
            .primary_account_number(&pan)
            .pin_block_format(src_gen_fmt)
            .generation_attributes(PinGenerationAttributes::VisaPin(
                VisaPin::builder().pin_verification_key_index(1).build()?,
            ))
            .send()
            .await?;
        let input_block = gen.encrypted_pin_block().to_string();

        // Proxy translate (CA or CC), source -> dest.
        let (cmd, handler): (&[u8], _) = if use_ca {
            (b"CA", &ca_handler)
        } else {
            (b"CC", &cc_handler)
        };
        let wire = encode_translate(
            &src_label,
            &dst_label,
            &input_block,
            src_code,
            dst_code,
            &pan,
        );
        let proxy = handler.handle(cmd, &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("pin_translate_ca_cc_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} {} error_code={} (src={src_name} dst={dst_name} pan={pan})",
                String::from_utf8_lossy(cmd),
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }
        let proxy_block = String::from_utf8(proxy.payload.to_vec())?;

        // Canonicalize both to Format 0 under CANON and compare (immune to ISO-3
        // random fill): decode the proxy's dst-format output, and the original
        // source-format input, both down to deterministic Format 0.
        let proxy_canon = data
            .translate_pin_data()
            .incoming_key_identifier(&dst_arn)
            .outgoing_key_identifier(&canon_arn)
            .encrypted_pin_block(&proxy_block)
            .incoming_translation_attributes(translate_iso(dst_idx, &pan)?)
            .outgoing_translation_attributes(translate_iso(0, &pan)?)
            .send()
            .await?;
        let ref_canon = data
            .translate_pin_data()
            .incoming_key_identifier(&src_arn)
            .outgoing_key_identifier(&canon_arn)
            .encrypted_pin_block(&input_block)
            .incoming_translation_attributes(translate_iso(src_idx, &pan)?)
            .outgoing_translation_attributes(translate_iso(0, &pan)?)
            .send()
            .await?;

        let proxy_c = proxy_canon.pin_block();
        let ref_c = ref_canon.pin_block();
        if !proxy_c.eq_ignore_ascii_case(ref_c) {
            eprintln!(
                "{}",
                replay_hint("pin_translate_ca_cc_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} {} PIN mismatch after canonicalization: proxy->{proxy_c} \
                 ref->{ref_c} (src={src_name} dst={dst_name} pan={pan})",
                String::from_utf8_lossy(cmd),
            ));
            break;
        }

        eprintln!(
            "case={case_idx:02} OK cmd={} src={src_name} dst={dst_name} pan={pan}",
            String::from_utf8_lossy(cmd),
        );
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;

    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── DUKPT PIN verify GO (live differential, IBM3624 3DES) ─────────────────────
//
// GO verifies a DUKPT-encrypted PIN against an IBM 3624 offset (PUGD0537-004
// p.349). Wire: Mode(1N) || BDK || PVK || KSN-descriptor(3H)+KSN || PIN block ||
// fmt code(2N) || check len(2N) || PAN(12N) || decim table(16H) || PIN
// validation data(12A) || offset(12H, left-justified F-padded).
//
// NOTE: this covers IBM3624 + 3DES DUKPT. The Visa-PVV sibling (GQ) is GATED
// (returns 68): APC's single-call verify_pin_data with DukptAttributes + VisaPin
// returns InternalServerException (500), reproducibly, across 3DES/AES and
// regions, while IBM3624 + DUKPT (this test) and non-DUKPT Visa PVV both work.
// See the GQ gating rationale in src/handlers/thales/dukpt_pin_verify_aes.rs.
//
// Verify has no deterministic output to diff, so the differential is on the
// VERDICT: a valid PIN is minted via generate_pin_data (IBM3624 natural PIN,
// offset 0) and translated to a DUKPT block; the proxy's GO verdict must match a
// direct APC verify_pin_data verdict (both accept). A wrong field offset in the
// proxy parse feeds APC garbage, which APC rejects -> verdicts diverge.

const GO_BDK_WIRE_LABEL: &str = "U00000000000000000000000000000010";
const GO_PVK_WIRE_LABEL: &str = "U00000000000000000000000000000011";
const GO_DECIM_TABLE: &str = "0123456789012345";

/// Encode a GO frame (IBM3624, 3DES DUKPT, ISO format 0) per PUGD0537-004 p.349.
#[allow(clippy::too_many_arguments)]
fn encode_go(
    bdk_label: &str,
    pvk_label: &str,
    ksn: &str,
    pin_block16: &str,
    pan: &str,
    decim: &str,
    pvid: &str,
    offset12: &str,
) -> Vec<u8> {
    let mut v = vec![b'0']; // Mode '0' = PIN verify only
    v.extend_from_slice(bdk_label.as_bytes());
    v.extend_from_slice(pvk_label.as_bytes());
    v.extend_from_slice(b"014"); // KSN descriptor: char0 ignored + "14"=0x14=20 nibbles (3DES)
    v.extend_from_slice(ksn.as_bytes()); // 20H
    v.extend_from_slice(pin_block16.as_bytes()); // 16H DUKPT-encrypted PIN block
    v.extend_from_slice(b"01"); // PIN Block Format Code (ISO0)
    v.extend_from_slice(b"04"); // Check Length (PIN length 4)
    v.extend_from_slice(pan.as_bytes()); // 12N
    v.extend_from_slice(decim.as_bytes()); // 16H decimalization table
    v.extend_from_slice(pvid.as_bytes()); // 12A PIN validation data
    v.extend_from_slice(offset12.as_bytes()); // 12H offset
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn dukpt_pin_verify_go_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }

    eprintln!(
        "dukpt_pin_verify_go_differential: grounding crypto=apc \
         wire=diff-xprov(IBM3624 3DES DUKPT; verdict differential)"
    );

    let (cpc, data) = aws_clients().await;

    let specs = [
        KeySpec {
            role: "BDK",
            wire_label: GO_BDK_WIRE_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31B0BaseDerivationKey,
            modes: KeyModesOfUse::builder().derive_key(true).build(),
        },
        KeySpec {
            role: "PVK",
            wire_label: GO_PVK_WIRE_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V1Ibm3624PinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
        KeySpec {
            role: "ZPK",
            wire_label: "ZPK_UNUSED_IN_WIRE",
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31P0PinEncryptionKey,
            modes: KeyModesOfUse::builder()
                .encrypt(true)
                .decrypt(true)
                .wrap(true)
                .unwrap(true)
                .build(),
        },
    ];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let bdk_arn = keys.arn("BDK").to_string();
    let pvk_arn = keys.arn("PVK").to_string();
    let zpk_arn = keys.arn("ZPK").to_string();
    let bdk_label = keys.wire_label("BDK").to_string();
    let pvk_label = keys.wire_label("PVK").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let go_handler = registry.get(b"GO").expect("GO handler registered");

    const LABEL: &str = "dukpt_pin_verify_go";
    let run = cases_to_run();
    eprintln!(
        "dukpt_pin_verify_go_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let pvid = pan.clone(); // PIN validation data: 12 digits, consistent per case
                                // KSN counter varied (low bits) to exercise different DUKPT derivations.
        let ctr = edge_biased(&mut rng, 1, 0xFFFF, &[1, 2, 0xFFFF]);
        let ksn = format!("FFFF9876543210{:06X}", 0xE0_0000 | ctr); // 20 hex, 3DES KSN

        // 1) Mint an IBM3624 natural-PIN block under the ZPK (offset 0).
        let gen = data
            .generate_pin_data()
            .generation_key_identifier(&pvk_arn)
            .encryption_key_identifier(&zpk_arn)
            .primary_account_number(&pan)
            .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
            .generation_attributes(PinGenerationAttributes::Ibm3624NaturalPin(
                Ibm3624NaturalPin::builder()
                    .decimalization_table(GO_DECIM_TABLE)
                    .pin_validation_data(&pvid)
                    .pin_validation_data_pad_character("F")
                    .build()?,
            ))
            .send()
            .await?;
        let zblk = gen.encrypted_pin_block().to_string();

        // 2) Translate ZPK -> BDK as a DUKPT-encrypted block at this KSN.
        let dblk = data
            .translate_pin_data()
            .incoming_key_identifier(&zpk_arn)
            .outgoing_key_identifier(&bdk_arn)
            .encrypted_pin_block(&zblk)
            .incoming_translation_attributes(translate_iso(0, &pan)?)
            .outgoing_translation_attributes(translate_iso(0, &pan)?)
            .outgoing_dukpt_attributes(
                aws_sdk_paymentcryptographydata::types::DukptDerivationAttributes::builder()
                    .key_serial_number(&ksn)
                    .dukpt_key_derivation_type(DukptDerivationType::Tdes2Key)
                    .build()?,
            )
            .send()
            .await?;
        let dblk = dblk.pin_block().to_string();

        // Natural PIN -> offset is all-zero for the PIN length; wire offset is
        // 12H left-justified, F-padded.
        let offset_wire = "0000FFFFFFFF";

        // 3) Proxy GO verdict.
        let wire = encode_go(
            &bdk_label,
            &pvk_label,
            &ksn,
            &dblk,
            &pan,
            GO_DECIM_TABLE,
            &pvid,
            offset_wire,
        );
        let proxy = go_handler.handle(b"GO", &wire, &state).await;
        let proxy_pass = &proxy.error_code == b"00";

        // 4) Oracle verdict: direct APC verify_pin_data (IBM3624 + DUKPT).
        let oracle = data
            .verify_pin_data()
            .verification_key_identifier(&pvk_arn)
            .encryption_key_identifier(&bdk_arn)
            .encrypted_pin_block(&dblk)
            .primary_account_number(&pan)
            .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
            .verification_attributes(PinVerificationAttributes::Ibm3624Pin(
                Ibm3624PinVerification::builder()
                    .decimalization_table(GO_DECIM_TABLE)
                    .pin_validation_data(&pvid)
                    .pin_validation_data_pad_character("F")
                    .pin_offset("0000")
                    .build()?,
            ))
            .dukpt_attributes(
                DukptAttributes::builder()
                    .key_serial_number(&ksn)
                    .dukpt_derivation_type(DukptDerivationType::Tdes2Key)
                    .build()?,
            )
            .send()
            .await;
        let oracle_pass = oracle.is_ok();

        if proxy_pass != oracle_pass {
            eprintln!(
                "{}",
                replay_hint("dukpt_pin_verify_go_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} GO verdict mismatch: proxy_pass={proxy_pass} \
                 (error_code={}) oracle_pass={oracle_pass} pan={pan} ksn={ksn}",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }
        if !oracle_pass {
            eprintln!(
                "{}",
                replay_hint("dukpt_pin_verify_go_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} GO: constructed PIN should verify but BOTH proxy and oracle \
                 rejected it (pan={pan} ksn={ksn}) — likely a setup/offset error"
            ));
            break;
        }

        eprintln!(
            "case={case_idx:02} OK pan={pan} ksn=..{} verdict=pass",
            &ksn[14..]
        );
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;

    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── Legacy MAC MA/MC + MK/MM (live differential + verify round-trip) ──────────
//
// Un-audited handler (PUGD0538). Two wire styles for the ISO 9797-1 Algorithm 1
// MAC: MA/MC are '~'-terminated; MK/MM are 3H-length-prefixed binary. The handler
// TRUNCATES APC's MAC to 8H (4 bytes) to match the Thales wire, then its own
// verify (MC/MM) hands that truncated MAC straight to APC verify_mac. This checks
// both: proxy MAC == APC's MAC prefix, and the truncated-MAC round-trip verifies.

const LEGACY_TAK_M1_LABEL: &str = "U000000000000000000000000000000F1";

/// Random data bytes; if `exclude_tilde`, avoids 0x7E (the MA/MC terminator).
fn gen_data_bytes(rng: &mut StdRng, len: usize, exclude_tilde: bool) -> Vec<u8> {
    (0..len)
        .map(|_| {
            let b = rng.random_range(0..=255_u8);
            if exclude_tilde && b == b'~' {
                b'.'
            } else {
                b
            }
        })
        .collect()
}

fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

fn encode_ma(key_label: &str, data: &[u8]) -> Vec<u8> {
    let mut v = key_label.as_bytes().to_vec();
    v.extend_from_slice(data);
    v.push(b'~');
    v
}
fn encode_mc(key_label: &str, mac_hex: &str, data: &[u8]) -> Vec<u8> {
    let mut v = key_label.as_bytes().to_vec();
    v.extend_from_slice(mac_hex.as_bytes());
    v.extend_from_slice(data);
    v.push(b'~');
    v
}
fn encode_mk(key_label: &str, data: &[u8]) -> Vec<u8> {
    let mut v = key_label.as_bytes().to_vec();
    v.extend_from_slice(format!("{:03X}", data.len()).as_bytes());
    v.extend_from_slice(data);
    v
}
fn encode_mm(key_label: &str, mac_hex: &str, data: &[u8]) -> Vec<u8> {
    let mut v = key_label.as_bytes().to_vec();
    v.extend_from_slice(mac_hex.as_bytes());
    v.extend_from_slice(format!("{:03X}", data.len()).as_bytes());
    v.extend_from_slice(data);
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn legacy_mac_ma_mc_mk_mm_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!("legacy_mac_ma_mc_mk_mm_differential: grounding crypto=apc wire=diff-xprov(style+length-randomised)");

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "TAK",
        wire_label: LEGACY_TAK_M1_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31M1Iso97971MacKey,
        modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let tak_arn = keys.arn("TAK").to_string();
    let tak_label = keys.wire_label("TAK").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let ma = registry.get(b"MA").expect("MA registered");
    let mc = registry.get(b"MC").expect("MC registered");
    let mk = registry.get(b"MK").expect("MK registered");
    let mm = registry.get(b"MM").expect("MM registered");

    const LABEL: &str = "legacy_mac_ma_mc_mk_mm";
    let run = cases_to_run();
    eprintln!(
        "legacy_mac_ma_mc_mk_mm_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );
    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let terminated = rng.random_bool(0.5); // MA/MC vs MK/MM
        let len = edge_biased(&mut rng, 1, 32, &[1, 7, 8, 9, 16, 32]);
        let data_bytes = gen_data_bytes(&mut rng, len, terminated);
        let data_hex = hex_upper(&data_bytes);
        let style = if terminated { "MA/MC" } else { "MK/MM" };

        // 1) generate via proxy
        let (gen_wire, gen_h, gname): (Vec<u8>, _, &[u8]) = if terminated {
            (encode_ma(&tak_label, &data_bytes), &ma, b"MA".as_slice())
        } else {
            (encode_mk(&tak_label, &data_bytes), &mk, b"MK".as_slice())
        };
        let proxy_gen = gen_h.handle(gname, &gen_wire, &state).await;
        if &proxy_gen.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("legacy_mac_ma_mc_mk_mm_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} {style} generate error_code={} (len={len})",
                String::from_utf8_lossy(&proxy_gen.error_code),
            ));
            break;
        }
        let proxy_mac = String::from_utf8(proxy_gen.payload.to_vec())?;

        // 2) oracle: APC generate_mac ALG1; proxy truncates to 8H, so compare prefix
        let oracle = data
            .generate_mac()
            .key_identifier(&tak_arn)
            .message_data(&data_hex)
            .generation_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm1))
            .send()
            .await?;
        let oracle_mac = oracle.mac().to_string();
        let oracle_prefix = &oracle_mac[..proxy_mac.len().min(oracle_mac.len())];
        if !proxy_mac.eq_ignore_ascii_case(oracle_prefix) {
            eprintln!(
                "{}",
                replay_hint("legacy_mac_ma_mc_mk_mm_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} {style} MAC mismatch: proxy={proxy_mac} apc_prefix={oracle_prefix} (apc_full={oracle_mac}) len={len}"
            ));
            break;
        }

        // 3) verify round-trip (MC or MM) — does APC verify_mac accept the truncated 8H MAC?
        let (ver_wire, ver_h, vname): (Vec<u8>, _, &[u8]) = if terminated {
            (
                encode_mc(&tak_label, &proxy_mac, &data_bytes),
                &mc,
                b"MC".as_slice(),
            )
        } else {
            (
                encode_mm(&tak_label, &proxy_mac, &data_bytes),
                &mm,
                b"MM".as_slice(),
            )
        };
        let proxy_ver = ver_h.handle(vname, &ver_wire, &state).await;
        if &proxy_ver.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("legacy_mac_ma_mc_mk_mm_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} {style} verify round-trip rejected proxy MAC: error_code={} mac={proxy_mac} (apc_full={oracle_mac})",
                String::from_utf8_lossy(&proxy_ver.error_code),
            ));
            break;
        }

        eprintln!(
            "case={case_idx:02} OK style={style} len={len} MAC={proxy_mac} apc_full={oracle_mac}"
        );
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── DUKPT MAC GW (live differential + verify round-trip) ──────────────────────
//
// Un-audited handler (PUGD0538). GW generate/verify a DUKPT MAC. Header: Mode +
// InFmt + MACSize + MACAlgo + PadMethod (5×1N), then BDK + KSN-descriptor+KSN +
// MsgLen(4H) + message. MAC size '0'=4 bytes, '1'=2 bytes (half). Algorithm:
// '1'=Alg1, '3'=Alg3, '6'=CMAC. The handler hardcodes APC DukptKeyVariant=Request
// (payShield GW does not carry direction — a documented assumption); the oracle
// uses the same variant, so this proves proxy==APC under that assumption, not that
// Request is what a real payShield would derive.

const GW_BDK_LABEL: &str = "U000000000000000000000000000000B7";

fn encode_gw(
    mode: u8,
    mac_size: u8,
    algo: u8,
    bdk_label: &str,
    ksn: &str,
    msg_hex: &str,
    mac_hex: Option<&str>,
) -> Vec<u8> {
    let mut v = vec![mode, b'1', mac_size, algo, b'1']; // pad method '1', consumed
    v.extend_from_slice(bdk_label.as_bytes());
    v.extend_from_slice(b"014"); // KSN descriptor: 0x14 = 20 nibbles (3DES)
    v.extend_from_slice(ksn.as_bytes());
    v.extend_from_slice(format!("{:04X}", msg_hex.len() / 2).as_bytes());
    v.extend_from_slice(msg_hex.as_bytes());
    if let Some(m) = mac_hex {
        v.extend_from_slice(m.as_bytes());
    }
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn dukpt_mac_gw_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!("dukpt_mac_gw_differential: grounding crypto=apc wire=diff-xprov(algo+size+length-randomised)");

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "BDK",
        wire_label: GW_BDK_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31B0BaseDerivationKey,
        modes: KeyModesOfUse::builder().derive_key(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let bdk_arn = keys.arn("BDK").to_string();
    let bdk_label = keys.wire_label("BDK").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let gw = registry.get(b"GW").expect("GW registered");

    const LABEL: &str = "dukpt_mac_gw";
    let ksn = "FFFF9876543210E00001"; // 3DES DUKPT, 20H
    let run = cases_to_run();
    eprintln!(
        "dukpt_mac_gw_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );
    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        // Algorithm: '1'=Alg1, '3'=Alg3, '6'=CMAC.
        let (algo_byte, oracle_algo): (u8, fn(MacAlgorithmDukpt) -> MacAttributes) =
            match rng.random_range(0..3_u8) {
                0 => (b'1', MacAttributes::DukptIso9797Algorithm1),
                1 => (b'3', MacAttributes::DukptIso9797Algorithm3),
                _ => (b'6', MacAttributes::DukptCmac),
            };
        let mac_size_byte = if rng.random_bool(0.5) { b'0' } else { b'1' }; // 4 or 2 bytes
        let mac_size_chars = if mac_size_byte == b'0' { 8 } else { 4 };
        // APC DUKPT generate_mac requires message length 8..4096 bytes. The CBC-MAC
        // variants (ALG1, ALG3) additionally require a multiple of 8 bytes
        // (block-aligned — APC does not pad for them); CMAC accepts any length.
        let msg_bytes = if algo_byte == b'6' {
            edge_biased(&mut rng, 8, 64, &[8, 9, 16, 32, 64])
        } else {
            8 * edge_biased(&mut rng, 1, 8, &[1, 2, 4, 8])
        };
        let msg_hex = gen_hex_message(&mut rng, msg_bytes);

        let dukpt = MacAlgorithmDukpt::builder()
            .key_serial_number(ksn)
            .dukpt_key_variant(DukptKeyVariant::Request)
            .dukpt_derivation_type(DukptDerivationType::Tdes2Key)
            .build()?;

        // 1) proxy generate
        let gen_wire = encode_gw(
            b'0',
            mac_size_byte,
            algo_byte,
            &bdk_label,
            ksn,
            &msg_hex,
            None,
        );
        let proxy_gen = gw.handle(b"GW", &gen_wire, &state).await;
        if &proxy_gen.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("dukpt_mac_gw_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} GW generate error_code={} (algo={} size={} msg_bytes={msg_bytes})",
                String::from_utf8_lossy(&proxy_gen.error_code),
                algo_byte as char,
                mac_size_byte as char,
            ));
            break;
        }
        let proxy_mac = String::from_utf8(proxy_gen.payload.to_vec())?;

        // 2) oracle: APC generate_mac with matching DUKPT algorithm + variant
        let oracle = data
            .generate_mac()
            .key_identifier(&bdk_arn)
            .message_data(&msg_hex)
            .generation_attributes(oracle_algo(dukpt.clone()))
            .send()
            .await?;
        let oracle_mac = oracle.mac().to_string();
        let oracle_prefix = &oracle_mac[..mac_size_chars.min(oracle_mac.len())];
        if !proxy_mac.eq_ignore_ascii_case(oracle_prefix) {
            eprintln!(
                "{}",
                replay_hint("dukpt_mac_gw_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} GW MAC mismatch (algo={} size={}): proxy={proxy_mac} apc_prefix={oracle_prefix} (apc_full={oracle_mac})",
                algo_byte as char,
                mac_size_byte as char,
            ));
            break;
        }

        // 3) verify round-trip
        let ver_wire = encode_gw(
            b'1',
            mac_size_byte,
            algo_byte,
            &bdk_label,
            ksn,
            &msg_hex,
            Some(&proxy_mac),
        );
        let proxy_ver = gw.handle(b"GW", &ver_wire, &state).await;
        if &proxy_ver.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("dukpt_mac_gw_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} GW verify round-trip rejected proxy MAC: error_code={} mac={proxy_mac} (apc_full={oracle_mac})",
                String::from_utf8_lossy(&proxy_ver.error_code),
            ));
            break;
        }

        eprintln!(
            "case={case_idx:02} OK algo={} size={} msg_bytes={msg_bytes} MAC={proxy_mac}",
            algo_byte as char, mac_size_byte as char,
        );
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}
