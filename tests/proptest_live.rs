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
// Several cases use a fail-fast `if err != "00" { (…, false) } else { … }` shape
// where the error branch is deliberately first; positive-first would bury the
// happy path under the check.
#![allow(clippy::if_not_else)]

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
    DukptKeyVariant, EncryptionDecryptionAttributes, EncryptionMode, Ibm3624NaturalPin,
    Ibm3624PinVerification, MacAlgorithm, MacAlgorithmDukpt, MacAttributes,
    PinBlockFormatForPinData, PinGenerationAttributes, PinVerificationAttributes,
    SymmetricEncryptionAttributes, TranslationIsoFormats, TranslationPinDataIsoFormat034, VisaPin,
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

// ── MAC translate MY (live differential: verify inbound + generate outbound) ──
//
// Un-audited handler (PUGD0537-004 p.371). MY verifies an inbound MAC under one
// key, then generates a new MAC under a second key for the same message. Header:
// per-direction MAC size + algorithm. Like GW, the inbound-verify step hands the
// (possibly truncated half) MAC straight to APC verify_mac.

const MY_IN_M1_LABEL: &str = "U000000000000000000000000000000C1";
const MY_OUT_M1_LABEL: &str = "U000000000000000000000000000000C2";

#[allow(clippy::too_many_arguments)]
fn encode_my(
    in_size: u8,
    out_size: u8,
    in_label: &str,
    out_label: &str,
    msg_hex: &str,
    inbound_mac: &str,
) -> Vec<u8> {
    // ALG1 ('1') for both directions in this test.
    let mut v = vec![b'0', b'1', in_size, b'1', b'1']; // mode, infmt, in size, in algo, in pad
    v.extend_from_slice(b"003"); // in key type (consumed)
    v.extend_from_slice(in_label.as_bytes());
    v.extend_from_slice(&[out_size, b'1', b'1']); // out size, out algo, out pad
    v.extend_from_slice(b"003"); // out key type (consumed)
    v.extend_from_slice(out_label.as_bytes());
    v.extend_from_slice(format!("{:04X}", msg_hex.len() / 2).as_bytes());
    v.extend_from_slice(msg_hex.as_bytes());
    v.extend_from_slice(inbound_mac.as_bytes());
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn mac_translate_my_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!("mac_translate_my_differential: grounding crypto=apc wire=diff-xprov(size+length-randomised, ALG1)");

    let (cpc, data) = aws_clients().await;
    let m1 = || KeyModesOfUse::builder().generate(true).verify(true).build();
    let specs = [
        KeySpec {
            role: "IN",
            wire_label: MY_IN_M1_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31M1Iso97971MacKey,
            modes: m1(),
        },
        KeySpec {
            role: "OUT",
            wire_label: MY_OUT_M1_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31M1Iso97971MacKey,
            modes: m1(),
        },
    ];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let in_arn = keys.arn("IN").to_string();
    let out_arn = keys.arn("OUT").to_string();
    let in_label = keys.wire_label("IN").to_string();
    let out_label = keys.wire_label("OUT").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let my = registry.get(b"MY").expect("MY registered");

    const LABEL: &str = "mac_translate_my";
    let run = cases_to_run();
    eprintln!(
        "mac_translate_my_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );
    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let in_size_byte = if rng.random_bool(0.5) { b'0' } else { b'1' };
        let out_size_byte = if rng.random_bool(0.5) { b'0' } else { b'1' };
        let in_chars = if in_size_byte == b'0' { 8 } else { 4 };
        let out_chars = if out_size_byte == b'0' { 8 } else { 4 };
        let msg_bytes = edge_biased(&mut rng, 1, 32, &[1, 7, 8, 16, 32]);
        let msg_hex = gen_hex_message(&mut rng, msg_bytes);

        // Setup: a valid inbound MAC under the IN key (truncated to in size).
        let in_full = data
            .generate_mac()
            .key_identifier(&in_arn)
            .message_data(&msg_hex)
            .generation_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm1))
            .send()
            .await?
            .mac()
            .to_string();
        let inbound_mac = in_full[..in_chars.min(in_full.len())].to_string();

        // Proxy MY: verify inbound + generate outbound.
        let wire = encode_my(
            in_size_byte,
            out_size_byte,
            &in_label,
            &out_label,
            &msg_hex,
            &inbound_mac,
        );
        let proxy = my.handle(b"MY", &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("mac_translate_my_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} MY error_code={} (in_size={} out_size={} msg_bytes={msg_bytes})",
                String::from_utf8_lossy(&proxy.error_code),
                in_size_byte as char,
                out_size_byte as char,
            ));
            break;
        }
        let proxy_out = String::from_utf8(proxy.payload.to_vec())?;

        // Oracle: APC generate_mac under the OUT key, truncated to out size.
        let out_full = data
            .generate_mac()
            .key_identifier(&out_arn)
            .message_data(&msg_hex)
            .generation_attributes(MacAttributes::Algorithm(MacAlgorithm::Iso9797Algorithm1))
            .send()
            .await?
            .mac()
            .to_string();
        let oracle_out = &out_full[..out_chars.min(out_full.len())];
        if !proxy_out.eq_ignore_ascii_case(oracle_out) {
            eprintln!(
                "{}",
                replay_hint("mac_translate_my_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} MY outbound mismatch: proxy={proxy_out} oracle={oracle_out} (in_size={} out_size={})",
                in_size_byte as char,
                out_size_byte as char,
            ));
            break;
        }

        eprintln!(
            "case={case_idx:02} OK in_size={} out_size={} msg_bytes={msg_bytes} out={proxy_out}",
            in_size_byte as char, out_size_byte as char,
        );
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── Legacy data encrypt/decrypt HE/HG (live differential + round-trip) ────────
//
// Un-audited handler (PUGD0538). HE encrypts and HG decrypts a single 64-bit
// block (16H) under a data key (TR31_D0), TDES-ECB. ECB is deterministic, so the
// HE differential is exact; HE→HG must recover the plaintext.

const HEHG_DEK_LABEL: &str = "U000000000000000000000000000000D5";

fn encode_he_hg(key_label: &str, data_hex: &str) -> Vec<u8> {
    let mut v = key_label.as_bytes().to_vec();
    v.extend_from_slice(data_hex.as_bytes());
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn encrypt_decrypt_he_hg_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!("encrypt_decrypt_he_hg_differential: grounding crypto=apc wire=diff-xprov(TDES-ECB 64-bit block)");

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "DEK",
        wire_label: HEHG_DEK_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31D0SymmetricDataEncryptionKey,
        // APC rejects encrypt+decrypt alone for a D0 key; NoRestrictions allows
        // both HE (encrypt) and HG (decrypt) under the one key.
        modes: KeyModesOfUse::builder().no_restrictions(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let dek_arn = keys.arn("DEK").to_string();
    let dek_label = keys.wire_label("DEK").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let he = registry.get(b"HE").expect("HE registered");
    let hg = registry.get(b"HG").expect("HG registered");

    const LABEL: &str = "encrypt_decrypt_he_hg";
    let run = cases_to_run();
    eprintln!(
        "encrypt_decrypt_he_hg_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );
    let ecb = || {
        EncryptionDecryptionAttributes::Symmetric(
            SymmetricEncryptionAttributes::builder()
                .mode(EncryptionMode::Ecb)
                .build()
                .expect("ecb attrs"),
        )
    };
    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        // One 64-bit block (8 bytes = 16 hex). Include all-zero / all-F edges.
        let plain = match rng.random_range(0..4_u8) {
            0 => "0000000000000000".to_string(),
            1 => "FFFFFFFFFFFFFFFF".to_string(),
            _ => gen_hex_message(&mut rng, 8),
        };

        // 1) HE encrypt via proxy
        let proxy_he = he
            .handle(b"HE", &encode_he_hg(&dek_label, &plain), &state)
            .await;
        if &proxy_he.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("encrypt_decrypt_he_hg_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} HE error_code={} (plain={plain})",
                String::from_utf8_lossy(&proxy_he.error_code),
            ));
            break;
        }
        let proxy_cipher = String::from_utf8(proxy_he.payload.to_vec())?;

        // 2) oracle: APC encrypt_data TDES-ECB (deterministic)
        let oracle = data
            .encrypt_data()
            .key_identifier(&dek_arn)
            .plain_text(&plain)
            .encryption_attributes(ecb())
            .send()
            .await?;
        let oracle_cipher = oracle.cipher_text().to_string();
        if !proxy_cipher.eq_ignore_ascii_case(&oracle_cipher) {
            eprintln!(
                "{}",
                replay_hint("encrypt_decrypt_he_hg_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} HE mismatch: proxy={proxy_cipher} oracle={oracle_cipher} plain={plain}"
            ));
            break;
        }

        // 3) HG decrypt round-trip → must recover the plaintext
        let proxy_hg = hg
            .handle(b"HG", &encode_he_hg(&dek_label, &proxy_cipher), &state)
            .await;
        if &proxy_hg.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("encrypt_decrypt_he_hg_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} HG error_code={} (cipher={proxy_cipher})",
                String::from_utf8_lossy(&proxy_hg.error_code),
            ));
            break;
        }
        let recovered = String::from_utf8(proxy_hg.payload.to_vec())?;
        if !recovered.eq_ignore_ascii_case(&plain) {
            eprintln!(
                "{}",
                replay_hint("encrypt_decrypt_he_hg_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} HE→HG round-trip mismatch: plain={plain} recovered={recovered}"
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK plain={plain} cipher={proxy_cipher}");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── Legacy single-length DUKPT PIN verify CK (live differential) ──────────────
//
// Un-audited handler (PUGD0538). CK verifies a DUKPT-encrypted PIN against an IBM
// 3624 offset (original single-length DUKPT, Tdes2Key). Wire: BDK + PVK + KSN
// descriptor(3H) + KSN(20H) + PIN block(16H) + check len(2N) + PAN(12N) + decim
// table(16H) + PIN validation data(12A) + offset(12H, F-padded). Verdict
// differential, like GO. (CM, the Visa-PVV sibling, is gated — same APC 500 as GQ.)

const CK_BDK_LABEL: &str = "U00000000000000000000000000000C10";
const CK_PVK_LABEL: &str = "U00000000000000000000000000000C11";

#[allow(clippy::too_many_arguments)]
fn encode_ck(
    bdk_label: &str,
    pvk_label: &str,
    ksn: &str,
    pin_block16: &str,
    pan: &str,
    decim: &str,
    pvid: &str,
    offset12: &str,
) -> Vec<u8> {
    let mut v = bdk_label.as_bytes().to_vec();
    v.extend_from_slice(pvk_label.as_bytes());
    v.extend_from_slice(b"000"); // KSN descriptor (3H, consumed)
    v.extend_from_slice(ksn.as_bytes()); // 20H
    v.extend_from_slice(pin_block16.as_bytes()); // 16H
    v.extend_from_slice(b"04"); // check length
    v.extend_from_slice(pan.as_bytes()); // 12N
    v.extend_from_slice(decim.as_bytes()); // 16H decimalization table
    v.extend_from_slice(pvid.as_bytes()); // 12A PIN validation data
    v.extend_from_slice(offset12.as_bytes()); // 12H offset
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn dukpt_pin_verify_ck_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!("dukpt_pin_verify_ck_differential: grounding crypto=apc wire=diff-xprov(IBM3624 single-length DUKPT; verdict)");

    let (cpc, data) = aws_clients().await;
    let specs = [
        KeySpec {
            role: "BDK",
            wire_label: CK_BDK_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31B0BaseDerivationKey,
            modes: KeyModesOfUse::builder().derive_key(true).build(),
        },
        KeySpec {
            role: "PVK",
            wire_label: CK_PVK_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V1Ibm3624PinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
        KeySpec {
            role: "ZPK",
            wire_label: "ZPK_UNUSED_IN_WIRE_CK",
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
    let ck = registry.get(b"CK").expect("CK registered");

    const LABEL: &str = "dukpt_pin_verify_ck";
    let ksn = "FFFF9876543210E00001"; // 3DES single-length DUKPT, 20H
    let run = cases_to_run();
    eprintln!(
        "dukpt_pin_verify_ck_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );
    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let pvid = pan.clone();

        // 1) IBM3624 natural-PIN block under the ZPK (offset 0).
        let zblk = data
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
            .await?
            .encrypted_pin_block()
            .to_string();

        // 2) Translate ZPK -> BDK DUKPT at this KSN.
        let dblk = data
            .translate_pin_data()
            .incoming_key_identifier(&zpk_arn)
            .outgoing_key_identifier(&bdk_arn)
            .encrypted_pin_block(&zblk)
            .incoming_translation_attributes(translate_iso(0, &pan)?)
            .outgoing_translation_attributes(translate_iso(0, &pan)?)
            .outgoing_dukpt_attributes(
                aws_sdk_paymentcryptographydata::types::DukptDerivationAttributes::builder()
                    .key_serial_number(ksn)
                    .dukpt_key_derivation_type(DukptDerivationType::Tdes2Key)
                    .build()?,
            )
            .send()
            .await?
            .pin_block()
            .to_string();

        let offset_wire = "0000FFFFFFFF"; // natural-PIN offset, F-padded to 12H

        // 3) Proxy CK verdict.
        let wire = encode_ck(
            &bdk_label,
            &pvk_label,
            ksn,
            &dblk,
            &pan,
            GO_DECIM_TABLE,
            &pvid,
            offset_wire,
        );
        let proxy = ck.handle(b"CK", &wire, &state).await;
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
                    .key_serial_number(ksn)
                    .dukpt_derivation_type(DukptDerivationType::Tdes2Key)
                    .build()?,
            )
            .send()
            .await;
        let oracle_pass = oracle.is_ok();

        if proxy_pass != oracle_pass {
            eprintln!(
                "{}",
                replay_hint("dukpt_pin_verify_ck_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} CK verdict mismatch: proxy_pass={proxy_pass} (error_code={}) oracle_pass={oracle_pass} pan={pan}",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }
        if !oracle_pass {
            eprintln!(
                "{}",
                replay_hint("dukpt_pin_verify_ck_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} CK: constructed PIN should verify but both rejected it (pan={pan})"
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK pan={pan} verdict=pass");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── EMV decrypt K0 (live differential, EMV-CBC round-trip) ────────────────────
//
// Un-audited handler (PUGD0537-004). K0 decrypts EMV-encrypted counters / app
// data under an IMK-ENC (E1) master key: APC derives an EMV session key from the
// master key + PAN/PSN + ATC, then CBC-decrypts. Wire (binary fields):
//   KeyType(3H ASCII) || Key || PAN+Seq(8B BCD) || ATC(2B) || DataLen(2B BE) ||
//   EncData(nB).
//
// Decrypt has a deterministic output, but a direct decrypt_data oracle would be
// the *same call* the handler makes — trivially equal, proving nothing about the
// wire parse. Instead the differential is a round-trip: APC encrypt_data (EMV-CBC,
// built from the field values) mints the ciphertext; the proxy's K0 must recover
// the original plaintext. A wrong field offset (PAN/PSN/ATC) derives a different
// session key, so K0 yields garbage or errors — proxy ≠ plaintext.

const K0_E1_WIRE_LABEL: &str = "U0000000000000000000000000000K0E1";

/// 16 BCD hex digits → 8 bytes. EMV Option A pre-format = "00" ‖ PAN(12) ‖ PSN(2)
/// (rightmost-16 of PAN‖PSN, left zero-padded), matching `decode_bcd_pan_seq`.
fn pan_seq_bcd(pan12: &str, seq2: &str) -> Vec<u8> {
    let hex = format!("00{pan12}{seq2}");
    assert_eq!(hex.len(), 16, "pan_seq_bcd: expected 16 BCD digits");
    hex_str_to_bytes(&hex)
}

/// Parse an even-length uppercase/lowercase hex string into bytes. Test-only.
fn hex_str_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex_str_to_bytes: odd length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Encode a K0 wire frame per PUGD0537-004. Binary PAN/ATC/len/data fields.
fn encode_k0(key_label: &str, pan_seq: &[u8], atc: [u8; 2], cipher_bytes: &[u8]) -> Vec<u8> {
    let mut v = b"00E".to_vec(); // key type 3H ASCII — consumed
    v.extend_from_slice(key_label.as_bytes());
    v.extend_from_slice(pan_seq); // 8B BCD
    v.extend_from_slice(&atc); // 2B ATC
    let len = u16::try_from(cipher_bytes.len()).expect("ciphertext < 64KiB");
    v.extend_from_slice(&len.to_be_bytes()); // 2B BE DataLen
    v.extend_from_slice(cipher_bytes); // nB ciphertext
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn emv_decrypt_k0_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "emv_decrypt_k0_differential: grounding crypto=apc \
         wire=diff-xprov(EMV-CBC encrypt→K0-decrypt round-trip)"
    );

    use aws_sdk_paymentcryptographydata::types::{
        EmvEncryptionAttributes, EmvEncryptionMode, EmvMajorKeyDerivationMode,
        EncryptionDecryptionAttributes,
    };

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "E1",
        wire_label: K0_E1_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31E1EmvMkeyConfidentiality,
        modes: KeyModesOfUse::builder().derive_key(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let e1_arn = keys.arn("E1").to_string();
    let e1_label = keys.wire_label("E1").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let k0 = registry.get(b"K0").expect("K0 handler registered");

    const LABEL: &str = "emv_decrypt_k0";
    let run = cases_to_run();
    eprintln!(
        "emv_decrypt_k0_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let seq = format!("{:02}", edge_biased(&mut rng, 0, 99, &[0, 1, 99]));
        // ATC (2B). Edge-biased over the 16-bit counter range.
        let atc_val = edge_biased(&mut rng, 0, 0xFFFF, &[1, 0x2A, 0xFFFF]) as u16;
        let atc = atc_val.to_be_bytes();
        let atc_hex = hex_upper(&atc); // 4 hex chars

        // CBC plaintext: whole TDES blocks (8B). Edge-biased over 1..4 blocks.
        let blocks = edge_biased(&mut rng, 1, 4, &[1, 2, 4]);
        let plain_hex = gen_hex_message(&mut rng, blocks * 8);

        // EMV-CBC attributes shared by the encrypt oracle and (rebuilt) the K0
        // handler: same PAN/PSN/ATC ⇒ same session key ⇒ round-trip recovers plain.
        let sdd = format!("{atc_hex}000000000000"); // ATC(4H) + 12 zero hex = 16H
        let emv = || -> anyhow::Result<EmvEncryptionAttributes> {
            Ok(EmvEncryptionAttributes::builder()
                .major_key_derivation_mode(EmvMajorKeyDerivationMode::EmvOptionA)
                .primary_account_number(&pan)
                .pan_sequence_number(&seq)
                .session_derivation_data(&sdd)
                .mode(EmvEncryptionMode::Cbc)
                .build()?)
        };

        // 1) Oracle encrypt → ciphertext (hex).
        let cipher_hex = data
            .encrypt_data()
            .key_identifier(&e1_arn)
            .plain_text(&plain_hex)
            .encryption_attributes(EncryptionDecryptionAttributes::Emv(emv()?))
            .send()
            .await?
            .cipher_text()
            .to_string();

        // 2) Proxy K0 decrypt. Wire carries the ciphertext as raw bytes; the
        //    handler hex-encodes it back before calling APC.
        let wire = encode_k0(
            &e1_label,
            &pan_seq_bcd(&pan, &seq),
            atc,
            &hex_str_to_bytes(&cipher_hex),
        );
        let proxy = k0.handle(b"K0", &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("emv_decrypt_k0_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} K0 error_code={} (pan={pan} seq={seq} atc={atc_hex} blocks={blocks})",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }
        let proxy_plain = String::from_utf8(proxy.payload.to_vec())?;

        if !proxy_plain.eq_ignore_ascii_case(&plain_hex) {
            eprintln!(
                "{}",
                replay_hint("emv_decrypt_k0_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} K0 round-trip mismatch: proxy={proxy_plain} expected={plain_hex} \
                 (pan={pan} seq={seq} atc={atc_hex} blocks={blocks})"
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK pan={pan} seq={seq} atc={atc_hex} blocks={blocks}");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── Non-DUKPT PIN verify DA/DC/EA/EC (live verdict differential) ───────────────
//
// Un-audited handler (PUGD0537-004 p.269/277/279/281). DA/EA verify an IBM 3624
// PIN; DC/EC verify a Visa PVV. DA/DC use a TPK, EA/EC a ZPK — both are P0 in APC
// (encryption_key_identifier), so the four commands share two code paths. No
// DUKPT. Wire (IBM): EncKey || PVK || Max(2N) || Min(2N) || PINblock(16H) ||
// fmt(2N) || PAN(12N) || decim(16H) || PIN-val-data(12A) || offset(12H F-padded).
// Wire (Visa): EncKey || PVK-pair(32H) || Max || Min || PINblock || fmt || PAN ||
// PVKI(1N) || PVV(4N).
//
// Verdict differential like GO/CK but without the DUKPT translate: a valid PIN is
// minted via generate_pin_data (IBM3624 natural PIN offset 0, or Visa PVV), the
// proxy's verify verdict must match a direct APC verify_pin_data verdict. A wrong
// field offset feeds APC garbage, which it rejects → verdicts diverge.

const NDV_ENC_LABEL: &str = "U00000000000000000000000000000D01";
const NDV_PVK_IBM_LABEL: &str = "U00000000000000000000000000000D02";
const NDV_PVK_VISA_LABEL: &str = "U00000000000000000000000000000D03";

/// Encode a DA/EA (IBM 3624) verify frame.
#[allow(clippy::too_many_arguments)]
fn encode_da_ea(
    enc_label: &str,
    pvk_label: &str,
    pin_block16: &str,
    account: &str,
    decim: &str,
    pin_val_data: &str,
    offset12: &str,
) -> Vec<u8> {
    let mut v = enc_label.as_bytes().to_vec();
    v.extend_from_slice(pvk_label.as_bytes());
    v.extend_from_slice(b"04"); // Max PIN length
    v.extend_from_slice(b"04"); // Min PIN length
    v.extend_from_slice(pin_block16.as_bytes()); // 16H
    v.extend_from_slice(b"01"); // PIN block format (ISO0)
    v.extend_from_slice(account.as_bytes()); // 12N
    v.extend_from_slice(decim.as_bytes()); // 16H
    v.extend_from_slice(pin_val_data.as_bytes()); // 12A
    v.extend_from_slice(offset12.as_bytes()); // 12H F-padded
    v
}

/// Encode a DC/EC (Visa PVV) verify frame.
fn encode_dc_ec(
    enc_label: &str,
    pvk_label: &str,
    pin_block16: &str,
    account: &str,
    pvki: &str,
    pvv: &str,
) -> Vec<u8> {
    let mut v = enc_label.as_bytes().to_vec();
    v.extend_from_slice(pvk_label.as_bytes());
    v.extend_from_slice(b"04"); // Max PIN length
    v.extend_from_slice(b"04"); // Min PIN length
    v.extend_from_slice(pin_block16.as_bytes()); // 16H
    v.extend_from_slice(b"01"); // PIN block format (ISO0)
    v.extend_from_slice(account.as_bytes()); // 12N
    v.extend_from_slice(pvki.as_bytes()); // 1N PVKI
    v.extend_from_slice(pvv.as_bytes()); // 4N PVV
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn pin_verify_non_dukpt_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "pin_verify_non_dukpt_differential: grounding crypto=apc \
         wire=diff-xprov(IBM3624 + Visa PVV non-DUKPT; cmd-randomised; verdict)"
    );

    use aws_sdk_paymentcryptographydata::types::VisaPinVerification;

    let (cpc, data) = aws_clients().await;
    let specs = [
        KeySpec {
            role: "ENC",
            wire_label: NDV_ENC_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31P0PinEncryptionKey,
            modes: KeyModesOfUse::builder()
                .encrypt(true)
                .decrypt(true)
                .wrap(true)
                .unwrap(true)
                .build(),
        },
        KeySpec {
            role: "PVK_IBM",
            wire_label: NDV_PVK_IBM_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V1Ibm3624PinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
        KeySpec {
            role: "PVK_VISA",
            wire_label: NDV_PVK_VISA_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V2VisaPinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
    ];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let enc_arn = keys.arn("ENC").to_string();
    let pvk_ibm_arn = keys.arn("PVK_IBM").to_string();
    let pvk_visa_arn = keys.arn("PVK_VISA").to_string();
    let enc_label = keys.wire_label("ENC").to_string();
    let pvk_ibm_label = keys.wire_label("PVK_IBM").to_string();
    let pvk_visa_label = keys.wire_label("PVK_VISA").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let da = registry.get(b"DA").expect("DA registered");
    let dc = registry.get(b"DC").expect("DC registered");
    let ea = registry.get(b"EA").expect("EA registered");
    let ec = registry.get(b"EC").expect("EC registered");

    const LABEL: &str = "pin_verify_non_dukpt";
    let run = cases_to_run();
    eprintln!(
        "pin_verify_non_dukpt_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12); // 12N account, also the ISO-0 PAN
        let use_ibm = rng.random_bool(0.5);

        let (cmd, method, proxy_pass, oracle_pass): (&[u8], &str, bool, bool) = if use_ibm {
            // DA (TPK) or EA (ZPK) — same APC path.
            let (cmd, handler): (&[u8], _) = if rng.random_bool(0.5) {
                (b"DA", &da)
            } else {
                (b"EA", &ea)
            };
            // Mint an IBM3624 natural-PIN block (offset 0) under the ENC key.
            let block = data
                .generate_pin_data()
                .generation_key_identifier(&pvk_ibm_arn)
                .encryption_key_identifier(&enc_arn)
                .primary_account_number(&pan)
                .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
                .generation_attributes(PinGenerationAttributes::Ibm3624NaturalPin(
                    Ibm3624NaturalPin::builder()
                        .decimalization_table(GO_DECIM_TABLE)
                        .pin_validation_data(&pan)
                        .pin_validation_data_pad_character("F")
                        .build()?,
                ))
                .send()
                .await?
                .encrypted_pin_block()
                .to_string();

            let wire = encode_da_ea(
                &enc_label,
                &pvk_ibm_label,
                &block,
                &pan,
                GO_DECIM_TABLE,
                &pan,
                "0000FFFFFFFF",
            );
            let proxy = handler.handle(cmd, &wire, &state).await;
            let oracle = data
                .verify_pin_data()
                .verification_key_identifier(&pvk_ibm_arn)
                .encryption_key_identifier(&enc_arn)
                .encrypted_pin_block(&block)
                .primary_account_number(&pan)
                .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
                .verification_attributes(PinVerificationAttributes::Ibm3624Pin(
                    Ibm3624PinVerification::builder()
                        .decimalization_table(GO_DECIM_TABLE)
                        .pin_validation_data(&pan)
                        .pin_validation_data_pad_character("F")
                        .pin_offset("0000")
                        .build()?,
                ))
                .send()
                .await;
            (cmd, "IBM3624", &proxy.error_code == b"00", oracle.is_ok())
        } else {
            // DC (TPK) or EC (ZPK) — same APC path.
            let (cmd, handler): (&[u8], _) = if rng.random_bool(0.5) {
                (b"DC", &dc)
            } else {
                (b"EC", &ec)
            };
            let pvki = i32::try_from(edge_biased(&mut rng, 1, 6, &[1, 6])).expect("pvki in 1..6");
            // Mint a Visa PVV block; read back the generated PVV.
            let gen = data
                .generate_pin_data()
                .generation_key_identifier(&pvk_visa_arn)
                .encryption_key_identifier(&enc_arn)
                .primary_account_number(&pan)
                .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
                .generation_attributes(PinGenerationAttributes::VisaPin(
                    VisaPin::builder()
                        .pin_verification_key_index(pvki)
                        .build()?,
                ))
                .send()
                .await?;
            let block = gen.encrypted_pin_block().to_string();
            let pvv = gen
                .pin_data()
                .and_then(|d| d.as_verification_value().ok().cloned())
                .ok_or_else(|| anyhow::anyhow!("generate_pin_data returned no Visa PVV"))?;

            let wire = encode_dc_ec(
                &enc_label,
                &pvk_visa_label,
                &block,
                &pan,
                &pvki.to_string(),
                &pvv,
            );
            let proxy = handler.handle(cmd, &wire, &state).await;
            let oracle = data
                .verify_pin_data()
                .verification_key_identifier(&pvk_visa_arn)
                .encryption_key_identifier(&enc_arn)
                .encrypted_pin_block(&block)
                .primary_account_number(&pan)
                .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
                .verification_attributes(PinVerificationAttributes::VisaPin(
                    VisaPinVerification::builder()
                        .pin_verification_key_index(pvki)
                        .verification_value(&pvv)
                        .build()?,
                ))
                .send()
                .await;
            (cmd, "VisaPVV", &proxy.error_code == b"00", oracle.is_ok())
        };

        if proxy_pass != oracle_pass {
            eprintln!(
                "{}",
                replay_hint("pin_verify_non_dukpt_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} {} {} verdict mismatch: proxy_pass={proxy_pass} \
                 oracle_pass={oracle_pass} pan={pan}",
                String::from_utf8_lossy(cmd),
                method,
            ));
            break;
        }
        if !oracle_pass {
            eprintln!(
                "{}",
                replay_hint("pin_verify_non_dukpt_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} {} {}: minted PIN should verify but both proxy and oracle \
                 rejected it (pan={pan}) — likely a setup error",
                String::from_utf8_lossy(cmd),
                method,
            ));
            break;
        }

        eprintln!(
            "case={case_idx:02} OK cmd={} method={method} pan={pan} verdict=pass",
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

// ── International encrypt M0/M2/M4 (live differential + round-trips) ───────────
//
// Un-audited handler (payShield International Host Commands, inferred layout).
// M0 encrypts a data block, M2 decrypts one, M4 translates one src→dst — all
// TDES-ECB under D0 data keys. Wire (M0/M2): Mode(2N '00'=ECB) || InFmt(1N '1') ||
// OutFmt(1N '1') || KeyType(3H, consumed) || Key || MsgLen(4H byte count) ||
// Msg(hex). Wire (M4): SrcMode(2N) || DstMode(2N) || InFmt || OutFmt ||
// SrcKeyType(3H) || SrcKey || DstKeyType(3H) || DstKey || MsgLen(4H) || Msg(hex).
// Response: MsgLen(4H) || data(hex).
//
// M0 IS an encrypt_data ECB call, so the oracle equality proves the wire parse
// (mode/format/key-type/key/len offsets); a shifted field feeds APC different
// bytes and proxy ≠ oracle. M2 round-trips the proxy's own ciphertext back to
// plaintext. M4 translates the M0 ciphertext src→dst, then a direct APC
// decrypt_data under the dst key must recover the original plaintext — validating
// the two-key parse and the decrypt-then-encrypt translate (M4 cannot use
// re_encrypt_data; APC rejects it for D0 keys — see the handler grounding).

const INTL_DEK_LABEL: &str = "U00000000000000000000000000000E01";
const INTL_DEK_DST_LABEL: &str = "U00000000000000000000000000000E02";

/// Encode an M0/M2 ECB-hex frame. Key type "00B" (DEK) is consumed by the parser.
fn encode_m0_m2(key_label: &str, msg_hex: &str) -> Vec<u8> {
    let mut v = b"00".to_vec(); // Mode: ECB
    v.push(b'1'); // Input format: hex
    v.push(b'1'); // Output format: hex
    v.extend_from_slice(b"00B"); // Key type 3H (consumed)
    v.extend_from_slice(key_label.as_bytes());
    let byte_count = msg_hex.len() / 2;
    v.extend_from_slice(format!("{byte_count:04X}").as_bytes());
    v.extend_from_slice(msg_hex.as_bytes());
    v
}

/// Encode an M4 translate ECB-hex frame (src→dst, both ECB).
fn encode_m4(src_label: &str, dst_label: &str, msg_hex: &str) -> Vec<u8> {
    let mut v = b"00".to_vec(); // Source mode: ECB
    v.extend_from_slice(b"00"); // Dest mode: ECB
    v.push(b'1'); // Input format: hex
    v.push(b'1'); // Output format: hex
    v.extend_from_slice(b"00B"); // Src key type 3H (consumed)
    v.extend_from_slice(src_label.as_bytes());
    v.extend_from_slice(b"00B"); // Dst key type 3H (consumed)
    v.extend_from_slice(dst_label.as_bytes());
    let byte_count = msg_hex.len() / 2;
    v.extend_from_slice(format!("{byte_count:04X}").as_bytes());
    v.extend_from_slice(msg_hex.as_bytes());
    v
}

/// Strip the 4H byte-length prefix from an M0/M2 response payload, returning the
/// data hex.
fn strip_m_len_prefix(payload: &[u8]) -> anyhow::Result<String> {
    let s = String::from_utf8(payload.to_vec())?;
    anyhow::ensure!(s.len() >= 4, "M0/M2 response shorter than 4H length prefix");
    Ok(s[4..].to_string())
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn intl_encrypt_m0_m2_m4_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "intl_encrypt_m0_m2_m4_differential: grounding crypto=apc \
         wire=diff-xprov(TDES-ECB; M0 vs oracle + M2/M4 round-trips; length-randomised)"
    );

    use aws_sdk_paymentcryptographydata::types::{
        EncryptionDecryptionAttributes, EncryptionMode, SymmetricEncryptionAttributes,
    };

    let (cpc, data) = aws_clients().await;
    let dek_modes = || KeyModesOfUse::builder().no_restrictions(true).build();
    let specs = [
        KeySpec {
            role: "DEK",
            wire_label: INTL_DEK_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31D0SymmetricDataEncryptionKey,
            modes: dek_modes(),
        },
        KeySpec {
            role: "DEK_DST",
            wire_label: INTL_DEK_DST_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31D0SymmetricDataEncryptionKey,
            modes: dek_modes(),
        },
    ];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let dek_arn = keys.arn("DEK").to_string();
    let dek_dst_arn = keys.arn("DEK_DST").to_string();
    let dek_label = keys.wire_label("DEK").to_string();
    let dek_dst_label = keys.wire_label("DEK_DST").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let m0 = registry.get(b"M0").expect("M0 registered");
    let m2 = registry.get(b"M2").expect("M2 registered");
    let m4 = registry.get(b"M4").expect("M4 registered");

    const LABEL: &str = "intl_encrypt_m0_m2_m4";
    let run = cases_to_run();
    eprintln!(
        "intl_encrypt_m0_m2_m4_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let ecb = || -> anyhow::Result<SymmetricEncryptionAttributes> {
        Ok(SymmetricEncryptionAttributes::builder()
            .mode(EncryptionMode::Ecb)
            .build()?)
    };

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        // TDES-ECB: whole 8-byte blocks. Edge-biased over 1..4 blocks.
        let blocks = edge_biased(&mut rng, 1, 4, &[1, 2, 4]);
        let plain_hex = gen_hex_message(&mut rng, blocks * 8);

        // 1) M0 encrypt via proxy.
        let m0_wire = encode_m0_m2(&dek_label, &plain_hex);
        let proxy_m0 = m0.handle(b"M0", &m0_wire, &state).await;
        if &proxy_m0.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("intl_encrypt_m0_m2_m4_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} M0 error_code={} (blocks={blocks})",
                String::from_utf8_lossy(&proxy_m0.error_code),
            ));
            break;
        }
        let proxy_cipher = strip_m_len_prefix(&proxy_m0.payload)?;

        // 2) Oracle: APC encrypt_data ECB with the same key + plaintext.
        let oracle_cipher = data
            .encrypt_data()
            .key_identifier(&dek_arn)
            .plain_text(&plain_hex)
            .encryption_attributes(EncryptionDecryptionAttributes::Symmetric(ecb()?))
            .send()
            .await?
            .cipher_text()
            .to_string();

        if !proxy_cipher.eq_ignore_ascii_case(&oracle_cipher) {
            eprintln!(
                "{}",
                replay_hint("intl_encrypt_m0_m2_m4_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} M0 differential mismatch: proxy={proxy_cipher} \
                 oracle={oracle_cipher} plain={plain_hex}"
            ));
            break;
        }

        // 3) M2 round-trip: the proxy's own M2 must decrypt M0's ciphertext back
        //    to the original plaintext.
        let m2_wire = encode_m0_m2(&dek_label, &proxy_cipher);
        let proxy_m2 = m2.handle(b"M2", &m2_wire, &state).await;
        if &proxy_m2.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("intl_encrypt_m0_m2_m4_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} M2 error_code={} on proxy M0 ciphertext",
                String::from_utf8_lossy(&proxy_m2.error_code),
            ));
            break;
        }
        let proxy_plain = strip_m_len_prefix(&proxy_m2.payload)?;
        if !proxy_plain.eq_ignore_ascii_case(&plain_hex) {
            eprintln!(
                "{}",
                replay_hint("intl_encrypt_m0_m2_m4_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} M2 round-trip mismatch: proxy={proxy_plain} expected={plain_hex}"
            ));
            break;
        }

        // 4) M4 translate the M0 ciphertext src→dst via proxy; a direct APC
        //    decrypt under the dst key must recover the original plaintext.
        let m4_wire = encode_m4(&dek_label, &dek_dst_label, &proxy_cipher);
        let proxy_m4 = m4.handle(b"M4", &m4_wire, &state).await;
        if &proxy_m4.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("intl_encrypt_m0_m2_m4_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} M4 error_code={} translating M0 ciphertext",
                String::from_utf8_lossy(&proxy_m4.error_code),
            ));
            break;
        }
        let dst_cipher = strip_m_len_prefix(&proxy_m4.payload)?;
        let recovered = data
            .decrypt_data()
            .key_identifier(&dek_dst_arn)
            .cipher_text(&dst_cipher)
            .decryption_attributes(EncryptionDecryptionAttributes::Symmetric(ecb()?))
            .send()
            .await?
            .plain_text()
            .to_string();
        if !recovered.eq_ignore_ascii_case(&plain_hex) {
            eprintln!(
                "{}",
                replay_hint("intl_encrypt_m0_m2_m4_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} M4 translate mismatch: dst-decrypt={recovered} expected={plain_hex}"
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK blocks={blocks} cipher={proxy_cipher} m4=ok");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── PIN change DU/CU (live differential, verify-current + generate-new) ────────
//
// Un-audited handler (PUGD0537-004 Rev A: DU "Verify a PIN & Generate an IBM PIN
// Offset" p.255; CU "Verify a PIN & Generate an ABA PVV" p.259). Each is atomic:
// verify the current PIN, and only on a match generate the new verification datum
// for a customer-selected new PIN. Two APC calls — verify_pin_data then
// generate_pin_data (Ibm3624PinOffset / VisaPinVerificationValue).
//
// Differential: mint a current PIN block (known offset/PVV) and a new PIN block,
// run the proxy command, then confirm end-to-end that the returned NEW
// offset/PVV actually verifies the NEW block via a direct APC verify_pin_data.
// A wrong field offset in the parse breaks either the verify step (proxy rejects
// a valid current PIN) or the generate step (the returned datum won't verify).

const PC_ZPK_LABEL: &str = "U0000000000000000000000000000F001";
const PC_PVK_IBM_LABEL: &str = "U0000000000000000000000000000F002";
const PC_PVK_VISA_LABEL: &str = "U0000000000000000000000000000F003";

/// Encode a DU (IBM offset) PIN-change frame.
#[allow(clippy::too_many_arguments)]
fn encode_du(
    zpk_label: &str,
    pvk_label: &str,
    cur_block: &str,
    account: &str,
    decim: &str,
    pin_val_data: &str,
    cur_offset12: &str,
    new_block: &str,
) -> Vec<u8> {
    let mut v = zpk_label.as_bytes().to_vec();
    v.extend_from_slice(pvk_label.as_bytes());
    v.extend_from_slice(b"04"); // max
    v.extend_from_slice(b"04"); // min
    v.extend_from_slice(cur_block.as_bytes()); // 16H current PIN block
    v.extend_from_slice(b"01"); // format (ISO0)
    v.extend_from_slice(account.as_bytes()); // 12N
    v.extend_from_slice(decim.as_bytes()); // 16H
    v.extend_from_slice(pin_val_data.as_bytes()); // 12A
    v.extend_from_slice(cur_offset12.as_bytes()); // 12H F-padded
    v.extend_from_slice(new_block.as_bytes()); // 16H new PIN block
    v
}

/// Encode a CU (Visa PVV) PIN-change frame.
#[allow(clippy::too_many_arguments)]
fn encode_cu(
    zpk_label: &str,
    pvk_label: &str,
    cur_block: &str,
    account: &str,
    pvki: &str,
    cur_pvv: &str,
    new_block: &str,
) -> Vec<u8> {
    let mut v = zpk_label.as_bytes().to_vec();
    v.extend_from_slice(pvk_label.as_bytes());
    v.extend_from_slice(b"04");
    v.extend_from_slice(b"04");
    v.extend_from_slice(cur_block.as_bytes()); // 16H current PIN block
    v.extend_from_slice(b"01"); // format (ISO0)
    v.extend_from_slice(account.as_bytes()); // 12N
    v.extend_from_slice(pvki.as_bytes()); // 1N PVKI
    v.extend_from_slice(cur_pvv.as_bytes()); // 4N current PVV
    v.extend_from_slice(new_block.as_bytes()); // 16H new PIN block
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn pin_change_du_cu_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "pin_change_du_cu_differential: grounding crypto=apc \
         wire=diff-xprov(IBM offset + Visa PVV; verify-current + generate-new; new datum re-verified)"
    );

    use aws_sdk_paymentcryptographydata::types::{VisaPin, VisaPinVerification};

    let (cpc, data) = aws_clients().await;
    let specs = [
        KeySpec {
            role: "ZPK",
            wire_label: PC_ZPK_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31P0PinEncryptionKey,
            modes: KeyModesOfUse::builder()
                .encrypt(true)
                .decrypt(true)
                .wrap(true)
                .unwrap(true)
                .build(),
        },
        KeySpec {
            role: "PVK_IBM",
            wire_label: PC_PVK_IBM_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V1Ibm3624PinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
        KeySpec {
            role: "PVK_VISA",
            wire_label: PC_PVK_VISA_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V2VisaPinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
    ];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let zpk_arn = keys.arn("ZPK").to_string();
    let pvk_ibm_arn = keys.arn("PVK_IBM").to_string();
    let pvk_visa_arn = keys.arn("PVK_VISA").to_string();
    let zpk_label = keys.wire_label("ZPK").to_string();
    let pvk_ibm_label = keys.wire_label("PVK_IBM").to_string();
    let pvk_visa_label = keys.wire_label("PVK_VISA").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let du = registry.get(b"DU").expect("DU registered");
    let cu = registry.get(b"CU").expect("CU registered");

    const LABEL: &str = "pin_change_du_cu";
    let iso0 = || PinBlockFormatForPinData::IsoFormat0;
    let run = cases_to_run();
    eprintln!(
        "pin_change_du_cu_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );
    let mut result: anyhow::Result<()> = Ok(());

    // Mint an IBM3624 natural-PIN block under the ZPK for a given validation data.
    async fn mint_natural(
        data: &aws_sdk_paymentcryptographydata::Client,
        pvk: &str,
        zpk: &str,
        pan: &str,
        pvid: &str,
    ) -> anyhow::Result<String> {
        Ok(data
            .generate_pin_data()
            .generation_key_identifier(pvk)
            .encryption_key_identifier(zpk)
            .primary_account_number(pan)
            .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
            .generation_attributes(PinGenerationAttributes::Ibm3624NaturalPin(
                Ibm3624NaturalPin::builder()
                    .decimalization_table(GO_DECIM_TABLE)
                    .pin_validation_data(pvid)
                    .pin_validation_data_pad_character("F")
                    .build()?,
            ))
            .send()
            .await?
            .encrypted_pin_block()
            .to_string())
    }

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let use_ibm = rng.random_bool(0.5);
        // New PIN block: a different natural PIN (distinct validation data), same PAN.
        let new_block = mint_natural(&data, &pvk_ibm_arn, &zpk_arn, &pan, "999999999999").await?;

        let (cmd, method, proxy_ok, new_verifies): (&[u8], &str, bool, bool) = if use_ibm {
            // Current PIN: natural PIN (pvid=PAN), so current offset is all-zero.
            let cur_block = mint_natural(&data, &pvk_ibm_arn, &zpk_arn, &pan, &pan).await?;
            let wire = encode_du(
                &zpk_label,
                &pvk_ibm_label,
                &cur_block,
                &pan,
                GO_DECIM_TABLE,
                &pan,
                "0000FFFFFFFF",
                &new_block,
            );
            let proxy = du.handle(b"DU", &wire, &state).await;
            if &proxy.error_code != b"00" {
                (b"DU", "IBM", false, false)
            } else {
                // DV response New Offset is 12H, left-justified and F-padded
                // (PUGD0537-004 Rev A p.255); APC's pin_offset wants the
                // significant digits only, so trim before re-verifying.
                let new_offset_wire = String::from_utf8(proxy.payload.to_vec())?;
                anyhow::ensure!(
                    new_offset_wire.len() == 12,
                    "DU new offset not 12H F-padded: {new_offset_wire:?}"
                );
                let new_offset = new_offset_wire.trim_end_matches('F');
                // The returned new offset must verify the new PIN block.
                let ok = data
                    .verify_pin_data()
                    .verification_key_identifier(&pvk_ibm_arn)
                    .encryption_key_identifier(&zpk_arn)
                    .encrypted_pin_block(&new_block)
                    .primary_account_number(&pan)
                    .pin_block_format(iso0())
                    .verification_attributes(PinVerificationAttributes::Ibm3624Pin(
                        Ibm3624PinVerification::builder()
                            .decimalization_table(GO_DECIM_TABLE)
                            .pin_validation_data(&pan)
                            .pin_validation_data_pad_character("F")
                            .pin_offset(new_offset)
                            .build()?,
                    ))
                    .send()
                    .await
                    .is_ok();
                (b"DU", "IBM", true, ok)
            }
        } else {
            // Current PIN: Visa PVV block; read back its PVV for the verify step.
            let pvki = i32::try_from(edge_biased(&mut rng, 1, 6, &[1, 6])).expect("pvki");
            let gen = data
                .generate_pin_data()
                .generation_key_identifier(&pvk_visa_arn)
                .encryption_key_identifier(&zpk_arn)
                .primary_account_number(&pan)
                .pin_block_format(iso0())
                .generation_attributes(PinGenerationAttributes::VisaPin(
                    VisaPin::builder()
                        .pin_verification_key_index(pvki)
                        .build()?,
                ))
                .send()
                .await?;
            let cur_block = gen.encrypted_pin_block().to_string();
            let cur_pvv = gen
                .pin_data()
                .and_then(|d| d.as_verification_value().ok().cloned())
                .ok_or_else(|| anyhow::anyhow!("no Visa PVV"))?;
            let wire = encode_cu(
                &zpk_label,
                &pvk_visa_label,
                &cur_block,
                &pan,
                &pvki.to_string(),
                &cur_pvv,
                &new_block,
            );
            let proxy = cu.handle(b"CU", &wire, &state).await;
            if &proxy.error_code != b"00" {
                (b"CU", "Visa", false, false)
            } else {
                let new_pvv = String::from_utf8(proxy.payload.to_vec())?;
                let ok = data
                    .verify_pin_data()
                    .verification_key_identifier(&pvk_visa_arn)
                    .encryption_key_identifier(&zpk_arn)
                    .encrypted_pin_block(&new_block)
                    .primary_account_number(&pan)
                    .pin_block_format(iso0())
                    .verification_attributes(PinVerificationAttributes::VisaPin(
                        VisaPinVerification::builder()
                            .pin_verification_key_index(pvki)
                            .verification_value(&new_pvv)
                            .build()?,
                    ))
                    .send()
                    .await
                    .is_ok();
                (b"CU", "Visa", true, ok)
            }
        };

        if !proxy_ok {
            eprintln!(
                "{}",
                replay_hint("pin_change_du_cu_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} {} {}: proxy did not return 00 (verify-current or generate-new failed) pan={pan}",
                String::from_utf8_lossy(cmd),
                method,
            ));
            break;
        }
        if !new_verifies {
            eprintln!(
                "{}",
                replay_hint("pin_change_du_cu_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} {} {}: proxy's new offset/PVV does NOT verify the new PIN block pan={pan}",
                String::from_utf8_lossy(cmd),
                method,
            ));
            break;
        }
        eprintln!(
            "case={case_idx:02} OK cmd={} method={method} pan={pan} new-datum-verifies=yes",
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

// ── Futurex TPIN (live differential, PIN translate) ───────────────────────────
//
// Un-audited Futurex Excrypt handler. TPIN translates a PIN block from an inbound
// PEK to an outbound PEK → APC translate_pin_data. Request params (';'-delimited,
// 2-char tags): AW=format ('0'=ISO0), AX=inbound key, BT=outbound key,
// AL=encrypted PIN block, AK=account (12N). Response: AL=translated block.
//
// ISO Format 0 translation is deterministic (no random fill), so the proxy's
// output must byte-match a direct APC translate_pin_data with the same keys and
// account. A Futurex param-parse bug (wrong key/format/account) diverges them.

const TPIN_IN_LABEL: &str = "U0000000000000000000000000000E101";
const TPIN_OUT_LABEL: &str = "U0000000000000000000000000000E102";

/// Encode a Futurex TPIN request param body (ISO0).
fn encode_tpin(in_label: &str, out_label: &str, pin_block: &str, account: &str) -> Vec<u8> {
    // AW0 = ISO Format 0
    format!("AW0;AX{in_label};BT{out_label};AL{pin_block};AK{account};").into_bytes()
}

/// Extract the AL (translated PIN block) value from a TPIN response payload.
fn tpin_response_block(payload: &[u8]) -> anyhow::Result<String> {
    let s = String::from_utf8(payload.to_vec())?;
    for token in s.split(';') {
        if let Some(v) = token.strip_prefix("AL") {
            return Ok(v.to_string());
        }
    }
    anyhow::bail!("TPIN response has no AL field: {s:?}")
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn futurex_tpin_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "futurex_tpin_differential: grounding crypto=apc \
         wire=diff-xprov(Futurex Excrypt params; ISO0 translate, deterministic)"
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
            role: "IN",
            wire_label: TPIN_IN_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31P0PinEncryptionKey,
            modes: zpk_modes(),
        },
        KeySpec {
            role: "OUT",
            wire_label: TPIN_OUT_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31P0PinEncryptionKey,
            modes: zpk_modes(),
        },
        KeySpec {
            role: "PGK",
            wire_label: "PGK_UNUSED_TPIN",
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V2VisaPinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
    ];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let in_arn = keys.arn("IN").to_string();
    let out_arn = keys.arn("OUT").to_string();
    let pgk_arn = keys.arn("PGK").to_string();
    let in_label = keys.wire_label("IN").to_string();
    let out_label = keys.wire_label("OUT").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let tpin = registry.get(b"TPIN").expect("TPIN registered");

    const LABEL: &str = "futurex_tpin";
    let run = cases_to_run();
    eprintln!(
        "futurex_tpin_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );
    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        // Mint a valid inbound-PEK-encrypted ISO0 PIN block.
        let input_block = data
            .generate_pin_data()
            .generation_key_identifier(&pgk_arn)
            .encryption_key_identifier(&in_arn)
            .primary_account_number(&pan)
            .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
            .generation_attributes(PinGenerationAttributes::VisaPin(
                VisaPin::builder().pin_verification_key_index(1).build()?,
            ))
            .send()
            .await?
            .encrypted_pin_block()
            .to_string();

        // Proxy TPIN (Futurex params) inbound → outbound.
        let wire = encode_tpin(&in_label, &out_label, &input_block, &pan);
        let proxy = tpin.handle(b"TPIN", &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("futurex_tpin_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} TPIN error_code={} pan={pan}",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }
        let proxy_block = tpin_response_block(&proxy.payload)?;

        // Oracle: direct APC translate_pin_data (ISO0 → ISO0, deterministic).
        let oracle_block = data
            .translate_pin_data()
            .incoming_key_identifier(&in_arn)
            .outgoing_key_identifier(&out_arn)
            .encrypted_pin_block(&input_block)
            .incoming_translation_attributes(translate_iso(0, &pan)?)
            .outgoing_translation_attributes(translate_iso(0, &pan)?)
            .send()
            .await?
            .pin_block()
            .to_string();

        if !proxy_block.eq_ignore_ascii_case(&oracle_block) {
            eprintln!(
                "{}",
                replay_hint("futurex_tpin_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} TPIN mismatch: proxy={proxy_block} oracle={oracle_block} pan={pan}"
            ));
            break;
        }
        eprintln!("case={case_idx:02} OK pan={pan} translated={proxy_block}");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ══ Negative / discrimination tests ═══════════════════════════════════════════
//
// The positive differentials above are accept-only: they confirm a VALID
// credential is accepted, but not that an INVALID one is rejected — an
// always-accept handler would pass them. These tests close that gap: for each
// verify handler, the valid credential must be accepted (error 00) AND a
// minimally-corrupted one must be rejected (error 01). A handler that ignores
// the credential fails the reject leg; one that rejects everything fails the
// accept leg.

/// A random symbol: hex nibble (`hex=true`) or decimal digit.
fn rand_symbol(rng: &mut StdRng, hex: bool) -> char {
    if hex {
        char::from(b"0123456789ABCDEF"[rng.random_range(0..16)])
    } else {
        char::from(b'0' + rng.random_range(0..10_u8))
    }
}

/// Produce an invalid variant of `correct`, guaranteed different (case-insensitive)
/// and the same length/alphabet. Half the time a minimal single-symbol edit at a
/// random position, half the time a fully random value — so a sweep explores both
/// off-by-one and far-away wrong credentials, varying per case and per seed.
fn corrupt(rng: &mut StdRng, correct: &str, hex: bool) -> String {
    loop {
        let mut chars: Vec<char> = correct.chars().collect();
        if chars.is_empty() {
            return rand_symbol(rng, hex).to_string();
        }
        if rng.random_bool(0.5) {
            let i = rng.random_range(0..chars.len());
            chars[i] = rand_symbol(rng, hex);
        } else {
            for c in &mut chars {
                *c = rand_symbol(rng, hex);
            }
        }
        let s: String = chars.into_iter().collect();
        if !s.eq_ignore_ascii_case(correct) {
            return s;
        }
    }
}

/// A random 12H IBM offset that is NOT the natural-PIN offset ("0000" F-padded).
/// Four random decimal digits (≠ "0000") left-justified and F-padded to 12H.
fn random_wrong_offset(rng: &mut StdRng) -> String {
    loop {
        let digits: String = (0..4).map(|_| rand_symbol(rng, false)).collect();
        if digits != "0000" {
            return format!("{digits:F<12}");
        }
    }
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn cvv_cy_discrimination_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "cvv_cy_discrimination_differential: valid CVV accepted (00), corrupted rejected (01)"
    );

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "CVK",
        wire_label: CVK_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31C0CardVerificationKey,
        modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let cvk_label = keys.wire_label("CVK").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let cw = registry.get(b"CW").expect("CW registered");
    let cy = registry.get(b"CY").expect("CY registered");

    const LABEL: &str = "cvv_cy_discrimination";
    let run = cases_to_run();
    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan_len = gen_pan_len(&mut rng);
        let pan = gen_pan(&mut rng, pan_len);
        let expiry = gen_expiry(&mut rng);
        let svc = gen_service_code(&mut rng);

        let cvv = {
            let r = cw
                .handle(b"CW", &encode_cw(&cvk_label, &pan, &expiry, svc), &state)
                .await;
            anyhow::ensure!(&r.error_code == b"00", "CW failed to generate CVV");
            String::from_utf8(r.payload.to_vec())?
        };
        let bad = corrupt(&mut rng, &cvv, false);

        let accept = cy
            .handle(
                b"CY",
                &encode_cy(&cvk_label, &cvv, &pan, &expiry, svc),
                &state,
            )
            .await;
        let reject = cy
            .handle(
                b"CY",
                &encode_cy(&cvk_label, &bad, &pan, &expiry, svc),
                &state,
            )
            .await;

        if let Err(e) =
            assert_discriminates("CY", case_idx, accept.error_code, reject.error_code, &pan)
        {
            eprintln!(
                "{}",
                replay_hint("cvv_cy_discrimination_differential", LABEL, case_idx)
            );
            result = Err(e);
            break;
        }
        eprintln!("case={case_idx:02} OK CVV={cvv} accept=00 corrupted({bad})=01");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn mac_m8_discrimination_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "mac_m8_discrimination_differential: valid MAC accepted (00), corrupted rejected (01)"
    );

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "MAK",
        wire_label: MAK_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31M3Iso97973MacKey,
        modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let mak_label = keys.wire_label("MAK").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let m6 = registry.get(b"M6").expect("M6 registered");
    let m8 = registry.get(b"M8").expect("M8 registered");

    const LABEL: &str = "mac_m8_discrimination";
    let run = cases_to_run();
    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let msg_bytes = edge_biased(&mut rng, 1, 32, &[1, 8, 16, 32]);
        let msg = gen_hex_message(&mut rng, msg_bytes);

        let mac = {
            let r = m6
                .handle(b"M6", &encode_m6(&mak_label, b'3', b'0', &msg), &state)
                .await;
            anyhow::ensure!(&r.error_code == b"00", "M6 failed to generate MAC");
            String::from_utf8(r.payload.to_vec())?
        };
        let bad = corrupt(&mut rng, &mac, true);

        let accept = m8
            .handle(
                b"M8",
                &encode_m8(&mak_label, b'3', b'0', &msg, &mac),
                &state,
            )
            .await;
        let reject = m8
            .handle(
                b"M8",
                &encode_m8(&mak_label, b'3', b'0', &msg, &bad),
                &state,
            )
            .await;

        if let Err(e) =
            assert_discriminates("M8", case_idx, accept.error_code, reject.error_code, &msg)
        {
            eprintln!(
                "{}",
                replay_hint("mac_m8_discrimination_differential", LABEL, case_idx)
            );
            result = Err(e);
            break;
        }
        eprintln!("case={case_idx:02} OK MAC={mac} accept=00 corrupted({bad})=01");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn pin_verify_non_dukpt_discrimination_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "pin_verify_non_dukpt_discrimination_differential: valid PIN accepted (00), \
         wrong offset/PVV rejected (01)"
    );

    use aws_sdk_paymentcryptographydata::types::VisaPin;

    let (cpc, data) = aws_clients().await;
    let specs = [
        KeySpec {
            role: "ENC",
            wire_label: NDV_ENC_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31P0PinEncryptionKey,
            modes: KeyModesOfUse::builder()
                .encrypt(true)
                .decrypt(true)
                .wrap(true)
                .unwrap(true)
                .build(),
        },
        KeySpec {
            role: "PVK_IBM",
            wire_label: NDV_PVK_IBM_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V1Ibm3624PinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
        KeySpec {
            role: "PVK_VISA",
            wire_label: NDV_PVK_VISA_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V2VisaPinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
    ];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let enc_arn = keys.arn("ENC").to_string();
    let pvk_ibm_arn = keys.arn("PVK_IBM").to_string();
    let pvk_visa_arn = keys.arn("PVK_VISA").to_string();
    let enc_label = keys.wire_label("ENC").to_string();
    let pvk_ibm_label = keys.wire_label("PVK_IBM").to_string();
    let pvk_visa_label = keys.wire_label("PVK_VISA").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let ea = registry.get(b"EA").expect("EA registered");
    let ec = registry.get(b"EC").expect("EC registered");

    const LABEL: &str = "pin_verify_non_dukpt_discrimination";
    let run = cases_to_run();
    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let use_ibm = rng.random_bool(0.5);

        let (label, accept_code, reject_code): (&str, [u8; 2], [u8; 2]) = if use_ibm {
            // IBM natural PIN (offset 0); verify with correct then wrong offset.
            let block = data
                .generate_pin_data()
                .generation_key_identifier(&pvk_ibm_arn)
                .encryption_key_identifier(&enc_arn)
                .primary_account_number(&pan)
                .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
                .generation_attributes(PinGenerationAttributes::Ibm3624NaturalPin(
                    Ibm3624NaturalPin::builder()
                        .decimalization_table(GO_DECIM_TABLE)
                        .pin_validation_data(&pan)
                        .pin_validation_data_pad_character("F")
                        .build()?,
                ))
                .send()
                .await?
                .encrypted_pin_block()
                .to_string();
            let good = encode_da_ea(
                &enc_label,
                &pvk_ibm_label,
                &block,
                &pan,
                GO_DECIM_TABLE,
                &pan,
                "0000FFFFFFFF",
            );
            let wrong_offset = random_wrong_offset(&mut rng);
            let bad = encode_da_ea(
                &enc_label,
                &pvk_ibm_label,
                &block,
                &pan,
                GO_DECIM_TABLE,
                &pan,
                &wrong_offset,
            );
            let a = ea.handle(b"EA", &good, &state).await.error_code;
            let r = ea.handle(b"EA", &bad, &state).await.error_code;
            ("EA/IBM", a, r)
        } else {
            // Visa PVV; verify with correct then corrupted PVV.
            let pvki = 1;
            let gen = data
                .generate_pin_data()
                .generation_key_identifier(&pvk_visa_arn)
                .encryption_key_identifier(&enc_arn)
                .primary_account_number(&pan)
                .pin_block_format(PinBlockFormatForPinData::IsoFormat0)
                .generation_attributes(PinGenerationAttributes::VisaPin(
                    VisaPin::builder()
                        .pin_verification_key_index(pvki)
                        .build()?,
                ))
                .send()
                .await?;
            let block = gen.encrypted_pin_block().to_string();
            let pvv = gen
                .pin_data()
                .and_then(|d| d.as_verification_value().ok().cloned())
                .ok_or_else(|| anyhow::anyhow!("no Visa PVV"))?;
            let bad_pvv = corrupt(&mut rng, &pvv, false);
            let good = encode_dc_ec(&enc_label, &pvk_visa_label, &block, &pan, "1", &pvv);
            let bad = encode_dc_ec(&enc_label, &pvk_visa_label, &block, &pan, "1", &bad_pvv);
            let a = ec.handle(b"EC", &good, &state).await.error_code;
            let r = ec.handle(b"EC", &bad, &state).await.error_code;
            ("EC/Visa", a, r)
        };

        if let Err(e) = assert_discriminates(label, case_idx, accept_code, reject_code, &pan) {
            eprintln!(
                "{}",
                replay_hint(
                    "pin_verify_non_dukpt_discrimination_differential",
                    LABEL,
                    case_idx
                )
            );
            result = Err(e);
            break;
        }
        eprintln!("case={case_idx:02} OK {label} accept=00 wrong-credential=01 pan={pan}");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

/// Assert a verify handler discriminates: the valid credential yields `00`
/// (accept) and the corrupted one yields `01` (reject). Any other pairing is a
/// failure — most importantly `accept==reject==00` (an always-accept handler).
fn assert_discriminates(
    what: &str,
    case_idx: usize,
    accept_code: [u8; 2],
    reject_code: [u8; 2],
    ctx: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        &accept_code == b"00",
        "case={case_idx} {what}: VALID credential was not accepted (got {}) — {ctx}",
        String::from_utf8_lossy(&accept_code)
    );
    anyhow::ensure!(
        &reject_code == b"01",
        "case={case_idx} {what}: CORRUPTED credential was not rejected with 01 (got {}) — \
         a handler that accepts an invalid credential is a critical bug — {ctx}",
        String::from_utf8_lossy(&reject_code)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn pin_change_du_cu_discrimination_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "pin_change_du_cu_discrimination_differential: correct current PIN changes (00), \
         wrong current PIN rejected (01) and generates nothing"
    );

    use aws_sdk_paymentcryptographydata::types::VisaPin;

    let (cpc, data) = aws_clients().await;
    let specs = [
        KeySpec {
            role: "ZPK",
            wire_label: PC_ZPK_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31P0PinEncryptionKey,
            modes: KeyModesOfUse::builder()
                .encrypt(true)
                .decrypt(true)
                .wrap(true)
                .unwrap(true)
                .build(),
        },
        KeySpec {
            role: "PVK_IBM",
            wire_label: PC_PVK_IBM_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V1Ibm3624PinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
        KeySpec {
            role: "PVK_VISA",
            wire_label: PC_PVK_VISA_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31V2VisaPinVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
    ];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let zpk_arn = keys.arn("ZPK").to_string();
    let pvk_ibm_arn = keys.arn("PVK_IBM").to_string();
    let pvk_visa_arn = keys.arn("PVK_VISA").to_string();
    let zpk_label = keys.wire_label("ZPK").to_string();
    let pvk_ibm_label = keys.wire_label("PVK_IBM").to_string();
    let pvk_visa_label = keys.wire_label("PVK_VISA").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let du = registry.get(b"DU").expect("DU registered");
    let cu = registry.get(b"CU").expect("CU registered");
    let iso0 = || PinBlockFormatForPinData::IsoFormat0;

    const LABEL: &str = "pin_change_du_cu_discrimination";
    let run = cases_to_run();
    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let use_ibm = rng.random_bool(0.5);
        // A "new PIN" block (any valid ISO0 block for the PAN).
        let new_block = data
            .generate_pin_data()
            .generation_key_identifier(&pvk_ibm_arn)
            .encryption_key_identifier(&zpk_arn)
            .primary_account_number(&pan)
            .pin_block_format(iso0())
            .generation_attributes(PinGenerationAttributes::Ibm3624NaturalPin(
                Ibm3624NaturalPin::builder()
                    .decimalization_table(GO_DECIM_TABLE)
                    .pin_validation_data("999999999999")
                    .pin_validation_data_pad_character("F")
                    .build()?,
            ))
            .send()
            .await?
            .encrypted_pin_block()
            .to_string();

        let (label, accept_code, reject_code): (&str, [u8; 2], [u8; 2]) = if use_ibm {
            // Current natural PIN (offset 0); change with correct then wrong current offset.
            let cur_block = data
                .generate_pin_data()
                .generation_key_identifier(&pvk_ibm_arn)
                .encryption_key_identifier(&zpk_arn)
                .primary_account_number(&pan)
                .pin_block_format(iso0())
                .generation_attributes(PinGenerationAttributes::Ibm3624NaturalPin(
                    Ibm3624NaturalPin::builder()
                        .decimalization_table(GO_DECIM_TABLE)
                        .pin_validation_data(&pan)
                        .pin_validation_data_pad_character("F")
                        .build()?,
                ))
                .send()
                .await?
                .encrypted_pin_block()
                .to_string();
            let good = encode_du(
                &zpk_label,
                &pvk_ibm_label,
                &cur_block,
                &pan,
                GO_DECIM_TABLE,
                &pan,
                "0000FFFFFFFF",
                &new_block,
            );
            let wrong_offset = random_wrong_offset(&mut rng);
            let bad = encode_du(
                &zpk_label,
                &pvk_ibm_label,
                &cur_block,
                &pan,
                GO_DECIM_TABLE,
                &pan,
                &wrong_offset,
                &new_block,
            );
            let a = du.handle(b"DU", &good, &state).await.error_code;
            let r = du.handle(b"DU", &bad, &state).await.error_code;
            ("DU/IBM", a, r)
        } else {
            // Current Visa PVV; change with correct then corrupted current PVV.
            let gen = data
                .generate_pin_data()
                .generation_key_identifier(&pvk_visa_arn)
                .encryption_key_identifier(&zpk_arn)
                .primary_account_number(&pan)
                .pin_block_format(iso0())
                .generation_attributes(PinGenerationAttributes::VisaPin(
                    VisaPin::builder().pin_verification_key_index(1).build()?,
                ))
                .send()
                .await?;
            let cur_block = gen.encrypted_pin_block().to_string();
            let pvv = gen
                .pin_data()
                .and_then(|d| d.as_verification_value().ok().cloned())
                .ok_or_else(|| anyhow::anyhow!("no Visa PVV"))?;
            let good = encode_cu(
                &zpk_label,
                &pvk_visa_label,
                &cur_block,
                &pan,
                "1",
                &pvv,
                &new_block,
            );
            let bad = encode_cu(
                &zpk_label,
                &pvk_visa_label,
                &cur_block,
                &pan,
                "1",
                &corrupt(&mut rng, &pvv, false),
                &new_block,
            );
            let a = cu.handle(b"CU", &good, &state).await.error_code;
            let r = cu.handle(b"CU", &bad, &state).await.error_code;
            ("CU/Visa", a, r)
        };

        if let Err(e) = assert_discriminates(label, case_idx, accept_code, reject_code, &pan) {
            eprintln!(
                "{}",
                replay_hint(
                    "pin_change_du_cu_discrimination_differential",
                    LABEL,
                    case_idx
                )
            );
            result = Err(e);
            break;
        }
        eprintln!(
            "case={case_idx:02} OK {label} correct-current-PIN=00 wrong-current-PIN=01 pan={pan}"
        );
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── Out-of-bounds / malformed input robustness ────────────────────────────────
//
// The discrimination tests above use well-formed-but-wrong credentials. This test
// pushes the other axis: intentionally out-of-bounds inputs — wrong length,
// non-hex where hex is expected, empty, oversized, and truncated wire frames. The
// property is stronger than "reject": a verify handler must NEVER return 00
// (accept) for malformed input, and must NEVER panic (the test completing is the
// no-panic proof). The malformed set is regenerated with random junk each run.

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn verify_rejects_malformed_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "verify_rejects_malformed_differential: out-of-bounds inputs are never accepted (never 00), \
         never panic"
    );

    let (cpc, data) = aws_clients().await;
    let specs = [
        KeySpec {
            role: "CVK",
            wire_label: CVK_WIRE_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31C0CardVerificationKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
        KeySpec {
            role: "MAK",
            wire_label: MAK_WIRE_LABEL,
            algorithm: KeyAlgorithm::Tdes2Key,
            key_usage: KeyUsage::Tr31M3Iso97973MacKey,
            modes: KeyModesOfUse::builder().generate(true).verify(true).build(),
        },
    ];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let cvk_label = keys.wire_label("CVK").to_string();
    let mak_label = keys.wire_label("MAK").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let cy = registry.get(b"CY").expect("CY registered");
    let m8 = registry.get(b"M8").expect("M8 registered");

    const LABEL: &str = "verify_rejects_malformed";
    let pan = "12345678901234";
    let (expiry, svc, msg) = ("3012", "201", "AABBCCDDEE112233");
    let run = cases_to_run();
    eprintln!(
        "verify_rejects_malformed_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );
    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        // Half the cases target the hex MAC field, half the decimal CVV field.
        let target_mac = rng.random_bool(0.5);
        let hex = target_mac;

        // Pick a random out-of-bounds strategy and build the malformed input.
        let (desc, cmd, wire): (String, &[u8], Vec<u8>) = if rng.random_bool(0.25) {
            // Truncated / arbitrary-byte wire frame — the parser must not panic or
            // index out of bounds. Real garbage bytes, not just ASCII.
            let n = rng.random_range(0..40_usize);
            let w: Vec<u8> = (0..n).map(|_| rng.random_range(0..=255_u8)).collect();
            if target_mac {
                (format!("M8 wire=junk[{n}]"), b"M8", w)
            } else {
                (format!("CY wire=junk[{n}]"), b"CY", w)
            }
        } else {
            // Well-formed frame carrying an out-of-bounds credential field.
            let bad: String = match rng.random_range(0..4) {
                0 => String::new(), // empty
                1 => (0..rng.random_range(1..12)) // wrong length
                    .map(|_| rand_symbol(&mut rng, hex))
                    .collect(),
                2 => (0..if hex { 8 } else { 3 }) // right length, out-of-alphabet
                    .map(|_| char::from(b"GHIJKLMNOPQRSTUVWXYZ"[rng.random_range(0..20)]))
                    .collect(),
                _ => (0..rng.random_range(20..48)) // oversized
                    .map(|_| rand_symbol(&mut rng, hex))
                    .collect(),
            };
            if target_mac {
                (
                    format!("M8 mac={bad:?}"),
                    b"M8",
                    encode_m8(&mak_label, b'3', b'0', msg, &bad),
                )
            } else {
                (
                    format!("CY cvv={bad:?}"),
                    b"CY",
                    encode_cy(&cvk_label, &bad, pan, expiry, svc),
                )
            }
        };

        let handler = if target_mac { &m8 } else { &cy };
        let out = handler.handle(cmd, &wire, &state).await;
        if &out.error_code == b"00" {
            eprintln!(
                "{}",
                replay_hint("verify_rejects_malformed_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} malformed input was ACCEPTED (00) — critical: {desc}"
            ));
            break;
        }
        eprintln!(
            "case={case_idx:02} OK rejected({}) {desc}",
            String::from_utf8_lossy(&out.error_code)
        );
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── ARQC accept-path KS (live differential) ──────────────────────────────────
//
// The ARQC-verify family (K2/KS/KQ/KW) had no live accept-path: verifying needs a
// VALID ARQC. APC's generate_auth_request_cryptogram mints one from an IMK-AC (E0)
// — available in aws-sdk-paymentcryptographydata >= 1.110. So the oracle is APC
// itself: APC mints a valid ARQC under a created E0 key, the proxy's KS handler
// verifies it through APC, and we assert ACCEPT — plus a corrupted ARQC must be
// rejected (01). KS uses SessionKeyDerivation::Emv2000 + EmvOptionA (no UN), so the
// mint uses the same attributes. The handler EMV-pads the txn before the APC call,
// so we mint over the padded txn to keep both sides byte-identical.
const KS_E0_WIRE_LABEL: &str = "U0000000000000000000000000000KSE0";

/// Encode a KS wire frame per PUGD0537-004 Rev A p.488. Binary fields.
fn encode_ks(key_label: &str, pan_seq: &[u8], atc: [u8; 2], txn: &[u8], arqc: &[u8]) -> Vec<u8> {
    let mut v = b"00E".to_vec(); // key type 3H ASCII — consumed
    v.extend_from_slice(key_label.as_bytes());
    v.extend_from_slice(pan_seq); // 8B BCD
    v.extend_from_slice(&atc); // 2B ATC (no UN for KS)
    let len = u16::try_from(txn.len()).expect("txn < 64KiB");
    v.extend_from_slice(&len.to_be_bytes()); // 2B BE TxnLen
    v.extend_from_slice(txn); // nB txn data
    v.push(0x3B); // delimiter
    v.extend_from_slice(arqc); // 8B cryptogram
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn arqc_verify_ks_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "arqc_verify_ks_differential: grounding crypto=apc \
         wire=diff-xprov(APC generate_auth_request_cryptogram -> proxy KS verify)"
    );

    use apc_proxy::handlers::thales::common::emv_pad;
    use aws_sdk_paymentcryptographydata::types::{
        MajorKeyDerivationMode, SessionKeyDerivation, SessionKeyEmv2000,
    };

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "E0",
        wire_label: KS_E0_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31E0EmvMkeyAppCryptograms,
        modes: KeyModesOfUse::builder().derive_key(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let e0_arn = keys.arn("E0").to_string();
    let e0_label = keys.wire_label("E0").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let ks = registry.get(b"KS").expect("KS handler registered");

    const LABEL: &str = "arqc_verify_ks";
    let run = cases_to_run();
    eprintln!(
        "arqc_verify_ks_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let seq = format!("{:02}", edge_biased(&mut rng, 0, 99, &[0, 1, 99]));
        let atc_val = edge_biased(&mut rng, 0, 0xFFFF, &[1, 0x2A, 0xFFFF]) as u16;
        let atc = atc_val.to_be_bytes();
        let atc_hex = hex_upper(&atc);

        // Raw txn (1..24 bytes); the KS handler EMV-pads it, so mint over the pad.
        let txn_len = edge_biased(&mut rng, 1, 24, &[1, 7, 8, 16]);
        let txn = hex_str_to_bytes(&gen_hex_message(&mut rng, txn_len));
        let padded_txn_hex = hex_upper(&emv_pad(&txn));

        let session = SessionKeyDerivation::Emv2000(
            SessionKeyEmv2000::builder()
                .primary_account_number(&pan)
                .pan_sequence_number(&seq)
                .application_transaction_counter(&atc_hex)
                .build()?,
        );

        // 1) APC mints a valid ARQC over the padded txn.
        let arqc_hex = data
            .generate_auth_request_cryptogram()
            .key_identifier(&e0_arn)
            .transaction_data(&padded_txn_hex)
            .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
            .session_key_derivation_attributes(session)
            .send()
            .await?
            .auth_request_cryptogram()
            .to_string();
        let arqc = hex_str_to_bytes(&arqc_hex);

        // 2) Proxy KS verify — must ACCEPT (error_code 00).
        let wire = encode_ks(&e0_label, &pan_seq_bcd(&pan, &seq), atc, &txn, &arqc);
        let proxy = ks.handle(b"KS", &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_ks_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} KS rejected a VALID ARQC: error_code={} \
                 (pan={pan} seq={seq} atc={atc_hex} arqc={arqc_hex})",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }

        // 3) Corrupted ARQC (flip one bit) — must be REJECTED (01).
        let mut bad = arqc.clone();
        bad[0] ^= 0x01;
        let wire_bad = encode_ks(&e0_label, &pan_seq_bcd(&pan, &seq), atc, &txn, &bad);
        let proxy_bad = ks.handle(b"KS", &wire_bad, &state).await;
        if &proxy_bad.error_code != b"01" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_ks_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} KS accepted a CORRUPTED ARQC: error_code={} (expected 01)",
                String::from_utf8_lossy(&proxy_bad.error_code),
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK pan={pan} seq={seq} atc={atc_hex} txn_len={txn_len} arqc={arqc_hex}");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── ARQC accept-path JS (UnionPay, live differential) ────────────────────────
//
// JS uses the SAME Emv2000 + Option A derivation as KS, so the ARQC is minted the
// same way; only the wire frame differs (UnionPay/CUP layout, per PUGD0538-003
// §7 p.122). APC mints a valid ARQC, the proxy JS handler verifies it and ACCEPTS,
// and a corrupted ARQC is rejected (JT / error 01).
const JS_E0_WIRE_LABEL: &str = "U0000000000000000000000000000JSE0";

/// Encode a JS (UnionPay) verify-only wire frame. Binary fields except TxnLen (2H
/// ASCII) and the mode/scheme/padding flags.
fn encode_js(key_label: &str, pan_seq: &[u8], atc: [u8; 2], txn: &[u8], arqc: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(b'0'); // mode: verify only
    v.push(b'1'); // scheme ID: CUP (consumed)
    v.extend_from_slice(key_label.as_bytes()); // 'U'+32H (no key-type prefix)
    v.extend_from_slice(pan_seq); // 8B BCD
    v.extend_from_slice(&atc); // 2B ATC
    v.push(b'0'); // padding flag: none (consumed)
    v.extend_from_slice(format!("{:02X}", txn.len()).as_bytes()); // TxnLen 2H ASCII
    v.extend_from_slice(txn); // nB txn data
    v.push(0x3B); // delimiter
    v.extend_from_slice(arqc); // 8B cryptogram
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn arqc_verify_js_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "arqc_verify_js_differential: grounding crypto=apc \
         wire=diff-xprov(APC generate_auth_request_cryptogram -> proxy JS verify)"
    );

    use apc_proxy::handlers::thales::common::emv_pad;
    use aws_sdk_paymentcryptographydata::types::{
        MajorKeyDerivationMode, SessionKeyDerivation, SessionKeyEmv2000,
    };

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "E0",
        wire_label: JS_E0_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31E0EmvMkeyAppCryptograms,
        modes: KeyModesOfUse::builder().derive_key(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let e0_arn = keys.arn("E0").to_string();
    let e0_label = keys.wire_label("E0").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let js = registry.get(b"JS").expect("JS handler registered");

    const LABEL: &str = "arqc_verify_js";
    let run = cases_to_run();
    eprintln!(
        "arqc_verify_js_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let seq = format!("{:02}", edge_biased(&mut rng, 0, 99, &[0, 1, 99]));
        let atc_val = edge_biased(&mut rng, 0, 0xFFFF, &[1, 0x2A, 0xFFFF]) as u16;
        let atc = atc_val.to_be_bytes();
        let atc_hex = hex_upper(&atc);

        let txn_len = edge_biased(&mut rng, 1, 24, &[1, 7, 8, 16]);
        let txn = hex_str_to_bytes(&gen_hex_message(&mut rng, txn_len));
        let padded_txn_hex = hex_upper(&emv_pad(&txn));

        let session = SessionKeyDerivation::Emv2000(
            SessionKeyEmv2000::builder()
                .primary_account_number(&pan)
                .pan_sequence_number(&seq)
                .application_transaction_counter(&atc_hex)
                .build()?,
        );

        let arqc_hex = data
            .generate_auth_request_cryptogram()
            .key_identifier(&e0_arn)
            .transaction_data(&padded_txn_hex)
            .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
            .session_key_derivation_attributes(session)
            .send()
            .await?
            .auth_request_cryptogram()
            .to_string();
        let arqc = hex_str_to_bytes(&arqc_hex);

        let wire = encode_js(&e0_label, &pan_seq_bcd(&pan, &seq), atc, &txn, &arqc);
        let proxy = js.handle(b"JS", &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_js_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} JS rejected a VALID ARQC: error_code={} \
                 (pan={pan} seq={seq} atc={atc_hex} arqc={arqc_hex})",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }

        let mut bad = arqc.clone();
        bad[0] ^= 0x01;
        let wire_bad = encode_js(&e0_label, &pan_seq_bcd(&pan, &seq), atc, &txn, &bad);
        let proxy_bad = js.handle(b"JS", &wire_bad, &state).await;
        if &proxy_bad.error_code != b"01" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_js_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} JS accepted a CORRUPTED ARQC: error_code={} (expected 01)",
                String::from_utf8_lossy(&proxy_bad.error_code),
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK pan={pan} seq={seq} atc={atc_hex} txn_len={txn_len} arqc={arqc_hex}");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── Issuer-script MAC JU/KU (EMV secure messaging integrity, live differential) ─
//
// JU/KU Mode-0 generate an issuer-script integrity MAC. The proxy maps the wire
// onto APC generate_mac with EmvMac attributes (APC does the IMK-SMI -> SK-SMI
// derivation). This differential confirms the proxy's wire parse + EmvMac mapping
// equals a direct APC generate_mac(EmvMac) with the same fields, swept across the
// reachable Scheme IDs:
//   idx%5==0  JU '1' UnionPay  -> EMV2000    + ATC
//         1  KU '0' Visa       -> VISA       + ATC
//         2  KU '1' Mastercard -> MASTERCARD + AC (8-byte RANDi)
//         3  KU '2' Amex       -> AMEX       + ATC
//         4  KU '5' JCB CVN04  -> EMV_COMMON + AC (length-prefixed message)
const SMI_E2_WIRE_LABEL: &str = "U0000000000000000000000000000SME2";

/// Encode a JU Mode-0 wire: mode '0' scheme '1' key PAN/Seq(8B) ATC(2B)
/// padflag '0' MacMsgLen(4H) msg ';'.
fn encode_ju(key_label: &str, pan_seq: &[u8], atc: [u8; 2], msg: &[u8]) -> Vec<u8> {
    let mut v = vec![b'0', b'1'];
    v.extend_from_slice(key_label.as_bytes());
    v.extend_from_slice(pan_seq);
    v.extend_from_slice(&atc);
    v.push(b'0'); // padding flag: proxy pads
    v.extend_from_slice(format!("{:04X}", msg.len()).as_bytes());
    v.extend_from_slice(msg);
    v.push(0x3B);
    v
}

/// Encode a KU Mode-0 wire for schemes 0/1/2/5. `length_prefixed` (scheme '5')
/// adds a 4H message-length field; the others are delimited only.
fn encode_ku(
    key_label: &str,
    scheme: u8,
    pan_seq: &[u8],
    skd: [u8; 8],
    msg: &[u8],
    length_prefixed: bool,
) -> Vec<u8> {
    let mut v = vec![b'0', scheme];
    v.extend_from_slice(key_label.as_bytes());
    v.extend_from_slice(pan_seq);
    v.extend_from_slice(&skd);
    if length_prefixed {
        v.extend_from_slice(format!("{:04X}", msg.len()).as_bytes());
    }
    v.extend_from_slice(msg);
    v.push(0x3B);
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn issuer_script_mac_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "issuer_script_mac_differential: grounding crypto=apc \
         wire=diff-xprov(proxy JU/KU generate MAC == direct APC generate_mac EmvMac)"
    );

    use apc_proxy::handlers::thales::common::emv_pad;
    use aws_sdk_paymentcryptographydata::types::{
        MacAlgorithmEmv, MacAttributes, MajorKeyDerivationMode, SessionKeyDerivationMode,
        SessionKeyDerivationValue,
    };

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "E2",
        wire_label: SMI_E2_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31E2EmvMkeyIntegrity,
        modes: KeyModesOfUse::builder().derive_key(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let e2_arn = keys.arn("E2").to_string();
    let e2_label = keys.wire_label("E2").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();

    const LABEL: &str = "issuer_script_mac";
    let run = cases_to_run();
    eprintln!(
        "issuer_script_mac_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let seq = format!("{:02}", edge_biased(&mut rng, 0, 99, &[0, 1, 99]));
        let pan_seq = pan_seq_bcd(&pan, &seq);
        let atc_val = edge_biased(&mut rng, 0, 0xFFFF, &[1, 0x2A, 0xFFFF]) as u16;
        let atc = atc_val.to_be_bytes();
        let atc_hex = hex_upper(&atc);
        // 8-byte AC / RANDi seed for the AC-based schemes.
        let ac_seed = hex_str_to_bytes(&gen_hex_message(&mut rng, 8));
        let ac_hex = hex_upper(&ac_seed);
        let ac_8: [u8; 8] = ac_seed.clone().try_into().unwrap();
        // ATC left-zero-padded to 8 bytes for the KU session-key-data field.
        let atc_skd: [u8; 8] = [0, 0, 0, 0, 0, 0, atc[0], atc[1]];

        let msg_len = edge_biased(&mut rng, 1, 24, &[1, 7, 8, 16]);
        // The KU schemes 0/1/2 frame the message by a ';' (0x3B) delimiter with no
        // length, so a 0x3B byte inside the message is not representable in that
        // wire (a payShield limitation, not a proxy bug). Sanitize it out here so
        // the differential exercises the mapping rather than that framing edge.
        let msg: Vec<u8> = hex_str_to_bytes(&gen_hex_message(&mut rng, msg_len))
            .into_iter()
            .map(|b| if b == 0x3B { 0x3A } else { b })
            .collect();
        let padded_msg_hex = hex_upper(&emv_pad(&msg));

        // (command, wire, session_mode, session_value) per swept scheme.
        let variant = case_idx % 5;
        let (cmd, wire, session_mode, session_value): (
            &[u8],
            Vec<u8>,
            SessionKeyDerivationMode,
            SessionKeyDerivationValue,
        ) = match variant {
            0 => (
                b"JU",
                encode_ju(&e2_label, &pan_seq, atc, &msg),
                SessionKeyDerivationMode::Emv2000,
                SessionKeyDerivationValue::ApplicationTransactionCounter(atc_hex.clone()),
            ),
            1 => (
                b"KU",
                encode_ku(&e2_label, b'0', &pan_seq, atc_skd, &msg, false),
                SessionKeyDerivationMode::Visa,
                SessionKeyDerivationValue::ApplicationTransactionCounter(atc_hex.clone()),
            ),
            2 => (
                b"KU",
                encode_ku(&e2_label, b'1', &pan_seq, ac_8, &msg, false),
                SessionKeyDerivationMode::MastercardSessionKey,
                SessionKeyDerivationValue::ApplicationCryptogram(ac_hex.clone()),
            ),
            3 => (
                b"KU",
                encode_ku(&e2_label, b'2', &pan_seq, atc_skd, &msg, false),
                SessionKeyDerivationMode::Amex,
                SessionKeyDerivationValue::ApplicationTransactionCounter(atc_hex.clone()),
            ),
            _ => (
                b"KU",
                encode_ku(&e2_label, b'5', &pan_seq, ac_8, &msg, true),
                SessionKeyDerivationMode::EmvCommonSessionKey,
                SessionKeyDerivationValue::ApplicationCryptogram(ac_hex.clone()),
            ),
        };

        // 1) Proxy generates the MAC.
        let handler = registry.get(cmd).expect("JU/KU handler registered");
        let proxy = handler.handle(cmd, &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("issuer_script_mac_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} {} rejected a valid script: error_code={} (pan={pan} seq={seq})",
                String::from_utf8_lossy(cmd),
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }
        let proxy_mac = String::from_utf8(proxy.payload.to_vec())?;

        // 2) Oracle: direct APC generate_mac with EmvMac and the same mapped fields.
        let emv = MacAlgorithmEmv::builder()
            .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
            .primary_account_number(&pan)
            .pan_sequence_number(&seq)
            .session_key_derivation_mode(session_mode)
            .session_key_derivation_value(session_value)
            .build()?;
        let oracle_mac = data
            .generate_mac()
            .key_identifier(&e2_arn)
            .message_data(&padded_msg_hex)
            .generation_attributes(MacAttributes::EmvMac(emv))
            .mac_length(4)
            .send()
            .await?
            .mac()
            .to_string();

        if !proxy_mac.eq_ignore_ascii_case(&oracle_mac) {
            eprintln!(
                "{}",
                replay_hint("issuer_script_mac_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} {} MAC mismatch: proxy={proxy_mac} oracle={oracle_mac} \
                 (variant={variant} pan={pan} seq={seq} atc={atc_hex})",
                String::from_utf8_lossy(cmd),
            ));
            break;
        }

        eprintln!(
            "case={case_idx:02} OK cmd={} variant={variant} pan={pan} seq={seq} MAC={proxy_mac}",
            String::from_utf8_lossy(cmd)
        );
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── ARQC accept-path KQ (Mastercard M/Chip, live differential) ───────────────
//
// KQ scheme '1' = Mastercard proprietary SKD (Option A + UN). Confirms the proxy
// forwards the Unpredictable Number to APC's SessionKeyDerivation::Mastercard: APC
// mints a valid ARQC (Mastercard, Option A) under a created E0 IMK, the proxy KQ
// handler verifies it and ACCEPTS, and a corrupted ARQC is rejected (01).
const KQ_E0_WIRE_LABEL: &str = "U0000000000000000000000000000KQE0";

/// Encode a KQ verify-only wire frame per PUGD0537-004 Rev A p.468. Binary fields.
fn encode_kq(
    scheme: u8,
    key_label: &str,
    pan_seq: &[u8],
    atc: [u8; 2],
    un: [u8; 4],
    txn: &[u8],
    arqc: &[u8],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(b'0'); // mode: verify only
    v.push(scheme); // scheme ID ('1'=Mastercard, '2'=Amex)
    v.extend_from_slice(b"00E"); // key type 3H ASCII — consumed
    v.extend_from_slice(key_label.as_bytes());
    v.extend_from_slice(pan_seq); // 8B BCD
    v.extend_from_slice(&atc); // 2B ATC
    v.extend_from_slice(&un); // 4B UN
    let len = u16::try_from(txn.len()).expect("txn < 64KiB");
    v.extend_from_slice(&len.to_be_bytes()); // 2B BE TxnLen
    v.extend_from_slice(txn); // nB txn data
    v.push(0x3B); // delimiter
    v.extend_from_slice(arqc); // 8B cryptogram
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn arqc_verify_kq_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "arqc_verify_kq_differential: grounding crypto=apc \
         wire=diff-xprov(APC generate_auth_request_cryptogram Mastercard -> proxy KQ verify)"
    );

    use apc_proxy::handlers::thales::common::emv_pad;
    use aws_sdk_paymentcryptographydata::types::{
        MajorKeyDerivationMode, SessionKeyDerivation, SessionKeyMastercard,
    };

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "E0",
        wire_label: KQ_E0_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31E0EmvMkeyAppCryptograms,
        modes: KeyModesOfUse::builder().derive_key(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let e0_arn = keys.arn("E0").to_string();
    let e0_label = keys.wire_label("E0").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let kq = registry.get(b"KQ").expect("KQ handler registered");

    const LABEL: &str = "arqc_verify_kq";
    let run = cases_to_run();
    eprintln!(
        "arqc_verify_kq_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let seq = format!("{:02}", edge_biased(&mut rng, 0, 99, &[0, 1, 99]));
        let atc_val = edge_biased(&mut rng, 0, 0xFFFF, &[1, 0x2A, 0xFFFF]) as u16;
        let atc = atc_val.to_be_bytes();
        let atc_hex = hex_upper(&atc);

        let un: [u8; 4] = hex_str_to_bytes(&gen_hex_message(&mut rng, 4))
            .try_into()
            .expect("4 bytes");
        let un_hex = hex_upper(&un);

        let txn_len = edge_biased(&mut rng, 1, 24, &[1, 7, 8, 16]);
        let txn = hex_str_to_bytes(&gen_hex_message(&mut rng, txn_len));
        let padded_txn_hex = hex_upper(&emv_pad(&txn));

        let session = SessionKeyDerivation::Mastercard(
            SessionKeyMastercard::builder()
                .primary_account_number(&pan)
                .pan_sequence_number(&seq)
                .application_transaction_counter(&atc_hex)
                .unpredictable_number(&un_hex)
                .build()?,
        );

        let arqc_hex = data
            .generate_auth_request_cryptogram()
            .key_identifier(&e0_arn)
            .transaction_data(&padded_txn_hex)
            .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
            .session_key_derivation_attributes(session)
            .send()
            .await?
            .auth_request_cryptogram()
            .to_string();
        let arqc = hex_str_to_bytes(&arqc_hex);

        // scheme '1' = Mastercard
        let wire = encode_kq(
            b'1',
            &e0_label,
            &pan_seq_bcd(&pan, &seq),
            atc,
            un,
            &txn,
            &arqc,
        );
        let proxy = kq.handle(b"KQ", &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_kq_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} KQ rejected a VALID Mastercard ARQC: error_code={} \
                 (pan={pan} seq={seq} atc={atc_hex} un={un_hex} arqc={arqc_hex})",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }

        let mut bad = arqc.clone();
        bad[0] ^= 0x01;
        let wire_bad = encode_kq(
            b'1',
            &e0_label,
            &pan_seq_bcd(&pan, &seq),
            atc,
            un,
            &txn,
            &bad,
        );
        let proxy_bad = kq.handle(b"KQ", &wire_bad, &state).await;
        if &proxy_bad.error_code != b"01" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_kq_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} KQ accepted a CORRUPTED ARQC: error_code={} (expected 01)",
                String::from_utf8_lossy(&proxy_bad.error_code),
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK pan={pan} seq={seq} atc={atc_hex} un={un_hex} txn_len={txn_len} arqc={arqc_hex}");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── ARQC accept-path KQ / Amex (scheme '2', live differential) ───────────────
//
// KQ scheme '2' = Amex AEIPS (Option A + Amex SKD; SessionKeyAmex = PAN + PSN, no
// ATC/UN). The wire still carries ATC and UN fields (ignored by the Amex method).
#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn arqc_verify_kq_amex_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "arqc_verify_kq_amex_differential: grounding crypto=apc \
         wire=diff-xprov(APC generate_auth_request_cryptogram Amex -> proxy KQ verify)"
    );

    use apc_proxy::handlers::thales::common::emv_pad;
    use aws_sdk_paymentcryptographydata::types::{
        MajorKeyDerivationMode, SessionKeyAmex, SessionKeyDerivation,
    };

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "E0",
        wire_label: "U0000000000000000000000000000QAE0",
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31E0EmvMkeyAppCryptograms,
        modes: KeyModesOfUse::builder().derive_key(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let e0_arn = keys.arn("E0").to_string();
    let e0_label = keys.wire_label("E0").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let kq = registry.get(b"KQ").expect("KQ handler registered");

    const LABEL: &str = "arqc_verify_kq_amex";
    let run = cases_to_run();
    eprintln!(
        "arqc_verify_kq_amex_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let seq = format!("{:02}", edge_biased(&mut rng, 0, 99, &[0, 1, 99]));
        let atc_val = edge_biased(&mut rng, 0, 0xFFFF, &[1, 0x2A, 0xFFFF]) as u16;
        let atc = atc_val.to_be_bytes();
        let un: [u8; 4] = hex_str_to_bytes(&gen_hex_message(&mut rng, 4))
            .try_into()
            .expect("4 bytes");

        let txn_len = edge_biased(&mut rng, 1, 24, &[1, 7, 8, 16]);
        let txn = hex_str_to_bytes(&gen_hex_message(&mut rng, txn_len));
        let padded_txn_hex = hex_upper(&emv_pad(&txn));

        // Amex session: PAN + PSN only.
        let session = SessionKeyDerivation::Amex(
            SessionKeyAmex::builder()
                .primary_account_number(&pan)
                .pan_sequence_number(&seq)
                .build()?,
        );

        let arqc_hex = data
            .generate_auth_request_cryptogram()
            .key_identifier(&e0_arn)
            .transaction_data(&padded_txn_hex)
            .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
            .session_key_derivation_attributes(session)
            .send()
            .await?
            .auth_request_cryptogram()
            .to_string();
        let arqc = hex_str_to_bytes(&arqc_hex);

        // scheme '2' = Amex
        let wire = encode_kq(
            b'2',
            &e0_label,
            &pan_seq_bcd(&pan, &seq),
            atc,
            un,
            &txn,
            &arqc,
        );
        let proxy = kq.handle(b"KQ", &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_kq_amex_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} KQ rejected a VALID Amex ARQC: error_code={} \
                 (pan={pan} seq={seq} arqc={arqc_hex})",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }

        let mut bad = arqc.clone();
        bad[0] ^= 0x01;
        let wire_bad = encode_kq(
            b'2',
            &e0_label,
            &pan_seq_bcd(&pan, &seq),
            atc,
            un,
            &txn,
            &bad,
        );
        let proxy_bad = kq.handle(b"KQ", &wire_bad, &state).await;
        if &proxy_bad.error_code != b"01" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_kq_amex_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} KQ accepted a CORRUPTED Amex ARQC: error_code={} (expected 01)",
                String::from_utf8_lossy(&proxy_bad.error_code),
            ));
            break;
        }

        eprintln!(
            "case={case_idx:02} OK (Amex) pan={pan} seq={seq} txn_len={txn_len} arqc={arqc_hex}"
        );
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── ARQC accept-path KW (Option A: EMV2000 + EMV Common, live differential) ───
//
// KW's Scheme ID selects major mode + session method. This sweeps the two Option-A
// schemes: '0' = Option A + EMV2000, '2' = Option A + EMV Common. (Option B schemes
// '1'/'3' need a PAN > 16 digits, which the 8-byte BCD PAN field can't carry — see
// the EMV PAN-length gap — so they stay uncovered.)
#[allow(clippy::too_many_arguments)]
fn encode_kw(
    scheme: u8,
    deriv_method: u8,
    key_label: &str,
    pan_seq: &[u8],
    atc: [u8; 2],
    un: [u8; 4],
    txn: &[u8],
    arqc: &[u8],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(b'0'); // mode: verify only
    v.push(scheme); // scheme ID
    v.push(deriv_method); // derivation method 'A'/'B' (consumed)
    v.extend_from_slice(b"00E"); // key type 3H ASCII
    v.extend_from_slice(key_label.as_bytes());
    v.extend_from_slice(pan_seq); // 8B BCD
    v.extend_from_slice(&atc); // 2B ATC
    v.extend_from_slice(&un); // 4B UN
    let len = u16::try_from(txn.len()).expect("txn < 64KiB");
    v.extend_from_slice(&len.to_be_bytes()); // 2B BE TxnLen
    v.extend_from_slice(txn); // nB txn data
    v.push(0x3B); // delimiter
    v.extend_from_slice(arqc); // 8B cryptogram
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn arqc_verify_kw_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "arqc_verify_kw_differential: grounding crypto=apc \
         wire=diff-xprov(APC generate_auth_request_cryptogram Option-A EMV2000/EMV-Common -> proxy KW verify)"
    );

    use apc_proxy::handlers::thales::common::emv_pad;
    use aws_sdk_paymentcryptographydata::types::{
        MajorKeyDerivationMode, SessionKeyDerivation, SessionKeyEmv2000, SessionKeyEmvCommon,
    };

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "E0",
        wire_label: "U0000000000000000000000000000KWE0",
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31E0EmvMkeyAppCryptograms,
        modes: KeyModesOfUse::builder().derive_key(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let e0_arn = keys.arn("E0").to_string();
    let e0_label = keys.wire_label("E0").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let kw = registry.get(b"KW").expect("KW handler registered");

    const LABEL: &str = "arqc_verify_kw";
    let run = cases_to_run();
    eprintln!(
        "arqc_verify_kw_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let seq = format!("{:02}", edge_biased(&mut rng, 0, 99, &[0, 1, 99]));
        let atc_val = edge_biased(&mut rng, 0, 0xFFFF, &[1, 0x2A, 0xFFFF]) as u16;
        let atc = atc_val.to_be_bytes();
        let atc_hex = hex_upper(&atc);
        let un: [u8; 4] = hex_str_to_bytes(&gen_hex_message(&mut rng, 4))
            .try_into()
            .expect("4 bytes");
        let txn_len = edge_biased(&mut rng, 1, 24, &[1, 7, 8, 16]);
        let txn = hex_str_to_bytes(&gen_hex_message(&mut rng, txn_len));
        let padded_txn_hex = hex_upper(&emv_pad(&txn));

        // Sweep all four A/B-convention schemes with an explicit Derivation Method
        // byte of 'A'. Under the Scheme-ID even/odd convention, '1' and '3' (odd)
        // would derive Option B and fail (no >16-digit PAN); honoring the explicit
        // byte (#23) gives Option A, so they verify. The Scheme ID selects only the
        // session-key method: '0'/'1' → EMV2000, '2'/'3' → EMV Common.
        let (scheme, method_label) = match case_idx % 4 {
            0 => (b'0', "sch0 EMV2000"),
            1 => (b'1', "sch1 EMV2000 (odd, byte=A)"),
            2 => (b'2', "sch2 EMV-Common"),
            _ => (b'3', "sch3 EMV-Common (odd, byte=A)"),
        };
        let session = if scheme == b'2' || scheme == b'3' {
            SessionKeyDerivation::EmvCommon(
                SessionKeyEmvCommon::builder()
                    .primary_account_number(&pan)
                    .pan_sequence_number(&seq)
                    .application_transaction_counter(&atc_hex)
                    .build()?,
            )
        } else {
            SessionKeyDerivation::Emv2000(
                SessionKeyEmv2000::builder()
                    .primary_account_number(&pan)
                    .pan_sequence_number(&seq)
                    .application_transaction_counter(&atc_hex)
                    .build()?,
            )
        };

        let arqc_hex = data
            .generate_auth_request_cryptogram()
            .key_identifier(&e0_arn)
            .transaction_data(&padded_txn_hex)
            .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
            .session_key_derivation_attributes(session)
            .send()
            .await?
            .auth_request_cryptogram()
            .to_string();
        let arqc = hex_str_to_bytes(&arqc_hex);

        // Derivation-method byte 'A' (Option A) — consumed by the handler.
        let wire = encode_kw(
            scheme,
            b'A',
            &e0_label,
            &pan_seq_bcd(&pan, &seq),
            atc,
            un,
            &txn,
            &arqc,
        );
        let proxy = kw.handle(b"KW", &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_kw_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} KW rejected a VALID {method_label} ARQC: error_code={} \
                 (pan={pan} seq={seq} atc={atc_hex} arqc={arqc_hex})",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }

        let mut bad = arqc.clone();
        bad[0] ^= 0x01;
        let wire_bad = encode_kw(
            scheme,
            b'A',
            &e0_label,
            &pan_seq_bcd(&pan, &seq),
            atc,
            un,
            &txn,
            &bad,
        );
        let proxy_bad = kw.handle(b"KW", &wire_bad, &state).await;
        if &proxy_bad.error_code != b"01" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_kw_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} KW accepted a CORRUPTED {method_label} ARQC: error_code={} (expected 01)",
                String::from_utf8_lossy(&proxy_bad.error_code),
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK ({method_label}) pan={pan} seq={seq} atc={atc_hex} txn_len={txn_len} arqc={arqc_hex}");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── ARPC generation KQ Method 1 (live differential) ──────────────────────────
//
// KQ mode '1' verifies the ARQC and generates an ARPC (Method 1, ARC) via APC's
// verify_auth_request_cryptogram AuthResponseAttributes. The proxy's ARPC output
// must equal a direct APC verify call with the same ARC. Mastercard scheme ('1'),
// Option A.
const KQ_ARPC_E0_WIRE_LABEL: &str = "U0000000000000000000000000000QPE0";

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn arqc_verify_kq_arpc_method1_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "arqc_verify_kq_arpc_method1_differential: grounding crypto=apc \
         wire=diff-xprov(proxy KQ mode1 ARPC == APC verify AuthResponseAttributes)"
    );

    use apc_proxy::handlers::thales::common::emv_pad;
    use aws_sdk_paymentcryptographydata::types::{
        CryptogramAuthResponse, CryptogramVerificationArpcMethod1, MajorKeyDerivationMode,
        SessionKeyDerivation, SessionKeyMastercard,
    };

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "E0",
        wire_label: KQ_ARPC_E0_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31E0EmvMkeyAppCryptograms,
        modes: KeyModesOfUse::builder().derive_key(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let e0_arn = keys.arn("E0").to_string();
    let e0_label = keys.wire_label("E0").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let kq = registry.get(b"KQ").expect("KQ handler registered");

    const LABEL: &str = "arqc_verify_kq_arpc_m1";
    let run = cases_to_run();
    eprintln!(
        "arqc_verify_kq_arpc_method1_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let seq = format!("{:02}", edge_biased(&mut rng, 0, 99, &[0, 1, 99]));
        let atc_val = edge_biased(&mut rng, 0, 0xFFFF, &[1, 0x2A, 0xFFFF]) as u16;
        let atc = atc_val.to_be_bytes();
        let atc_hex = hex_upper(&atc);
        let un: [u8; 4] = hex_str_to_bytes(&gen_hex_message(&mut rng, 4))
            .try_into()
            .expect("4 bytes");
        let un_hex = hex_upper(&un);
        let arc: [u8; 2] = hex_str_to_bytes(&gen_hex_message(&mut rng, 2))
            .try_into()
            .expect("2 bytes");
        let arc_hex = hex_upper(&arc);

        let txn_len = edge_biased(&mut rng, 1, 24, &[1, 8, 16]);
        let txn = hex_str_to_bytes(&gen_hex_message(&mut rng, txn_len));
        let padded_txn_hex = hex_upper(&emv_pad(&txn));

        let session = || {
            SessionKeyDerivation::Mastercard(
                SessionKeyMastercard::builder()
                    .primary_account_number(&pan)
                    .pan_sequence_number(&seq)
                    .application_transaction_counter(&atc_hex)
                    .unpredictable_number(&un_hex)
                    .build()
                    .expect("mastercard session"),
            )
        };

        // APC mints the ARQC.
        let arqc_hex = data
            .generate_auth_request_cryptogram()
            .key_identifier(&e0_arn)
            .transaction_data(&padded_txn_hex)
            .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
            .session_key_derivation_attributes(session())
            .send()
            .await?
            .auth_request_cryptogram()
            .to_string();
        let arqc = hex_str_to_bytes(&arqc_hex);

        // Oracle: direct APC verify + ARPC Method 1.
        let ara = CryptogramAuthResponse::ArpcMethod1(
            CryptogramVerificationArpcMethod1::builder()
                .auth_response_code(&arc_hex)
                .build()?,
        );
        let apc_arpc = data
            .verify_auth_request_cryptogram()
            .key_identifier(&e0_arn)
            .transaction_data(&padded_txn_hex)
            .auth_request_cryptogram(&arqc_hex)
            .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
            .session_key_derivation_attributes(session())
            .auth_response_attributes(ara)
            .send()
            .await?
            .auth_response_value()
            .map(str::to_string)
            .unwrap_or_default();

        // Proxy KQ mode '1' (scheme '1' Mastercard): mode + scheme + 00E + key +
        // panseq + atc + un + txnlen(2B) + txn + 0x3B + arqc(8B) + arc(2B).
        let mut wire = vec![b'1', b'1'];
        wire.extend_from_slice(b"00E");
        wire.extend_from_slice(e0_label.as_bytes());
        wire.extend_from_slice(&pan_seq_bcd(&pan, &seq));
        wire.extend_from_slice(&atc);
        wire.extend_from_slice(&un);
        wire.extend_from_slice(&(txn.len() as u16).to_be_bytes());
        wire.extend_from_slice(&txn);
        wire.push(0x3B);
        wire.extend_from_slice(&arqc);
        wire.extend_from_slice(&arc);

        let proxy = kq.handle(b"KQ", &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_kq_arpc_method1_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} KQ mode1 error_code={} (pan={pan} arc={arc_hex} arqc={arqc_hex})",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }
        let proxy_arpc = String::from_utf8(proxy.payload.to_vec())?;
        if !proxy_arpc.eq_ignore_ascii_case(&apc_arpc) || proxy_arpc.is_empty() {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_kq_arpc_method1_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} ARPC mismatch: proxy={proxy_arpc} apc={apc_arpc} \
                 (pan={pan} arc={arc_hex} arqc={arqc_hex})"
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK pan={pan} arc={arc_hex} arpc={proxy_arpc}");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── ARPC generation KQ Method 2 (CSU, live differential) ─────────────────────
//
// KQ mode '2' generates an ARPC (Method 2, CSU + optional proprietary auth data)
// via APC's verify_auth_request_cryptogram AuthResponseAttributes. The proxy's
// ARPC must equal a direct APC verify with the same CSU/PAD. Sweeps the PAD length
// (including 0, where proprietary_authentication_data is omitted). Mastercard '1'.
const KQ_ARPC2_E0_WIRE_LABEL: &str = "U0000000000000000000000000000QP2E";

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn arqc_verify_kq_arpc_method2_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "arqc_verify_kq_arpc_method2_differential: grounding crypto=apc \
         wire=diff-xprov(proxy KQ mode2 ARPC == APC verify AuthResponseAttributes)"
    );

    use apc_proxy::handlers::thales::common::emv_pad;
    use aws_sdk_paymentcryptographydata::types::{
        CryptogramAuthResponse, CryptogramVerificationArpcMethod2, MajorKeyDerivationMode,
        SessionKeyDerivation, SessionKeyMastercard,
    };

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "E0",
        wire_label: KQ_ARPC2_E0_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31E0EmvMkeyAppCryptograms,
        modes: KeyModesOfUse::builder().derive_key(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let e0_arn = keys.arn("E0").to_string();
    let e0_label = keys.wire_label("E0").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let kq = registry.get(b"KQ").expect("KQ handler registered");

    const LABEL: &str = "arqc_verify_kq_arpc_m2";
    let run = cases_to_run();
    eprintln!(
        "arqc_verify_kq_arpc_method2_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let seq = format!("{:02}", edge_biased(&mut rng, 0, 99, &[0, 1, 99]));
        let atc_val = edge_biased(&mut rng, 0, 0xFFFF, &[1, 0x2A, 0xFFFF]) as u16;
        let atc = atc_val.to_be_bytes();
        let atc_hex = hex_upper(&atc);
        let un: [u8; 4] = hex_str_to_bytes(&gen_hex_message(&mut rng, 4))
            .try_into()
            .expect("4 bytes");
        let un_hex = hex_upper(&un);
        let csu: [u8; 4] = hex_str_to_bytes(&gen_hex_message(&mut rng, 4))
            .try_into()
            .expect("4 bytes");
        let csu_hex = hex_upper(&csu);
        // Proprietary auth data: 0..8 bytes (edge-biased over empty / partial / full).
        let pad_len = edge_biased(&mut rng, 0, 8, &[0, 4, 8]);
        let pad = hex_str_to_bytes(&gen_hex_message(&mut rng, pad_len));
        let pad_hex = hex_upper(&pad);

        let txn_len = edge_biased(&mut rng, 1, 24, &[1, 8, 16]);
        let txn = hex_str_to_bytes(&gen_hex_message(&mut rng, txn_len));
        let padded_txn_hex = hex_upper(&emv_pad(&txn));

        let session = || {
            SessionKeyDerivation::Mastercard(
                SessionKeyMastercard::builder()
                    .primary_account_number(&pan)
                    .pan_sequence_number(&seq)
                    .application_transaction_counter(&atc_hex)
                    .unpredictable_number(&un_hex)
                    .build()
                    .expect("mastercard session"),
            )
        };

        let arqc_hex = data
            .generate_auth_request_cryptogram()
            .key_identifier(&e0_arn)
            .transaction_data(&padded_txn_hex)
            .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
            .session_key_derivation_attributes(session())
            .send()
            .await?
            .auth_request_cryptogram()
            .to_string();
        let arqc = hex_str_to_bytes(&arqc_hex);

        // Oracle: direct APC verify + ARPC Method 2 (proprietary data only if non-empty).
        let mut m2b = CryptogramVerificationArpcMethod2::builder().card_status_update(&csu_hex);
        if !pad.is_empty() {
            m2b = m2b.proprietary_authentication_data(&pad_hex);
        }
        let ara = CryptogramAuthResponse::ArpcMethod2(m2b.build()?);
        let apc_arpc = data
            .verify_auth_request_cryptogram()
            .key_identifier(&e0_arn)
            .transaction_data(&padded_txn_hex)
            .auth_request_cryptogram(&arqc_hex)
            .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
            .session_key_derivation_attributes(session())
            .auth_response_attributes(ara)
            .send()
            .await?
            .auth_response_value()
            .map(str::to_string)
            .unwrap_or_default();

        // Proxy KQ mode '2': ... 0x3B + arqc(8B) + CSU(4B) + PAD_len(1B) + PAD(nB).
        let mut wire = vec![b'2', b'1'];
        wire.extend_from_slice(b"00E");
        wire.extend_from_slice(e0_label.as_bytes());
        wire.extend_from_slice(&pan_seq_bcd(&pan, &seq));
        wire.extend_from_slice(&atc);
        wire.extend_from_slice(&un);
        wire.extend_from_slice(&(txn.len() as u16).to_be_bytes());
        wire.extend_from_slice(&txn);
        wire.push(0x3B);
        wire.extend_from_slice(&arqc);
        wire.extend_from_slice(&csu);
        wire.push(pad.len() as u8);
        wire.extend_from_slice(&pad);

        let proxy = kq.handle(b"KQ", &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_kq_arpc_method2_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} KQ mode2 error_code={} (pan={pan} csu={csu_hex} pad={pad_hex} arqc={arqc_hex})",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }
        let proxy_arpc = String::from_utf8(proxy.payload.to_vec())?;
        if !proxy_arpc.eq_ignore_ascii_case(&apc_arpc) || proxy_arpc.is_empty() {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_kq_arpc_method2_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} ARPC(M2) mismatch: proxy={proxy_arpc} apc={apc_arpc} \
                 (pan={pan} csu={csu_hex} pad={pad_hex} arqc={arqc_hex})"
            ));
            break;
        }

        eprintln!(
            "case={case_idx:02} OK pan={pan} csu={csu_hex} pad_len={pad_len} arpc={proxy_arpc}"
        );
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}

// ── ARQC accept-path K2 (Mastercard, live differential) ──────────────────────
//
// After the #42 fix, K2 derives the ICC master key with Option A (the only mode
// its ≤14-digit PAN field can represent) + SessionKeyDerivation::Mastercard (UN).
// APC mints a valid Mastercard ARQC, the proxy K2 handler verifies it and ACCEPTS,
// and a corrupted ARQC is rejected (01). K2 has no mode/scheme bytes and no ARPC.
const K2_E0_WIRE_LABEL: &str = "U0000000000000000000000000000K2E0";

/// Encode a K2 wire frame per PUGD0537-004 Rev A p.485. Binary fields; UN present.
fn encode_k2(
    key_label: &str,
    pan_seq: &[u8],
    atc: [u8; 2],
    un: [u8; 4],
    txn: &[u8],
    arqc: &[u8],
) -> Vec<u8> {
    let mut v = b"00E".to_vec(); // key type 3H ASCII — consumed
    v.extend_from_slice(key_label.as_bytes());
    v.extend_from_slice(pan_seq); // 8B BCD
    v.extend_from_slice(&atc); // 2B ATC
    v.extend_from_slice(&un); // 4B UN (K2 only)
    v.extend_from_slice(&(txn.len() as u16).to_be_bytes()); // 2B BE TxnLen
    v.extend_from_slice(txn); // nB txn data
    v.push(0x3B); // delimiter
    v.extend_from_slice(arqc); // 8B cryptogram
    v
}

#[tokio::test]
#[ignore = "live APC; set APC_LIVE=1 to run"]
async fn arqc_verify_k2_differential() -> anyhow::Result<()> {
    if !live_enabled() {
        eprintln!("APC_LIVE not set; skipping live harness");
        return Ok(());
    }
    eprintln!(
        "arqc_verify_k2_differential: grounding crypto=apc \
         wire=diff-xprov(APC generate_auth_request_cryptogram Mastercard -> proxy K2 verify)"
    );

    use apc_proxy::handlers::thales::common::emv_pad;
    use aws_sdk_paymentcryptographydata::types::{
        MajorKeyDerivationMode, SessionKeyDerivation, SessionKeyMastercard,
    };

    let (cpc, data) = aws_clients().await;
    let specs = [KeySpec {
        role: "E0",
        wire_label: K2_E0_WIRE_LABEL,
        algorithm: KeyAlgorithm::Tdes2Key,
        key_usage: KeyUsage::Tr31E0EmvMkeyAppCryptograms,
        modes: KeyModesOfUse::builder().derive_key(true).build(),
    }];
    let keys = TestKeys::create(cpc.clone(), &specs).await?;
    let e0_arn = keys.arn("E0").to_string();
    let e0_label = keys.wire_label("E0").to_string();
    let provisioned_arns = keys.arns();
    let state = live_state(data.clone(), &keys);

    let registry = Registry::build();
    let k2 = registry.get(b"K2").expect("K2 handler registered");

    const LABEL: &str = "arqc_verify_k2";
    let run = cases_to_run();
    eprintln!(
        "arqc_verify_k2_differential: seed=0x{:016X} cases={:?}",
        rng_seed(),
        run
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in run {
        let mut rng = case_rng(LABEL, case_idx);
        let pan = gen_pan(&mut rng, 12);
        let seq = format!("{:02}", edge_biased(&mut rng, 0, 99, &[0, 1, 99]));
        let atc_val = edge_biased(&mut rng, 0, 0xFFFF, &[1, 0x2A, 0xFFFF]) as u16;
        let atc = atc_val.to_be_bytes();
        let atc_hex = hex_upper(&atc);
        let un: [u8; 4] = hex_str_to_bytes(&gen_hex_message(&mut rng, 4))
            .try_into()
            .expect("4 bytes");
        let un_hex = hex_upper(&un);
        let txn_len = edge_biased(&mut rng, 1, 24, &[1, 8, 16]);
        let txn = hex_str_to_bytes(&gen_hex_message(&mut rng, txn_len));
        let padded_txn_hex = hex_upper(&emv_pad(&txn));

        let session = SessionKeyDerivation::Mastercard(
            SessionKeyMastercard::builder()
                .primary_account_number(&pan)
                .pan_sequence_number(&seq)
                .application_transaction_counter(&atc_hex)
                .unpredictable_number(&un_hex)
                .build()?,
        );

        let arqc_hex = data
            .generate_auth_request_cryptogram()
            .key_identifier(&e0_arn)
            .transaction_data(&padded_txn_hex)
            .major_key_derivation_mode(MajorKeyDerivationMode::EmvOptionA)
            .session_key_derivation_attributes(session)
            .send()
            .await?
            .auth_request_cryptogram()
            .to_string();
        let arqc = hex_str_to_bytes(&arqc_hex);

        let wire = encode_k2(&e0_label, &pan_seq_bcd(&pan, &seq), atc, un, &txn, &arqc);
        let proxy = k2.handle(b"K2", &wire, &state).await;
        if &proxy.error_code != b"00" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_k2_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} K2 rejected a VALID ARQC: error_code={} (pan={pan} un={un_hex} arqc={arqc_hex})",
                String::from_utf8_lossy(&proxy.error_code),
            ));
            break;
        }

        let mut bad = arqc.clone();
        bad[0] ^= 0x01;
        let wire_bad = encode_k2(&e0_label, &pan_seq_bcd(&pan, &seq), atc, un, &txn, &bad);
        let proxy_bad = k2.handle(b"K2", &wire_bad, &state).await;
        if &proxy_bad.error_code != b"01" {
            eprintln!(
                "{}",
                replay_hint("arqc_verify_k2_differential", LABEL, case_idx)
            );
            result = Err(anyhow::anyhow!(
                "case={case_idx} K2 accepted a CORRUPTED ARQC: error_code={} (expected 01)",
                String::from_utf8_lossy(&proxy_bad.error_code),
            ));
            break;
        }

        eprintln!("case={case_idx:02} OK pan={pan} un={un_hex} txn_len={txn_len} arqc={arqc_hex}");
    }

    let teardown_result = keys.teardown().await;
    let survivor_result = assert_no_surviving(&cpc, &provisioned_arns).await;
    result?;
    teardown_result?;
    survivor_result?;
    Ok(())
}
