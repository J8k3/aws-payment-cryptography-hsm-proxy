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
//!   `APC_LIVE_SEED` (u64, default `0xA5C3F00C0FFEE_u64`) — reproducible RNG seed
//!   `APC_LIVE_CASES` (usize, default `8`) — cases per command
//!
//! Each test creates fresh APC keys via `TestKeys::create`, exercises a
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
    CardGenerationAttributes, CardVerificationValue1, MacAlgorithm, MacAttributes,
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

fn case_count() -> usize {
    std::env::var("APC_LIVE_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
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

/// Random MMYY-style expiry (4 digits). Year 25..30, month 01..12, encoded as YYMM.
fn gen_expiry(rng: &mut StdRng) -> String {
    let yy = rng.random_range(25..=30_u8);
    let mm = rng.random_range(1..=12_u8);
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

    let mut rng = StdRng::seed_from_u64(rng_seed());
    let cases = case_count();
    eprintln!(
        "cvv_cw_cy_differential: seed=0x{:016X} cases={cases}",
        rng_seed()
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in 0..cases {
        let pan_len = rng.random_range(13..=19_usize);
        let pan = gen_pan(&mut rng, pan_len);
        let expiry = gen_expiry(&mut rng);
        let service_code = gen_service_code(&mut rng);

        // 1) CW: proxy
        let cw_wire = encode_cw(&cvk_label, &pan, &expiry, service_code);
        let proxy_cw = cw_handler.handle(b"CW", &cw_wire, &state).await;
        if &proxy_cw.error_code != b"00" {
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

    let mut rng = StdRng::seed_from_u64(rng_seed());
    let cases = case_count();
    eprintln!(
        "mac_m6_m8_differential: seed=0x{:016X} cases={cases}",
        rng_seed()
    );

    let mut result: anyhow::Result<()> = Ok(());

    for case_idx in 0..cases {
        // Randomise message length (whole bytes) to surface fixed-offset bugs.
        let msg_bytes = rng.random_range(1..=32_usize);
        let msg_hex = gen_hex_message(&mut rng, msg_bytes);

        // 1) M6 generate via proxy. algo '3' = ISO9797 ALG3; MAC size '1' = the
        //    full 8-byte (16H) MAC so the M8 verify path sees a complete MAC.
        let m6_wire = encode_m6(&mak_label, b'3', b'1', &msg_hex);
        let proxy_m6 = m6_handler.handle(b"M6", &m6_wire, &state).await;
        if &proxy_m6.error_code != b"00" {
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
            result = Err(anyhow::anyhow!(
                "case={case_idx} M6 differential mismatch: proxy={proxy_mac} oracle={oracle_mac} \
                 msg_bytes={msg_bytes} msg={msg_hex}"
            ));
            break;
        }

        // 3) M8 round-trip: the proxy's own M8 verifier must accept the MAC M6 made.
        let m8_wire = encode_m8(&mak_label, b'3', b'1', &msg_hex, &proxy_mac);
        let proxy_m8 = m8_handler.handle(b"M8", &m8_wire, &state).await;
        if &proxy_m8.error_code != b"00" {
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
