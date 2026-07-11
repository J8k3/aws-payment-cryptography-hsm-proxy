//! `--verify-only` mode: confirm the proxy's config is internally consistent
//! and that every `key_mappings` entry resolves to a usable APC key, without
//! starting the listener. Exit 0 = everything is ready to serve; non-zero =
//! at least one problem the operator needs to fix before going live.
//!
//! What we check today:
//!   - AWS credentials resolve at all
//!   - For each `key_mappings` entry: APC `get_key(arn)` succeeds, the key is
//!     in `CREATE_COMPLETE` state, and `Enabled=true`
//!   - When `discover.hsm_host` is configured (Thales): the source HSM's KCV
//!     for each LMK-encrypted mapping key matches APC's KCV (`BU` probe — see
//!     `hsm_probe`). HSM unreachable degrades to a single warning; the APC-side
//!     checks still run.
//!   - Inbound TLS config files exist (parse happens at server start)
//!   - Outbound TLS config files exist (same approach)
//!   - The startup APC `list_keys` scan succeeds and reports its index size
//!
//! What we don't check yet:
//!   - Futurex HSM-side KCV (`GPKR` field layout unverified — see `hsm_probe`
//!     module docs and #13)
//!   - Cert validity windows (expiry)

use anyhow::Result;
use std::collections::BTreeMap;

use crate::config::ProxyConfig;
#[cfg(feature = "thales")]
use crate::hsm_client::HsmClient;
#[cfg(feature = "thales")]
use crate::hsm_probe::{self, ProbeOutcome};
use crate::key_map::KeyMap;

#[derive(Debug, Default)]
struct Report {
    ok: Vec<String>,
    warnings: Vec<String>,
    errors: Vec<String>,
}

impl Report {
    fn pass(&mut self, line: String) {
        self.ok.push(line);
    }
    fn warn(&mut self, line: String) {
        self.warnings.push(line);
    }
    fn fail(&mut self, line: String) {
        self.errors.push(line);
    }
    fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Run the verification pass. Returns Ok(true) if everything is ready to
/// serve, Ok(false) if any check failed (caller exits non-zero).
pub async fn run(cfg: &ProxyConfig) -> Result<bool> {
    println!("apc-proxy verify-only against {}", cfg.aws.region);
    println!("─────────────────────────────────────────────────────────────");

    let mut report = Report::default();

    // 1. AWS credentials
    let aws_cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(cfg.aws.region.clone()))
        .load()
        .await;
    let Some(provider) = aws_cfg.credentials_provider() else {
        report.fail("no AWS credentials provider in config".to_string());
        print_report(&report);
        return Ok(false);
    };
    use aws_credential_types::provider::ProvideCredentials;
    match provider.provide_credentials().await {
        Ok(_) => report.pass("AWS credentials resolved".to_string()),
        Err(e) => {
            report.fail(format!("AWS credentials: {e}"));
            print_report(&report);
            return Ok(false);
        }
    }

    let control = aws_sdk_paymentcryptography::Client::new(&aws_cfg);

    // 2. APC inventory scan (used by wrapped-key resolution at runtime)
    let mut scan_map = KeyMap::new(std::collections::HashMap::new());
    if let Err(e) = scan_map.scan_apc(&control).await {
        report.warn(format!(
            "APC list_keys scan failed: {e} — wrapped-key resolution will not work at runtime"
        ));
    } else {
        report.pass("APC list_keys scan succeeded".to_string());
    }

    // 3. key_mappings: every entry must resolve to a CREATE_COMPLETE, enabled key.
    // When discover.hsm_host is configured, additionally cross-check the KCV the
    // source HSM computes for the mapping key against the KCV APC reports — a
    // matching APC inventory can still point at different clear key material,
    // and without this check the first live transaction is what finds out.
    // `hsm` goes to None after the first fatal probe outcome, so a dead HSM
    // produces one warning instead of one per mapping.
    #[cfg(feature = "thales")]
    let mut hsm = hsm_probe_target(cfg, &mut report);
    let mut per_arn_checked: BTreeMap<String, KeyCheck> = BTreeMap::new();
    for (label, arn_or_alias) in &cfg.key_mappings {
        if !per_arn_checked.contains_key(arn_or_alias) {
            let result = check_one_key(&control, arn_or_alias).await;
            per_arn_checked.insert(arn_or_alias.clone(), result);
        }
        match per_arn_checked
            .get(arn_or_alias)
            .expect("inserted above")
            .clone()
        {
            KeyCheck::Ok { kcv, usage, algo } => {
                let line = |suffix: &str| {
                    format!(
                        "{label:<36} → {} ({usage}/{algo}, KCV={kcv}{suffix})",
                        short(arn_or_alias)
                    )
                };
                // HSM-side KCV cross-check (Thales `BU` probe) — only with the
                // `thales` vendor. Without it, verify validates the APC side only.
                #[cfg(feature = "thales")]
                {
                    let outcome = match &hsm {
                        Some(client) => Some(hsm_probe::thales_kcv(client, label).await),
                        None => None,
                    };
                    match outcome {
                        None => report.pass(line("")),
                        Some(ProbeOutcome::Kcv(h)) if hsm_probe::kcv_matches(&kcv, &h) => {
                            report.pass(line(&format!(", HSM={h} ✓")));
                        }
                        Some(ProbeOutcome::Kcv(h)) => {
                            report.fail(format!(
                                "{label:<36} → {} APC KCV={kcv}, HSM KCV={h} — KEY MISMATCH",
                                short(arn_or_alias)
                            ));
                        }
                        Some(ProbeOutcome::UnsupportedForm) => {
                            report.warn(line(
                                ", HSM: not probeable — mapping key is not an LMK-encrypted wire form",
                            ));
                        }
                        Some(ProbeOutcome::KeyTypeUnknown) => {
                            report.warn(line(
                                ", HSM: BU rejected all blind-probeable key types (ZPK/TMK-TPK-PVK/TAK/ZMK)",
                            ));
                        }
                        Some(ProbeOutcome::HsmError(e)) => {
                            report.warn(line(&format!(", HSM probe error: {e}")));
                        }
                        Some(ProbeOutcome::CommandDisabled) => {
                            hsm = None;
                            report.warn(
                                "HSM refused BU (error 68 — command disabled by security settings) \
                                 — skipping HSM-side KCV checks"
                                    .to_string(),
                            );
                            report.pass(line(""));
                        }
                        Some(ProbeOutcome::Unreachable(e)) => {
                            hsm = None;
                            report.warn(format!(
                                "HSM unreachable — skipping HSM-side KCV checks: {e}"
                            ));
                            report.pass(line(""));
                        }
                    }
                }
                #[cfg(not(feature = "thales"))]
                report.pass(line(""));
            }
            KeyCheck::NotFound => {
                report.fail(format!(
                    "{label:<36} → {} NOT FOUND in APC",
                    short(arn_or_alias)
                ));
            }
            KeyCheck::Disabled => {
                report.fail(format!("{label:<36} → {} DISABLED", short(arn_or_alias)));
            }
            KeyCheck::WrongState(state) => {
                report.fail(format!(
                    "{label:<36} → {} state={state} (must be CREATE_COMPLETE)",
                    short(arn_or_alias)
                ));
            }
            KeyCheck::ApiError(e) => {
                report.fail(format!(
                    "{label:<36} → {} APC error: {e}",
                    short(arn_or_alias)
                ));
            }
        }
    }

    // 4. TLS file existence — actual parse happens at server start
    if let Some(tls) = &cfg.listen.tls {
        check_file_exists("listen.tls.cert_file", &tls.cert_file, &mut report);
        check_file_exists("listen.tls.key_file", &tls.key_file, &mut report);
        if let Some(ca) = &tls.ca_file {
            check_file_exists("listen.tls.ca_file (mTLS)", ca, &mut report);
        }
    } else {
        report
            .warn("inbound TLS not configured — plaintext listener (development only)".to_string());
    }

    if let Some(d) = &cfg.discover {
        if let Some(tls) = &d.tls {
            check_file_exists("discover.tls.ca_file", &tls.ca_file, &mut report);
            if let Some(p) = &tls.client_cert_file {
                check_file_exists("discover.tls.client_cert_file (mTLS)", p, &mut report);
            }
            if let Some(p) = &tls.client_key_file {
                check_file_exists("discover.tls.client_key_file (mTLS)", p, &mut report);
            }
            match (&tls.client_cert_file, &tls.client_key_file) {
                (Some(_), None) | (None, Some(_)) => {
                    report.fail(
                        "discover.tls: client_cert_file and client_key_file must be provided together"
                            .to_string(),
                    );
                }
                _ => {}
            }
        } else if d.enabled {
            report.warn(
                "discover.enabled=true but no discover.tls — forward leg is plaintext".to_string(),
            );
        }
    }

    print_report(&report);
    Ok(report.is_clean())
}

#[derive(Debug, Clone)]
enum KeyCheck {
    Ok {
        kcv: String,
        usage: String,
        algo: String,
    },
    NotFound,
    Disabled,
    WrongState(String),
    ApiError(String),
}

async fn check_one_key(client: &aws_sdk_paymentcryptography::Client, identifier: &str) -> KeyCheck {
    use aws_sdk_paymentcryptography::types::KeyState;
    match client.get_key().key_identifier(identifier).send().await {
        Ok(resp) => {
            let Some(key) = resp.key else {
                return KeyCheck::ApiError("get_key returned no Key field".into());
            };
            match key.key_state {
                KeyState::CreateComplete => {}
                other => return KeyCheck::WrongState(other.as_str().to_string()),
            }
            if !key.enabled {
                return KeyCheck::Disabled;
            }
            let kcv = key.key_check_value;
            let Some(attrs) = key.key_attributes else {
                return KeyCheck::ApiError("get_key returned no KeyAttributes".into());
            };
            let usage = attrs.key_usage().as_str().to_string();
            let algo = attrs.key_algorithm().as_str().to_string();
            KeyCheck::Ok { kcv, usage, algo }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("ResourceNotFoundException") {
                KeyCheck::NotFound
            } else {
                KeyCheck::ApiError(msg)
            }
        }
    }
}

/// Decide whether the HSM-side KCV cross-check runs, emit the corresponding
/// report line, and build the client (loading TLS material once for the whole
/// run). `None` means "no probing": no `discover` block, the Futurex gate, an
/// unrecognized vendor, or unusable TLS config. Also validates `vendor` itself
/// — server::run refuses to start on an unknown vendor, and verify must not
/// report a config as ready when the proxy would not boot it.
#[cfg(feature = "thales")]
fn hsm_probe_target(cfg: &ProxyConfig, report: &mut Report) -> Option<HsmClient> {
    let discover = cfg.discover.as_ref()?;
    // The HSM-side KCV cross-check is implemented only for the Thales probe. For
    // any other vendor (e.g. a bolt-on), skip probing — `key_mappings` are still
    // validated, and `server::run` is the authority on whether the configured
    // vendor is actually bootable.
    if cfg.vendor != "thales_payshield" {
        report.warn(format!(
            "HSM-side KCV cross-check skipped for vendor {:?} — only \"thales_payshield\" \
             is probed; key_mappings validation still applies",
            cfg.vendor
        ));
        return None;
    }
    match HsmClient::from_discover(discover) {
        Ok(client) => {
            report.pass(format!(
                "HSM-side KCV cross-check enabled against {}:{} (BU probe)",
                discover.hsm_host, discover.hsm_port
            ));
            Some(client)
        }
        Err(e) => {
            report.fail(format!(
                "discover.tls unusable — HSM-side KCV checks skipped: {e}"
            ));
            None
        }
    }
}

fn check_file_exists(label: &str, path: &std::path::Path, report: &mut Report) {
    if path.exists() {
        report.pass(format!("{label}: {}", path.display()));
    } else {
        report.fail(format!("{label} does not exist: {}", path.display()));
    }
}

fn short(arn_or_alias: &str) -> String {
    if let Some(rest) = arn_or_alias.strip_prefix("arn:aws:payment-cryptography:") {
        if let Some(idx) = rest.rfind(':') {
            return rest[idx + 1..].to_string();
        }
    }
    arn_or_alias.to_string()
}

fn print_report(report: &Report) {
    for line in &report.ok {
        println!("  ok    {line}");
    }
    for line in &report.warnings {
        println!("  warn  {line}");
    }
    for line in &report.errors {
        println!("  FAIL  {line}");
    }
    println!("─────────────────────────────────────────────────────────────");
    println!(
        "{} ok, {} warning(s), {} error(s)",
        report.ok.len(),
        report.warnings.len(),
        report.errors.len()
    );
    if report.is_clean() {
        println!("Verification PASSED — config is ready to serve.");
    } else {
        println!("Verification FAILED — fix errors before starting the proxy.");
    }
}
