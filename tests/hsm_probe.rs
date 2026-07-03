//! Mock-HSM round-trip tests for the `--verify-only` KCV cross-check probe
//! (`src/hsm_probe.rs`). A tokio listener plays the payShield: it parses the
//! probe's `BU` frame and answers with a scripted `BV`. These verify the
//! framing, the candidate-key-type iteration, and the degradation paths; the
//! KCV semantics themselves are grounded on PUGD0537-004 Rev A (see the
//! module docs) — there is no live payShield in this environment.

use std::net::SocketAddr;
use std::sync::Arc;

use apc_proxy::config::DiscoverConfig;
use apc_proxy::hsm_probe::{thales_kcv, ProbeOutcome};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const KEYBLOCK: &str = "SD0112P0TE00N0000A1B2C3D4E5F60718293A4B5C6D7E8F90";
const DOUBLE_LEN: &str = "U0123456789ABCDEF0123456789ABCDEF";

/// Start a mock HSM. `respond` maps the received `BU` payload (ASCII) to
/// `(error_code, kcv_field)`; the mock frames it as a `BV` echoing the header.
/// Accepts any number of connections — the probe opens one per candidate.
async fn mock_hsm<F>(respond: F) -> SocketAddr
where
    F: Fn(&str) -> (&'static str, &'static str) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let respond = Arc::new(respond);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let respond = Arc::clone(&respond);
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                if sock.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
                if sock.read_exact(&mut body).await.is_err() {
                    return;
                }
                assert!(body.len() >= 4, "frame too short");
                let header = [body[0], body[1]];
                assert_eq!(&body[2..4], b"BU", "probe must send BU");
                let payload = String::from_utf8_lossy(&body[4..]).to_string();
                let (err, kcv) = respond(&payload);

                let resp_body_len = 2 + 2 + 2 + kcv.len();
                let mut resp = Vec::new();
                resp.extend_from_slice(&(resp_body_len as u16).to_be_bytes());
                resp.extend_from_slice(&header);
                resp.extend_from_slice(b"BV");
                resp.extend_from_slice(err.as_bytes());
                resp.extend_from_slice(kcv.as_bytes());
                let _ = sock.write_all(&resp).await;
            });
        }
    });
    addr
}

fn discover(addr: SocketAddr) -> DiscoverConfig {
    DiscoverConfig {
        enabled: true,
        hsm_host: addr.ip().to_string(),
        hsm_port: addr.port(),
        log_file: None,
        hsm_read_timeout_secs: Some(5),
        tls: None,
    }
}

#[tokio::test]
async fn keyblock_form_probes_in_one_round_trip() {
    let addr = mock_hsm(|payload| {
        // Key Block LMK form: reserved type/length fields, block, reserved
        // 3-digit type, 6-digit KCV request.
        assert!(payload.starts_with("FFFS"), "got {payload}");
        assert!(payload.ends_with(";FFF;001"), "got {payload}");
        ("00", "D5D44F")
    })
    .await;
    let outcome = thales_kcv(&discover(addr), KEYBLOCK).await;
    assert_eq!(outcome, ProbeOutcome::Kcv("D5D44F".into()));
}

#[tokio::test]
async fn variant_form_iterates_documented_type_codes() {
    // First candidate ('01' ZPK) fails key parity — the mock only accepts the
    // key as '02' (TMK/TPK/PVK). The probe must move on and succeed.
    let addr = mock_hsm(|payload| match &payload[..2] {
        "02" => ("00", "A68CDC"),
        _ => ("10", ""),
    })
    .await;
    let outcome = thales_kcv(&discover(addr), DOUBLE_LEN).await;
    assert_eq!(outcome, ProbeOutcome::Kcv("A68CDC".into()));
}

#[tokio::test]
async fn all_type_codes_rejected_is_key_type_unknown() {
    let addr = mock_hsm(|_| ("10", "")).await;
    let outcome = thales_kcv(&discover(addr), DOUBLE_LEN).await;
    assert_eq!(outcome, ProbeOutcome::KeyTypeUnknown);
}

#[tokio::test]
async fn command_disabled_stops_immediately() {
    // '68' means BU itself is switched off — retrying other type codes cannot
    // help, and verify.rs uses this to disable further probing for the run.
    let addr = mock_hsm(|_| ("68", "")).await;
    let outcome = thales_kcv(&discover(addr), DOUBLE_LEN).await;
    assert_eq!(outcome, ProbeOutcome::CommandDisabled);
}

#[tokio::test]
async fn sixteen_digit_kcv_is_accepted() {
    // Variant LMK without the 6-digit restriction returns 16 digits; the
    // comparable part is the leftmost 6 (kcv_matches handles the prefix).
    let addr = mock_hsm(|_| ("00", "D5D44F0000000000")).await;
    let outcome = thales_kcv(&discover(addr), KEYBLOCK).await;
    assert_eq!(outcome, ProbeOutcome::Kcv("D5D44F0000000000".into()));
}

#[tokio::test]
async fn unreachable_hsm_reports_unreachable() {
    // Bind then drop a listener so the port is closed but was recently valid.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);

    let outcome = thales_kcv(&discover(addr), KEYBLOCK).await;
    assert!(
        matches!(outcome, ProbeOutcome::Unreachable(_)),
        "got {outcome:?}"
    );
}

#[tokio::test]
async fn garbage_response_is_hsm_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let _ = sock.write_all(b"\x00\x06NOPEXX").await;
        }
    });
    let outcome = thales_kcv(&discover(addr), KEYBLOCK).await;
    assert!(
        matches!(outcome, ProbeOutcome::HsmError(_)),
        "got {outcome:?}"
    );
}
