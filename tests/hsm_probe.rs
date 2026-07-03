//! Mock-HSM round-trip tests for the `--verify-only` KCV cross-check probe
//! (`src/hsm_probe.rs`), built on the shared `tests/common/mock_hsm.rs`
//! fixture. These verify the framing, the candidate-key-type iteration, and
//! the degradation paths; the KCV semantics themselves are grounded on
//! PUGD0537-004 Rev A (see the module docs) — there is no live payShield in
//! this environment.

mod common;

use std::sync::Arc;

use apc_proxy::config::DiscoverConfig;
use apc_proxy::hsm_client::HsmClient;
use apc_proxy::hsm_probe::{thales_kcv, ProbeOutcome};
use apc_proxy::protocol::thales::ThalesPayShield;
use apc_proxy::protocol::Protocol;
use common::mock_hsm::{MockBehavior, MockHsm};
use tokio::net::TcpListener;

const KEYBLOCK: &str = "SD0112P0TE00N0000A1B2C3D4E5F60718293A4B5C6D7E8F90";
const DOUBLE_LEN: &str = "U0123456789ABCDEF0123456789ABCDEF";
const PROBE_HEADER: [u8; 2] = *b"PB";

fn client_for(addr: std::net::SocketAddr) -> HsmClient {
    HsmClient::from_discover(&DiscoverConfig {
        enabled: true,
        hsm_host: addr.ip().to_string(),
        hsm_port: addr.port(),
        log_file: None,
        hsm_read_timeout_secs: Some(5),
        tls: None,
    })
    .expect("plaintext client")
}

fn bv_response(error: &[u8], kcv: &[u8]) -> Vec<u8> {
    ThalesPayShield.frame_response(PROBE_HEADER, b"BV", error, kcv)
}

/// The `BU` payload of a captured probe frame.
fn bu_payload(frame: &[u8]) -> String {
    let parsed = ThalesPayShield.parse(frame).expect("probe frame parses");
    assert_eq!(&parsed.command_code, b"BU", "probe must send BU");
    String::from_utf8_lossy(&parsed.payload).to_string()
}

/// A mock whose `BV` reply is computed from the received `BU` payload.
fn respond_by_payload(
    f: impl Fn(&str) -> (&'static [u8], &'static [u8]) + Send + Sync + 'static,
) -> MockBehavior {
    MockBehavior::RespondWith(Arc::new(move |frame| {
        let (err, kcv) = f(&bu_payload(frame));
        bv_response(err, kcv)
    }))
}

#[tokio::test]
async fn keyblock_form_probes_in_one_round_trip() {
    let mock = MockHsm::spawn(MockBehavior::Respond(bv_response(b"00", b"D5D44F")), 1).await;
    let outcome = thales_kcv(&client_for(mock.addr), KEYBLOCK).await;
    assert_eq!(outcome, ProbeOutcome::Kcv("D5D44F".into()));

    // Key Block LMK form: reserved type/length fields, block, reserved
    // 3-digit type, 6-digit KCV request — in one round trip.
    let frames = mock.frames().await;
    assert_eq!(frames.len(), 1);
    let payload = bu_payload(&frames[0]);
    assert!(payload.starts_with("FFFS"), "got {payload}");
    assert!(payload.ends_with(";FFF;001"), "got {payload}");
}

#[tokio::test]
async fn variant_form_iterates_documented_type_codes() {
    // First candidate ('01' ZPK) fails key parity — the mock only accepts the
    // key as '02' (TMK/TPK/PVK). The probe must move on and succeed.
    let mock = MockHsm::spawn(
        respond_by_payload(|payload| match &payload[..2] {
            "02" => (b"00", b"A68CDC"),
            _ => (b"10", b""),
        }),
        4,
    )
    .await;
    let outcome = thales_kcv(&client_for(mock.addr), DOUBLE_LEN).await;
    assert_eq!(outcome, ProbeOutcome::Kcv("A68CDC".into()));
    assert_eq!(mock.frames().await.len(), 2, "stops at first success");
}

#[tokio::test]
async fn all_type_codes_rejected_is_key_type_unknown() {
    let mock = MockHsm::spawn(MockBehavior::Respond(bv_response(b"10", b"")), 4).await;
    let outcome = thales_kcv(&client_for(mock.addr), DOUBLE_LEN).await;
    assert_eq!(outcome, ProbeOutcome::KeyTypeUnknown);
    assert_eq!(mock.frames().await.len(), 4, "tries all four type codes");
}

#[tokio::test]
async fn command_disabled_stops_immediately() {
    // '68' means BU itself is switched off — retrying other type codes cannot
    // help, and verify.rs uses this to disable further probing for the run.
    let mock = MockHsm::spawn(MockBehavior::Respond(bv_response(b"68", b"")), 4).await;
    let outcome = thales_kcv(&client_for(mock.addr), DOUBLE_LEN).await;
    assert_eq!(outcome, ProbeOutcome::CommandDisabled);
    assert_eq!(mock.frames().await.len(), 1, "no retry after 68");
}

#[tokio::test]
async fn sixteen_digit_kcv_is_accepted() {
    // Variant LMK without the 6-digit restriction returns 16 digits; the
    // comparable part is the leftmost 6 (kcv_matches handles the prefix).
    let mock = MockHsm::spawn(
        MockBehavior::Respond(bv_response(b"00", b"D5D44F0000000000")),
        1,
    )
    .await;
    let outcome = thales_kcv(&client_for(mock.addr), KEYBLOCK).await;
    assert_eq!(outcome, ProbeOutcome::Kcv("D5D44F0000000000".into()));
}

#[tokio::test]
async fn unreachable_hsm_reports_unreachable() {
    // Bind then drop a listener so the port is closed but was recently valid.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);

    let outcome = thales_kcv(&client_for(addr), KEYBLOCK).await;
    assert!(
        matches!(outcome, ProbeOutcome::Unreachable(_)),
        "got {outcome:?}"
    );
}

#[tokio::test]
async fn garbage_response_is_hsm_error() {
    let mock = MockHsm::spawn(MockBehavior::Respond(b"\x00\x06NOPEXX".to_vec()), 1).await;
    let outcome = thales_kcv(&client_for(mock.addr), KEYBLOCK).await;
    assert!(
        matches!(outcome, ProbeOutcome::HsmError(_)),
        "got {outcome:?}"
    );
}
