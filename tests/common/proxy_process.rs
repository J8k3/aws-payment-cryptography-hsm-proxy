//! Spawn the production `apc-proxy` binary as a subprocess for tests.
//!
//! Writes a temp `proxy.yaml` with the test-specified vendor, listen port,
//! and discover block, starts the binary, and waits until the listener is
//! accepting connections.
//!
//! Test isolation: each `ProxyProcess` picks its own listen port from a
//! shared monotonic counter starting at 19500 so concurrent tests in the
//! same `cargo test` invocation don't collide.

use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Ask the OS for a free loopback port, then release it.
///
/// This replaces a fixed-base `AtomicU16` counter. That counter was a *per-test-
/// binary* static seeded at the same value in every binary, and cargo runs the
/// integration crates (`forward_tls`, `passthrough`, `tls`, `inbound_limits`)
/// as concurrent processes — so two binaries handed out identical ports. The
/// loser's bind failed, and because the readiness poll only checks that
/// *something* accepts on the port, it would connect to the other binary's
/// proxy and the test would then assert against the wrong process.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("read ephemeral addr")
        .port()
}

// `tests/common/` is compiled separately for each test binary; a field used
// by passthrough.rs looks dead from tls.rs's perspective. Allow at the type
// level rather than chasing per-field/per-method annotations.
#[allow(dead_code)]
pub struct ProxyProcess {
    pub addr: SocketAddr,
    pub discovery_log_path: PathBuf,
    child: Child,
    _tempdir: super::tempdir::TempDir,
}

pub struct ProxyConfigInput<'a> {
    pub vendor: &'a str,
    pub hsm_host: &'a str,
    pub hsm_port: u16,
    /// Override the proxy's forward read timeout in seconds. `None` = default
    /// (30s). Tests that exercise the read-timeout path should set this low
    /// so the test doesn't take 30 seconds.
    pub hsm_read_timeout_secs: Option<u64>,
    /// Inbound idle read timeout in seconds (`listen.read_timeout_secs`).
    /// `None` = disabled (proxy default). Set low to exercise the idle-eviction
    /// path without the test hanging.
    pub listen_read_timeout_secs: Option<u64>,
    /// Inbound TLS configuration. `None` = plaintext listener.
    pub tls: Option<TlsInput>,
    /// Outbound TLS configuration on the forward leg (proxy → real HSM).
    /// `None` = plaintext forward connection.
    pub forward_tls: Option<ForwardTlsInput>,
}

pub struct TlsInput {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Optional CA path: setting this turns the listener into mTLS (the
    /// client must present a cert signed by this CA).
    pub ca_path: Option<PathBuf>,
}

pub struct ForwardTlsInput {
    pub ca_file: PathBuf,
    pub client_cert_file: Option<PathBuf>,
    pub client_key_file: Option<PathBuf>,
    pub server_name: Option<String>,
}

#[allow(dead_code)]
impl ProxyProcess {
    /// Start the proxy with `discover.enabled=true` pointing at the given HSM
    /// host:port (the test's mock HSM). Blocks until the proxy is accepting
    /// connections (poll on TCP connect) or panics on timeout.
    pub fn spawn(input: &ProxyConfigInput<'_>) -> Self {
        let port = free_port();
        let tempdir = super::tempdir::TempDir::with_prefix("apc-proxy-test");
        let config_path = tempdir.path.join("proxy.yaml");
        let discovery_log_path = tempdir.path.join("discovery.jsonl");

        let vendor = input.vendor;
        let hsm_host = input.hsm_host;
        let hsm_port = input.hsm_port;
        let log_path = discovery_log_path.display();
        let read_timeout_line = match input.hsm_read_timeout_secs {
            Some(secs) => format!("  hsm_read_timeout_secs: {secs}\n"),
            None => String::new(),
        };
        let listen_read_timeout_line = match input.listen_read_timeout_secs {
            Some(secs) => format!("  read_timeout_secs: {secs}\n"),
            None => String::new(),
        };
        let tls_block = match &input.tls {
            Some(tls) => {
                let cert = tls.cert_path.display();
                let key = tls.key_path.display();
                let ca_line = match &tls.ca_path {
                    Some(p) => format!("    ca_file: {}\n", p.display()),
                    None => String::new(),
                };
                format!("  tls:\n    cert_file: {cert}\n    key_file: {key}\n{ca_line}")
            }
            None => String::new(),
        };
        let forward_tls_block = match &input.forward_tls {
            Some(t) => {
                use std::fmt::Write as _;
                let mut s = format!("  tls:\n    ca_file: {}\n", t.ca_file.display());
                if let Some(p) = &t.client_cert_file {
                    let _ = writeln!(s, "    client_cert_file: {}", p.display());
                }
                if let Some(p) = &t.client_key_file {
                    let _ = writeln!(s, "    client_key_file: {}", p.display());
                }
                if let Some(n) = &t.server_name {
                    let _ = writeln!(s, "    server_name: {n}");
                }
                s
            }
            None => String::new(),
        };
        let yaml = format!(
            "vendor: {vendor}\n\
             listen:\n  host: 127.0.0.1\n  port: {port}\n{listen_read_timeout_line}{tls_block}\
             aws:\n  region: us-east-1\n\
             key_mappings: {{}}\n\
             discover:\n  enabled: true\n  hsm_host: {hsm_host}\n  hsm_port: {hsm_port}\n  log_file: {log_path}\n{read_timeout_line}{forward_tls_block}"
        );

        std::fs::write(&config_path, yaml).expect("write temp proxy.yaml");

        let binary = locate_binary();
        let mut child = Command::new(&binary)
            .arg("--config")
            .arg(&config_path)
            .env("RUST_LOG", "apc_proxy=warn") // quieter than info for test output
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", binary.display()));

        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("parse addr");

        // Wait for the listener — poll TCP connect. Check liveness first: if the
        // child died (e.g. it could not bind), a successful connect would mean we
        // reached somebody else's listener, so fail loudly instead of testing it.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait().expect("poll proxy child") {
                panic!("proxy exited before it began listening on {addr} (status {status})");
            }
            assert!(
                Instant::now() <= deadline,
                "proxy {addr} did not start listening within 15s"
            );
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        Self {
            addr,
            discovery_log_path,
            child,
            _tempdir: tempdir,
        }
    }

    /// `spawn` for use inside an async test.
    ///
    /// Not `async` itself — `block_in_place` is synchronous — but it must be
    /// called from within a multi-thread runtime.
    ///
    /// `spawn` blocks — it polls the listener with `TcpStream::connect_timeout`
    /// and `thread::sleep`. Calling it straight from a `#[tokio::test]` body
    /// blocks a runtime worker, which can starve an in-test `MockHsm` accept
    /// task long enough for the proxy's forward-leg TLS handshake to give up.
    /// The proxy then answers with a framed error 41 and the assertion fails —
    /// but only under load, which made it look like a flaky test rather than a
    /// fixture bug.
    ///
    /// `block_in_place` hands the worker off so the mock keeps being polled. It
    /// requires the multi-thread runtime, which every caller already uses.
    pub fn spawn_in_async_test(input: &ProxyConfigInput<'_>) -> Self {
        tokio::task::block_in_place(|| Self::spawn(input))
    }

    pub fn read_discovery_log(&self) -> String {
        std::fs::read_to_string(&self.discovery_log_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", self.discovery_log_path.display()))
    }
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        // Drain so the OS releases the port before the next test grabs it.
        let _ = self.child.wait();
    }
}

/// Find the proxy binary. CARGO_BIN_EXE_apc-proxy is set by cargo for
/// integration tests; fall back to a debug-target search if not.
fn locate_binary() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_apc-proxy") {
        return PathBuf::from(path);
    }
    let exe = if cfg!(windows) {
        "apc-proxy.exe"
    } else {
        "apc-proxy"
    };
    PathBuf::from("target/debug").join(exe)
}
