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
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

static NEXT_PORT: AtomicU16 = AtomicU16::new(19500);

pub struct ProxyProcess {
    pub addr: SocketAddr,
    pub discovery_log_path: PathBuf,
    child: Child,
    _tempdir: tempdir_holder::TempDirHolder,
}

pub struct ProxyConfigInput<'a> {
    pub vendor: &'a str,
    pub hsm_host: &'a str,
    pub hsm_port: u16,
    /// Override the proxy's forward read timeout in seconds. `None` = default
    /// (30s). Tests that exercise the read-timeout path should set this low
    /// so the test doesn't take 30 seconds.
    pub hsm_read_timeout_secs: Option<u64>,
}

impl ProxyProcess {
    /// Start the proxy with `discover.enabled=true` pointing at the given HSM
    /// host:port (the test's mock HSM). Blocks until the proxy is accepting
    /// connections (poll on TCP connect) or panics on timeout.
    pub fn spawn(input: &ProxyConfigInput<'_>) -> Self {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let tempdir = tempdir_holder::TempDirHolder::new();
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
        let yaml = format!(
            "vendor: {vendor}\n\
             listen:\n  host: 127.0.0.1\n  port: {port}\n\
             aws:\n  region: us-east-1\n\
             key_mappings: {{}}\n\
             discover:\n  enabled: true\n  hsm_host: {hsm_host}\n  hsm_port: {hsm_port}\n  log_file: {log_path}\n{read_timeout_line}"
        );

        std::fs::write(&config_path, yaml).expect("write temp proxy.yaml");

        let binary = locate_binary();
        let child = Command::new(&binary)
            .arg("--config")
            .arg(&config_path)
            .env("RUST_LOG", "apc_proxy=warn") // quieter than info for test output
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", binary.display()));

        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("parse addr");

        // Wait for the listener — poll TCP connect.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
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

mod tempdir_holder {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// Minimal owned temp dir without pulling in the `tempfile` crate as a
    /// dev-dep. Cleans up on drop. Path uniqueness comes from PID + a
    /// monotonic counter; collisions across runs are not a concern since the
    /// dir is removed in Drop.
    pub struct TempDirHolder {
        pub path: PathBuf,
    }

    impl TempDirHolder {
        pub fn new() -> Self {
            let seq = SEQ.fetch_add(1, Ordering::SeqCst);
            let pid = std::process::id();
            let path = std::env::temp_dir().join(format!("apc-proxy-test-{pid}-{seq}"));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDirHolder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
