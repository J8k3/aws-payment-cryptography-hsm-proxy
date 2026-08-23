//! Owned temp directory for tests, without pulling in the `tempfile` crate as a
//! dev-dependency. Cleans up on drop.
//!
//! Uniqueness is PID + a monotonic counter. That combination matters: the PID
//! separates concurrently running test binaries, and the counter separates tests
//! running as threads *within* one binary.
//!
//! An earlier copy of this in `tls.rs` and `forward_tls.rs` used a wall-clock
//! timestamp instead of the counter, which is not unique — the clock is only
//! microsecond-resolution in practice, so concurrent tests in the same binary
//! routinely observed the same value, and `create_dir_all` silently succeeds on
//! a directory that already exists. Two tests then shared a directory and
//! overwrote each other's generated CA and leaf certificates, so a client would
//! verify a certificate signed by the other test's CA and the handshake failed
//! with `InvalidCertificate(BadSignature)`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    #[allow(dead_code)] // each test binary compiles common/ separately
    pub fn new() -> Self {
        Self::with_prefix("apc-proxy-test")
    }

    /// `prefix` only aids human inspection of leftovers; uniqueness comes from
    /// the PID and counter, never the prefix.
    #[allow(dead_code)]
    pub fn with_prefix(prefix: &str) -> Self {
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("{prefix}-{pid}-{seq}"));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
