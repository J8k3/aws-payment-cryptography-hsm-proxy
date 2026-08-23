//! The forward leg: sending one framed command to the backend HSM and reading
//! its complete response.
//!
//! This is the same kind of seam as [`VendorModule`](crate::vendor::VendorModule).
//! The core ships one implementation — a fresh TCP connection per command — and
//! a deployment can supply a different one (a multi-HSM connection pool, say)
//! without forking the core.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::config::DiscoverConfig;
use crate::hsm_client::HsmClient;
use crate::protocol::Protocol;

/// Send one framed command to the backend HSM and return its complete response.
///
/// # Contract
///
/// Implementations carry a correctness obligation that the trait cannot express
/// in its signature, and that a pooled implementation must uphold explicitly:
///
/// * **Exclusivity** — a connection is owned by exactly one logical request from
///   the moment the request is written until its complete, validated response
///   has been read. No interleaving of two requests on one connection.
/// * **Zero residual** — when an exchange finishes, no unread bytes belonging to
///   it may remain buffered on the connection. Leftovers become the *next*
///   request's response, which is a cross-transaction integrity failure: one
///   cardholder's operation answered with another's data.
/// * **Poison on anomaly** — a connection may only be reused if it is provably
///   clean. On timeout, a short or malformed response, or any error that leaves
///   the stream's position uncertain, the connection must be destroyed rather
///   than returned to service.
///
/// The single-endpoint implementation below satisfies all three trivially: it
/// opens a fresh connection per command and never reuses one. The obligations
/// bind implementations that do reuse connections.
#[async_trait]
pub trait ForwardLeg: Send + Sync {
    /// Write `frame`, then read until `protocol` reports the response complete
    /// (or the peer closes). Returns the raw response bytes.
    async fn exchange(&self, frame: &[u8], protocol: &dyn Protocol) -> Result<Vec<u8>>;
}

/// The core's forward leg: one endpoint, a fresh connection per command.
///
/// Builds its [`HsmClient`] inside `exchange` rather than once up front. That
/// looks wasteful — it re-reads the TLS PEM files per call — but it is what the
/// passthrough path did before this seam existed, and hoisting it would move
/// when a bad TLS file is reported (first forward, versus startup). Left as-is
/// so introducing the seam changes no behaviour; see the note on [`HsmClient`].
pub struct SingleEndpointLeg {
    discover: Arc<DiscoverConfig>,
}

impl SingleEndpointLeg {
    pub fn new(discover: Arc<DiscoverConfig>) -> Self {
        Self { discover }
    }
}

#[async_trait]
impl ForwardLeg for SingleEndpointLeg {
    async fn exchange(&self, frame: &[u8], protocol: &dyn Protocol) -> Result<Vec<u8>> {
        HsmClient::from_discover(&self.discover)?
            .exchange(frame, protocol)
            .await
    }
}

/// A prebuilt [`HsmClient`] is itself a forward leg — one endpoint, still a
/// fresh connection per `exchange`, but with the TLS material parsed once. The
/// `--verify-only` probe uses this: it runs many exchanges against one endpoint
/// and would otherwise re-read the same PEM files for each one.
#[async_trait]
impl ForwardLeg for HsmClient {
    async fn exchange(&self, frame: &[u8], protocol: &dyn Protocol) -> Result<Vec<u8>> {
        HsmClient::exchange(self, frame, protocol).await
    }
}

/// The leg used when no `discover` block is configured.
///
/// With discovery off the proxy never forwards — unhandled commands are refused
/// before reaching the forward leg — so this is unreachable in practice. It
/// exists so the leg is always a real value rather than an `Option` threaded
/// through every connection task, and it errors rather than inventing an
/// endpoint, so a future path that *did* reach it would fail loudly.
pub struct NoForwardLeg;

#[async_trait]
impl ForwardLeg for NoForwardLeg {
    async fn exchange(&self, _frame: &[u8], _protocol: &dyn Protocol) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!(
            "no forward leg: passthrough requires a `discover` block"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ParsedCommand;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A minimal `Protocol` so these tests run in every feature configuration.
    /// Gating them on `thales` would leave the seam — which is vendor-agnostic —
    /// untested in exactly the no-vendor build it exists to serve.
    struct StubProtocol;

    impl Protocol for StubProtocol {
        fn parse(&self, _buf: &[u8]) -> Option<ParsedCommand> {
            None
        }
        fn response_code(&self, _command_code: &[u8]) -> Vec<u8> {
            b"ZZ".to_vec()
        }
        fn frame_response(
            &self,
            _header: [u8; 2],
            _response_code: &[u8],
            _error_code: &[u8],
            _payload: &[u8],
        ) -> Vec<u8> {
            Vec::new()
        }
        fn frame_error(
            &self,
            _header: [u8; 2],
            _command_code: &[u8],
            _error_code: &[u8],
        ) -> Vec<u8> {
            Vec::new()
        }
        fn is_response_complete(&self, _data: &[u8]) -> bool {
            true
        }
    }

    struct RecordingLeg {
        calls: AtomicUsize,
        reply: Vec<u8>,
    }

    #[async_trait]
    impl ForwardLeg for RecordingLeg {
        async fn exchange(&self, _frame: &[u8], _protocol: &dyn Protocol) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.reply.clone())
        }
    }

    /// The trait is object-safe and dispatches behind `Arc<dyn ForwardLeg>` —
    /// the shape `run_with` injects, and the property the seam exists for.
    #[tokio::test]
    async fn forward_leg_is_object_safe_and_dispatches() {
        let leg = Arc::new(RecordingLeg {
            calls: AtomicUsize::new(0),
            reply: b"canned".to_vec(),
        });
        let as_trait: Arc<dyn ForwardLeg> = leg.clone();

        let out = as_trait.exchange(b"frame", &StubProtocol).await.unwrap();
        assert_eq!(out, b"canned");
        assert_eq!(leg.calls.load(Ordering::SeqCst), 1);
    }

    /// With no `discover` block there is nothing to forward to, and the stand-in
    /// leg must fail loudly rather than silently succeed or invent an endpoint.
    #[tokio::test]
    async fn no_forward_leg_errors() {
        let err = NoForwardLeg
            .exchange(b"frame", &StubProtocol)
            .await
            .expect_err("NoForwardLeg must not succeed");
        assert!(
            err.to_string().contains("no forward leg"),
            "unexpected error: {err}"
        );
    }
}
