pub mod grounding;
pub mod noop;
#[cfg(feature = "thales")]
pub mod thales;

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::error::ProxyError;
use crate::key_map::KeyMap;

/// Shared application state cloned into every connection task.
pub struct AppState {
    pub key_map: KeyMap,
    pub data: aws_sdk_paymentcryptographydata::Client,
}

/// Result returned by every command handler.
pub struct HandlerResult {
    /// 2-byte ASCII error code. b"00" = success.
    pub error_code: [u8; 2],
    /// Response payload. Zeroized on drop to avoid key/PIN material lingering in heap.
    pub payload: Zeroizing<Vec<u8>>,
}

impl HandlerResult {
    pub fn success(payload: Vec<u8>) -> Self {
        Self {
            error_code: *b"00",
            payload: Zeroizing::new(payload),
        }
    }

    pub fn err(code: [u8; 2]) -> Self {
        Self {
            error_code: code,
            payload: Zeroizing::new(vec![]),
        }
    }

    pub fn from_proxy_error(e: &ProxyError) -> Self {
        Self::err(e.payshield_code())
    }
}

/// Every command handler implements this trait.
#[async_trait]
pub trait Handler: Send + Sync {
    /// Handle one command. `command_code` is the raw bytes from the parsed frame
    /// (2 bytes for Thales, 4 bytes for Futurex).
    async fn handle(
        &self,
        command_code: &[u8],
        payload: &[u8],
        state: &Arc<AppState>,
    ) -> HandlerResult;
    /// The command codes this handler accepts. Matched by byte equality against parsed frames.
    fn command_codes(&self) -> &'static [&'static str];

    /// Structured evidence for *why* this handler is implemented as it is and *how*
    /// it was verified (manual citation and/or live-APC differential). The single
    /// source of truth for grounding; the report in `docs/grounding-report.md` is
    /// generated from this. Defaults to empty so handlers adopt it incrementally;
    /// the audit test (`tests/grounding.rs`) flags supported handlers that have none.
    fn grounding(&self) -> &'static [grounding::Evidence] {
        &[]
    }
}

/// O(1) command dispatch table built at startup.
pub struct Registry {
    map: HashMap<Vec<u8>, Arc<dyn Handler>>,
}

impl Registry {
    /// The default registry: the built-in vendor module(s) plus the
    /// vendor-agnostic stubs. With the `thales` feature (on by default) this is
    /// Thales payShield + the not-available stub; without it, only the stub.
    ///
    /// Used by the grounding report and tests. A running proxy builds its registry
    /// from the selected vendor via [`Registry::for_module`].
    pub fn build() -> Self {
        #[cfg(feature = "thales")]
        {
            Self::for_module(&thales::ThalesModule)
        }
        #[cfg(not(feature = "thales"))]
        {
            let mut r = Self::empty();
            r.register(Arc::new(noop::NotAvailableHandler));
            r
        }
    }

    fn empty() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Assemble a registry from one vendor module's handlers plus the core's
    /// vendor-agnostic handlers (the not-available stub). This is how a running
    /// proxy registers exactly the vendor it was configured for.
    pub fn for_module(module: &dyn crate::vendor::VendorModule) -> Self {
        let mut r = Self::empty();
        for h in module.handlers() {
            r.register(h);
        }
        r.register(Arc::new(noop::NotAvailableHandler));
        r
    }

    /// Register a handler under each of its command codes, overwriting any prior
    /// entry for those codes. `h` is taken by value so `Arc<ConcreteType>` coerces
    /// to `Arc<dyn Handler>` at the call site (which does not work through a
    /// `&Arc<dyn Handler>`).
    #[allow(clippy::needless_pass_by_value)]
    pub fn register(&mut self, h: Arc<dyn Handler>) {
        for code in h.command_codes() {
            self.map.insert(code.as_bytes().to_vec(), Arc::clone(&h));
        }
    }

    pub fn get(&self, command_code: &[u8]) -> Option<Arc<dyn Handler>> {
        self.map.get(command_code).cloned()
    }

    /// Every registered command code, sorted for determinism. Used by the
    /// robustness sweep to fuzz every handler, and by tooling that enumerates
    /// the command surface.
    pub fn command_codes(&self) -> Vec<Vec<u8>> {
        let mut codes: Vec<Vec<u8>> = self.map.keys().cloned().collect();
        codes.sort();
        codes
    }

    /// One grounding entry per *distinct* handler (deduped by its first command
    /// code, which is unique per handler), sorted for deterministic output. Drives
    /// the generated grounding report and the coverage audit.
    pub fn grounding_entries(&self) -> Vec<grounding::Entry> {
        let mut seen = std::collections::HashSet::new();
        let mut entries: Vec<grounding::Entry> = Vec::new();
        for h in self.map.values() {
            let codes = h.command_codes();
            let Some(&first) = codes.first() else {
                continue;
            };
            if !seen.insert(first) {
                continue;
            }
            entries.push(grounding::Entry {
                codes: codes.to_vec(),
                evidence: h.grounding(),
            });
        }
        entries.sort_by(|a, b| a.codes.first().cmp(&b.codes.first()));
        entries
    }

    /// The generated grounding report (Markdown). Source of truth for
    /// `docs/grounding-report.md`.
    #[must_use]
    pub fn grounding_report(&self) -> String {
        grounding::format_report(&self.grounding_entries())
    }
}
