//! Pluggable vendor modules.
//!
//! A [`VendorModule`] bundles everything the proxy needs to serve one HSM wire
//! vendor: the `vendor:` config string it answers to, its framing
//! [`Protocol`](crate::protocol::Protocol), and the command
//! [`Handler`](crate::handlers::Handler)s it provides.
//!
//! Every vendor plugs in the same way — the built-in Thales payShield support
//! ([`crate::handlers::thales::ThalesModule`]) and any separately-licensed
//! bolt-on (Futurex, Atalla) alike. A deployment assembles exactly the modules
//! it needs via [`server::run_with`](crate::server::run_with), and — because
//! Thales is behind the default `thales` cargo feature — a build that doesn't
//! need payShield can compile it out entirely, leaving no unused vendor code in
//! the binary.

use std::sync::Arc;

use crate::handlers::Handler;
use crate::protocol::Protocol;

/// One pluggable HSM wire vendor: its config string, framing protocol, and
/// command handlers.
pub trait VendorModule: Send + Sync {
    /// The `vendor:` value in `proxy.yaml` this module serves
    /// (e.g. `"thales_payshield"`).
    fn vendor(&self) -> &'static str;

    /// The wire framing protocol for this vendor.
    fn protocol(&self) -> Arc<dyn Protocol>;

    /// The command handlers to register when this vendor is selected.
    fn handlers(&self) -> Vec<Arc<dyn Handler>>;
}
