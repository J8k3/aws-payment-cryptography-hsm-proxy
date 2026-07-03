//! Library surface for the `apc-proxy` crate.
//!
//! `apc-proxy` ships as a binary; this `lib.rs` exists so external test
//! crates under `tests/` can reach the handlers, key map, and supporting
//! types directly (e.g. the live-APC differential harness in `tests/proptest`).
//! The binary entry point is `src/main.rs`.

// `unwrap_used` is denied crate-wide (see Cargo.toml) to keep it out of production
// code paths. In `#[cfg(test)]` modules a panic *is* the intended failure mode and
// the test runner already reports file:line, so the lint is relaxed there. (This
// attribute moved here from `main.rs` when the modules became a library crate.)
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod config;
pub mod error;
pub mod handlers;
pub mod hsm_probe;
pub mod key_map;
pub mod protocol;
pub mod server;
pub mod verify;
