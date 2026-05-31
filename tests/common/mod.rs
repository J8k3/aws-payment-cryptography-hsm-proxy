//! Shared test fixtures. Cargo recognises `tests/common/mod.rs` as a
//! non-test module rather than compiling it as a separate test binary.

pub mod mock_hsm;
pub mod proxy_process;
