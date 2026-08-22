//! Shared test fixtures. Cargo recognises `tests/common/mod.rs` as a
//! non-test module rather than compiling it as a separate test binary.

pub mod mock_hsm;
pub mod proxy_process;
pub mod tls_certs;

/// Install the rustls crypto provider selected by cargo feature, mirroring
/// `hsm_client::default_crypto_provider` in the production build. Hardcoding
/// `ring` here made the test targets fail to compile under `--features
/// aws-lc-rs`, even though the library itself built fine.
#[allow(dead_code)]
pub fn install_default_crypto_provider() {
    #[cfg(feature = "ring")]
    let provider = rustls::crypto::ring::default_provider();
    #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
    compile_error!("one of features 'ring' or 'aws-lc-rs' must be enabled");

    // Idempotent: only the first install in a test binary wins.
    let _ = provider.install_default();
}

/// Read one complete length-prefixed Thales frame (`[len:2BE][body]`).
///
/// A single `read()` can return a partial TCP segment, so comparing its result
/// against the expected frame fails intermittently — most visibly when the whole
/// suite runs in parallel and responses get split. Read the 2-byte length, then
/// exactly that many body bytes.
#[allow(dead_code)]
pub fn read_framed(conn: &mut impl std::io::Read) -> Vec<u8> {
    let mut len_buf = [0u8; 2];
    conn.read_exact(&mut len_buf).expect("read frame length");
    let body_len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; body_len];
    conn.read_exact(&mut body).expect("read frame body");

    let mut frame = Vec::with_capacity(2 + body_len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&body);
    frame
}

/// `read_framed` for an async stream (the TLS tests drive tokio streams).
#[allow(dead_code)]
pub async fn read_framed_async(conn: &mut (impl tokio::io::AsyncReadExt + Unpin)) -> Vec<u8> {
    let mut len_buf = [0u8; 2];
    conn.read_exact(&mut len_buf)
        .await
        .expect("read frame length");
    let body_len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; body_len];
    conn.read_exact(&mut body).await.expect("read frame body");

    let mut frame = Vec::with_capacity(2 + body_len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&body);
    frame
}
