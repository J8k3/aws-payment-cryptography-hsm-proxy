//! Test-only mock HSM. Binds an ephemeral TCP port and acts like an HSM the
//! proxy can forward to in passthrough/discovery mode. Each connection is
//! handled exactly once: read the inbound frame, write a canned response,
//! record what was received for the test to assert on. Lives entirely in
//! `tests/` — not part of the shipped proxy.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// A running mock HSM. Drop the handle when the test ends; the task will
/// finish naturally after `expected_connections` are served (or whenever the
/// process exits).
pub struct MockHsm {
    pub addr: std::net::SocketAddr,
    /// Captured frames the proxy forwarded — one entry per accepted connection.
    pub received: Arc<Mutex<Vec<Vec<u8>>>>,
    _task: JoinHandle<()>,
}

/// Test fixture: variants are added as later passthrough tests need them.
/// `AcceptThenHang` will be wired in when we add the timeout test.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum MockBehavior {
    /// Read inbound frame, immediately write the canned response, close.
    Respond(Vec<u8>),
    /// Accept the connection, read the frame, then hang indefinitely
    /// (no response). Use to exercise proxy's read-timeout path.
    AcceptThenHang,
}

impl MockHsm {
    /// Spawn a mock that serves at most `connections` connections then exits.
    /// Returns once the listener is bound — callers can immediately read
    /// `addr` and feed it into a proxy config.
    pub async fn spawn(behavior: MockBehavior, connections: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock HSM listener");
        let addr = listener.local_addr().expect("local_addr");

        let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let received_for_task = Arc::clone(&received);

        let task = tokio::spawn(async move {
            for _ in 0..connections {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                // Read whatever the proxy forwards in one go. The proxy
                // currently sends a single frame per connection and waits
                // for a single response, so one read is sufficient.
                let mut buf = vec![0u8; 65536];
                let Ok(n) = stream.read(&mut buf).await else {
                    continue;
                };
                buf.truncate(n);
                received_for_task.lock().await.push(buf);

                match &behavior {
                    MockBehavior::Respond(reply) => {
                        let _ = stream.write_all(reply).await;
                        let _ = stream.shutdown().await;
                    }
                    MockBehavior::AcceptThenHang => {
                        // Hold the socket open without replying so the proxy
                        // exercises its read-timeout. Sleep long enough that
                        // any reasonable test timeout fires first.
                        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                    }
                }
            }
        });

        Self {
            addr,
            received,
            _task: task,
        }
    }

    /// Convenience: snapshot the captured frames (clones, so the lock is
    /// released immediately).
    pub async fn frames(&self) -> Vec<Vec<u8>> {
        self.received.lock().await.clone()
    }
}
