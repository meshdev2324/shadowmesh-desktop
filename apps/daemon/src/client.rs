//! Desktop-side IPC client for the ShadowMesh daemon (RFC-016 §4.1).
//!
//! Speaks the daemon's existing framed protocol (`IpcCodec`, length-prefix,
//! 64 KiB cap) over the daemon's 0600 Unix socket. Trust model: same-user
//! socket permissions first; the daemon token (`SHADOWMESH_DAEMON_TOKEN`)
//! is defense-in-depth until OS-keyring pairing lands (RFC-016 non-goal).

use crate::ipc_codec::IpcCodec;
use crate::types::{VpnAction, VpnCommand, VpnResponse};
use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Standard request window (Status/Ping/Disconnect).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Connect involves node selection and possibly PoW — server-side work.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolves the daemon socket: `SHADOWMESH_DAEMON_SOCKET` overrides, else
/// `$HOME/.shadowmesh.sock` (matches the daemon's well-known path).
pub fn socket_path() -> PathBuf {
    socket_path_from(
        &std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()),
        std::env::var("SHADOWMESH_DAEMON_SOCKET").ok().as_deref(),
    )
}

/// Pure resolution logic (tested without touching process env).
pub fn socket_path_from(home: &str, env_override: Option<&str>) -> PathBuf {
    match env_override {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(home).join(".shadowmesh.sock"),
    }
}

/// The daemon token from the environment (empty = none configured).
pub fn token_from_env() -> Option<String> {
    std::env::var("SHADOWMESH_DAEMON_TOKEN").ok().filter(|t| !t.is_empty())
}

/// A connection to the daemon. One request/response per frame; the daemon
/// handles commands sequentially per connection, so no multiplexing needed.
pub struct DaemonClient {
    stream: UnixStream,
}

impl DaemonClient {
    /// Connects to the daemon at the resolved socket path.
    pub async fn connect() -> Result<Self> {
        Self::connect_to(socket_path()).await
    }

    /// Connects to an explicit socket path (tests, custom deployments).
    pub async fn connect_to(path: PathBuf) -> Result<Self> {
        let stream = UnixStream::connect(&path)
            .await
            .with_context(|| format!("daemon socket connect failed ({})", path.display()))?;
        Ok(Self::from_stream(stream))
    }

    /// Wraps an already-connected stream (loopback tests, socket activation).
    pub fn from_stream(stream: UnixStream) -> Self {
        Self { stream }
    }

    /// Handshake: a `Ping` round-trip proves framing + daemon liveness.
    pub async fn handshake(&mut self) -> Result<VpnResponse> {
        self.request(VpnAction::Ping).await
    }

    /// Standard request (10s window).
    pub async fn request(&mut self, action: VpnAction<'_>) -> Result<VpnResponse> {
        self.request_with_timeout(action, REQUEST_TIMEOUT).await
    }

    /// Connect with the extended window (node selection + PoW server-side).
    pub async fn connect_vpn(
        &mut self,
        node_id: &str,
        mode: Option<String>,
    ) -> Result<VpnResponse> {
        self.request_with_timeout(
            VpnAction::Connect { node_id: node_id.into(), mode: mode.map(Into::into) },
            CONNECT_TIMEOUT,
        )
        .await
    }

    /// Sends one command and awaits its response frame.
    pub async fn request_with_timeout(
        &mut self,
        action: VpnAction<'_>,
        timeout: Duration,
    ) -> Result<VpnResponse> {
        let token = token_from_env().unwrap_or_default();
        let cmd = VpnCommand { action, token: std::borrow::Cow::Owned(token) };
        let payload = serde_json::to_vec(&cmd)?;

        let mut out = BytesMut::new();
        IpcCodec::encode(&payload, &mut out)?;
        self.stream.write_all(&out).await?;
        self.stream.flush().await?;

        let mut buf = BytesMut::with_capacity(IpcCodec::MAX_PAYLOAD_SIZE);
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(frame) = IpcCodec::decode(&mut buf)? {
                let response: VpnResponse = serde_json::from_slice(&frame)
                    .map_err(|e| anyhow!("daemon sent malformed response: {e}"))?;
                return Ok(response);
            }
            let mut chunk = [0u8; 8192];
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("daemon response timed out"));
            }
            let n = tokio::time::timeout(remaining, self.stream.read(&mut chunk))
                .await
                .map_err(|_| anyhow!("daemon response timed out"))??;
            if n == 0 {
                return Err(anyhow!("daemon closed the connection"));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }
}
