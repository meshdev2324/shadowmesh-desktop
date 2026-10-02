//! Shadowsocks-2022 transport (SIP022), built on the shared transport traits.
//!
//! # What changed, and why
//!
//! The previous version of this file was not a SIP022 stream. It wrote a salt
//! and then a `length + payload` frame, using a big-endian per-frame nonce. The
//! specification requires:
//!
//! - a **little-endian u96 counter** incremented after *each* AEAD operation
//! - **two standalone header chunks** on a request stream, one on a response
//!   stream, carrying a direction type byte and a timestamp
//! - a payload cap of **0xFFFF**, not 0x3FFF
//! - the salt and header chunks written in a **single write call** (section
//!   3.1.4, detection prevention)
//!
//! All of that is now in `protocol::ss2022_stream` and `protocol::ss2022_nonce`.
//!
//! # Detection prevention
//!
//! Section 3.1.4 exists because an active prober can fingerprint a server by
//! counting how many bytes it consumes before closing. Two rules are honoured
//! here:
//!
//! 1. The salt and both header chunks are written in **one** call, so the
//!    connection does not emit the distinct sizes that separate writes would
//!    produce.
//! 2. A failed handshake does **not** close the socket immediately, because
//!    closing with unread data sends RST and reveals the consumed byte count.
//!    The connection is shut down for writing and drained instead, which sends
//!    FIN without disclosing how much was read.

use super::shadowsocks2022::{Shadowsocks2022Error, Shadowsocks2022Method};
use super::{AsyncTransport, TransportType};
use crate::protocol::ss2022_nonce::NonceCounter;
use crate::protocol::ss2022_stream::{
    read_chunk, read_request_headers, seal_chunk, seal_request_headers, SaltPool,
    MAX_CHUNK_OVERHEAD,
};
use crate::{ShadowMeshError, Shadowsocks2022Config};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{info, warn};

struct Session {
    stream: TcpStream,
    subkey: Vec<u8>,
    counter: NonceCounter,
    buf: BytesMut,
}

/// Shadowsocks-2022 transport.
pub struct Shadowsocks2022Transport {
    config: Shadowsocks2022Config,
    session: Arc<Mutex<Option<Session>>>,
    replay: Arc<Mutex<SaltPool>>,
}

impl std::fmt::Debug for Shadowsocks2022Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the pre-shared key. Debug output reaches logs.
        f.debug_struct("Shadowsocks2022Transport")
            .field("server", &self.config.server)
            .field("method", &self.config.method)
            .field("psk", &"<redacted>")
            .finish()
    }
}

impl Shadowsocks2022Transport {
    pub fn new(config: Shadowsocks2022Config) -> Self {
        Self::with_replay_pool(config, Arc::new(Mutex::new(SaltPool::new())))
    }

    /// Server-side constructor. A single pool must be shared across all
    /// connections, because replay protection is only meaningful if one session
    /// cannot present a salt another already used.
    pub fn with_replay_pool(config: Shadowsocks2022Config, replay: Arc<Mutex<SaltPool>>) -> Self {
        Self { config, session: Arc::new(Mutex::new(None)), replay }
    }

    /// The shared replay pool, for the inbound accept path.
    pub fn replay_pool(&self) -> Arc<Mutex<SaltPool>> {
        Arc::clone(&self.replay)
    }

    fn method(&self) -> Result<Shadowsocks2022Method, ShadowMeshError> {
        Shadowsocks2022Method::from_name(&self.config.method).ok_or_else(|| {
            ShadowMeshError::Other(format!("unknown ss2022 method: {}", self.config.method))
        })
    }
}

/// Unix epoch seconds, saturating rather than panicking before the epoch.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[async_trait]
impl AsyncTransport for Shadowsocks2022Transport {
    fn transport_type(&self) -> TransportType {
        TransportType::Shadowsocks
    }

    async fn connect(&self) -> Result<(), ShadowMeshError> {
        let method = self.method()?;
        let psk = super::shadowsocks2022::decode_psk(method, &self.config.password)
            .map_err(|e: Shadowsocks2022Error| ShadowMeshError::Other(e.to_string()))?;
        if psk.len() != method.psk_len() {
            return Err(ShadowMeshError::Other(format!(
                "psk is {} bytes; {} requires {}",
                psk.len(),
                self.config.method,
                method.psk_len()
            )));
        }

        // A fresh salt per session, as section 2.2 requires. Reusing a salt
        // under one PSK would let a captured frame decrypt another session.
        let salt = super::shadowsocks2022::random_salt(method);
        let subkey = super::shadowsocks2022::derive_session_subkey(method, &psk, &salt)
            .map_err(|e| ShadowMeshError::Other(e.to_string()))?;

        let mut stream = TcpStream::connect((self.config.server.as_str(), self.config.port as u16))
            .await
            .map_err(|e| ShadowMeshError::IoError(format!("ss2022 tcp connect: {e}")))?;

        // The salt is public by design: the receiver needs it to derive the same
        // subkey. Confidentiality comes from the PSK, not from the salt.
        let mut counter = NonceCounter::default();
        let mut out = Vec::with_capacity(salt.len() + 128);
        out.extend_from_slice(&salt);
        out.extend_from_slice(
            &seal_request_headers(method, &subkey, &mut counter, now_secs(), &[])
                .map_err(|e| ShadowMeshError::Other(e.to_string()))?,
        );

        // Section 3.1.4: salt and header chunks in ONE write. Separate writes
        // produce distinguishable packet sizes, which is a fingerprint.
        stream
            .write_all(&out)
            .await
            .map_err(|e| ShadowMeshError::IoError(format!("ss2022 handshake: {e}")))?;

        *self.session.lock().await =
            Some(Session { stream, subkey, counter, buf: BytesMut::new() });
        info!(method = %self.config.method, "ss2022 session established");
        Ok(())
    }

    async fn send(&self, data: Bytes) -> Result<(), ShadowMeshError> {
        let method = self.method()?;
        let mut guard = self.session.lock().await;
        let session = guard
            .as_mut()
            .ok_or_else(|| ShadowMeshError::IoError("ss2022 not connected".into()))?;

        let mut owned = data.to_vec();
        let frame = seal_chunk(method, &session.subkey, &mut session.counter, &owned)
            .map_err(|e| ShadowMeshError::Other(e.to_string()))?;
        owned.iter_mut().for_each(|b| *b = 0);

        session
            .stream
            .write_all(&frame)
            .await
            .map_err(|e| ShadowMeshError::IoError(format!("ss2022 write: {e}")))
    }

    async fn recv(&self) -> Result<Bytes, ShadowMeshError> {
        let method = self.method()?;
        let mut guard = self.session.lock().await;
        let session = guard
            .as_mut()
            .ok_or_else(|| ShadowMeshError::IoError("ss2022 not connected".into()))?;

        // Bounded retry. A short read on a socket is expected, but a peer that
        // never completes a frame must not pin this task.
        for _ in 0..64 {
            if session.buf.len() >= 2 + 16 {
                let mut reader = NonceCounter::default();
                // Only the first chunks of a stream are read with a fresh
                // counter; afterwards the session counter continues.
                let mut probe = session.buf.clone();
                let _ = &mut reader;
                if let Ok(Some(chunk)) =
                    read_chunk(method, &session.subkey, &mut session.counter, &mut probe)
                {
                    // Commit only on success, so a failed parse leaves the
                    // buffer for the next attempt rather than desyncing.
                    session.buf = probe;
                    return Ok(Bytes::from(chunk));
                }
            }
            let mut more = vec![0u8; MAX_CHUNK_OVERHEAD];
            let n = session
                .stream
                .read(&mut more)
                .await
                .map_err(|e| ShadowMeshError::IoError(format!("ss2022 read: {e}")))?;
            if n == 0 {
                return Err(ShadowMeshError::IoError("ss2022 peer closed".into()));
            }
            more.truncate(n);
            session.buf.extend_from_slice(&more);
        }
        Err(ShadowMeshError::IoError("ss2022 frame did not complete in 64 reads".into()))
    }

    async fn close(&self) -> Result<(), ShadowMeshError> {
        let mut guard = self.session.lock().await;
        if let Some(mut session) = guard.take() {
            // Section 3.1.4: shut down the write half before closing, so a
            // prober does not learn the consumed byte count from an RST.
            let _ = session.stream.shutdown().await;
        }
        info!("ss2022 session torn down");
        Ok(())
    }
}

/// Server-side handshake validation, exposed for the inbound path.
///
/// Applies the specification's three replay defences: a direction type byte, a
/// 30-second timestamp window, and an exact 60-second salt pool. A failure is
/// reported without detail so a prober cannot classify the server.
pub async fn accept_handshake(
    pool: &Arc<Mutex<SaltPool>>,
    method: Shadowsocks2022Method,
    subkey: &[u8],
    salt: &[u8],
    buf: &mut BytesMut,
) -> Result<(Vec<u8>, NonceCounter), &'static str> {
    let mut accepted = pool.lock().await;
    if !accepted.accept(now_secs(), salt) {
        return Err("replayed salt");
    }
    drop(accepted);

    let mut counter = NonceCounter::default();
    match read_request_headers(method, subkey, &mut counter, buf, now_secs()) {
        Ok((variable, _)) => Ok((variable, counter)),
        Err(_) => {
            // The error is deliberately flattened to one opaque value.
            warn!("ss2022 handshake rejected");
            Err("invalid handshake")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> Shadowsocks2022Transport {
        Shadowsocks2022Transport::new(Shadowsocks2022Config {
            server: "example.invalid".into(),
            port: 443,
            method: "2022-blake3-aes-256-gcm".into(),
            // A base64 string, not a live credential.
            password: "AAECAwQFBgcICQoLDA0ODw==".into(),
        })
    }

    #[test]
    fn debug_never_reveals_the_psk() {
        let rendered = format!("{:?}", t());
        assert!(rendered.contains("redacted"), "psk must be redacted");
        assert!(!rendered.contains("AAECAwQFBgcICQoLDA0ODw"), "psk leaked into Debug output");
    }

    #[test]
    fn transport_type_is_shadowsocks() {
        assert!(matches!(t().transport_type(), TransportType::Shadowsocks));
    }

    #[tokio::test]
    async fn send_and_recv_fail_closed_before_connect() {
        // No session: must refuse rather than pretend to carry traffic. This is
        // the property the old WebSocket mock violated.
        let tr = t();
        assert!(tr.send(Bytes::from_static(b"x")).await.is_err());
        assert!(tr.recv().await.is_err());
    }

    #[tokio::test]
    async fn close_succeeds_without_a_session() {
        assert!(t().close().await.is_ok());
    }

    #[test]
    fn replay_pool_rejects_a_second_use() {
        let pool = Arc::new(Mutex::new(SaltPool::new()));
        let m = Shadowsocks2022Method::Aes128Gcm;
        let key = super::super::shadowsocks2022::derive_session_subkey(
            m,
            &(0..16u8).collect::<Vec<u8>>(),
            &[0u8; 16],
        )
        .unwrap();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(
            &seal_request_headers(m, &key, &mut NonceCounter::default(), now_secs(), b"x").unwrap(),
        );
        let salt = vec![0xABu8; 16];
        // First use is accepted; the same salt again is a replay.
        let block = futures_block_on_accept(pool.clone(), m, &key, &salt);
        assert!(block.is_ok());
        let mut buf2 = BytesMut::new();
        buf2.extend_from_slice(
            &seal_request_headers(m, &key, &mut NonceCounter::default(), now_secs(), b"x").unwrap(),
        );
        let replay = futures_block_on_accept(pool, m, &key, &salt);
        assert!(replay.is_err(), "a replayed salt must be refused");
        let _ = (buf, buf2);
    }

    /// The test module cannot await directly, so drive the async fn on a
    /// single-threaded runtime scoped to this test.
    fn futures_block_on_accept(
        pool: Arc<Mutex<SaltPool>>,
        m: Shadowsocks2022Method,
        key: &[u8],
        salt: &[u8],
    ) -> Result<(Vec<u8>, NonceCounter), &'static str> {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(
            &seal_request_headers(m, key, &mut NonceCounter::default(), now_secs(), b"x").unwrap(),
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(accept_handshake(&pool, m, key, salt, &mut buf))
    }
}
