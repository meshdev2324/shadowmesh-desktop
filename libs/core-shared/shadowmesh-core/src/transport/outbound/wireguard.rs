use crate::engine::context::SharedContext;
use crate::transport::traits::{AsyncIoStream, OutboundDialer};
use crate::transport::wireguard::WireGuardTransport;
use crate::transport::AsyncTransport;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// WireGuard outbound built on the boringtun-backed `WireGuardTransport`.
///
/// Implementation Source:
/// - Specification: WireGuard protocol (official whitepaper)
/// - Relevant sections: handshake (Noise_IKpsk2), transport data messages,
///   keepalive (an empty inner packet).
/// - Security considerations: x25519 keys from base64 config; key material
///   lives inside boringtun; no custom crypto here.
///
/// `dial_stream` binds the UDP socket, drives the boringtun handshake, and
/// returns a packet-oriented stream shim: the engine's byte-oriented plumbing
/// reads/writes inner IP packets, which is the WireGuard data model.
pub struct WireguardOutbound {
    pub tag: String,
    private_key: String,
    public_key: String,
    endpoint: String,
}

impl WireguardOutbound {
    pub fn new(tag: String, endpoint: String, private_key: String, public_key: String) -> Self {
        Self { tag, private_key, public_key, endpoint }
    }

    fn build_transport(&self) -> Result<WireGuardTransport> {
        let remote_addr: SocketAddr = self
            .endpoint
            .parse()
            .map_err(|_| anyhow!("Invalid WireGuard endpoint: {}", self.endpoint))?;
        WireGuardTransport::new(remote_addr, self.private_key.clone(), self.public_key.clone())
            .map_err(|e| anyhow!("WireGuard transport init failed: {e:?}"))
    }

    /// Drives the boringtun handshake to completion. A zero-length inner
    /// "packet" makes boringtun emit the handshake initiation; the peer's
    /// response is consumed inside `recv()` which completes the session.
    async fn handshake(&self, transport: &WireGuardTransport) -> Result<()> {
        transport
            .send(Bytes::new())
            .await
            .map_err(|e| anyhow!("WireGuard handshake initiation failed: {e:?}"))?;

        let mut attempts = 0u8;
        loop {
            attempts += 1;
            match tokio::time::timeout(std::time::Duration::from_secs(5), transport.recv()).await {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => return Err(anyhow!("WireGuard handshake transport error: {e:?}")),
                Err(_) => {
                    if attempts >= 3 {
                        return Err(anyhow!("WireGuard handshake timed out"));
                    }
                    // Retry: re-emits the initiation while the session is
                    // not yet established (boringtun retransmit semantics).
                    transport
                        .send(Bytes::new())
                        .await
                        .map_err(|e| anyhow!("WireGuard handshake retry failed: {e:?}"))?;
                }
            }
        }
    }
}

#[async_trait]
impl OutboundDialer for WireguardOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, _context: SharedContext) -> Result<Box<dyn AsyncIoStream>> {
        tracing::debug!("WireGuard outbound [{}] connecting to {}", self.tag, self.endpoint);

        let transport = self.build_transport()?;
        transport.connect().await.map_err(|e| anyhow!("WireGuard socket bind failed: {e:?}"))?;

        self.handshake(&transport).await?;

        // Post-handshake keepalive so NAT mappings survive and the session
        // timer starts cleanly.
        transport
            .send(Bytes::new())
            .await
            .map_err(|e| anyhow!("WireGuard keepalive failed: {e:?}"))?;

        Ok(Box::new(WireGuardPacketStream { transport: Arc::new(transport) }))
    }

    async fn send_packet(
        &self,
        _context: SharedContext,
        payload: &[u8],
        _source: SocketAddr,
    ) -> Result<Vec<u8>> {
        // WireGuard data path: one datagram = one inner IP packet, exactly
        // the datagram model `send_packet` carries.
        let transport = self.build_transport()?;
        transport.connect().await.map_err(|e| anyhow!("WireGuard socket bind failed: {e:?}"))?;
        transport
            .send(Bytes::copy_from_slice(payload))
            .await
            .map_err(|e| anyhow!("WireGuard send failed: {e:?}"))?;
        // Bounded reply wait on the WG session socket.
        match tokio::time::timeout(std::time::Duration::from_millis(2000), transport.recv()).await {
            Ok(Ok(packet)) => Ok(packet.to_vec()),
            Ok(Err(e)) => Err(anyhow!("WireGuard reply error: {e:?}")),
            Err(_) => Ok(Vec::new()),
        }
    }
}

/// Packet-oriented stream shim over the WireGuard transport so the engine's
/// byte-oriented dispatcher can carry WG sessions: each poll_write is one
/// inner IP packet; poll_read surfaces decapsulated inner packets.
pub struct WireGuardPacketStream {
    transport: Arc<WireGuardTransport>,
}

impl AsyncRead for WireGuardPacketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let transport = self.get_mut().transport.clone();
        let mut fut = Box::pin(async move { transport.recv().await });
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(packet)) => {
                let n = packet.len().min(buf.remaining());
                buf.put_slice(&packet[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(format!("{e:?}")))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WireGuardPacketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let transport = self.get_mut().transport.clone();
        let data = Bytes::copy_from_slice(buf);
        let mut fut = Box::pin(async move { transport.send(data).await });
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(format!("{e:?}")))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let transport = self.get_mut().transport.clone();
        let mut fut = Box::pin(async move { transport.close().await });
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(format!("{e:?}")))),
            Poll::Pending => Poll::Pending,
        }
    }
}
