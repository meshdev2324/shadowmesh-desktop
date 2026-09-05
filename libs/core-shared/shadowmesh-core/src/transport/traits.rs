use crate::engine::context::SharedContext;
use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

/// A common interface for asynchronous I/O streams.
pub trait AsyncIoStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncIoStream for T {}

/// Unified interface for asynchronous transport (Stream or Packet).
#[async_trait]
pub trait BaseTransport: Send + Sync {
    /// The unique tag for this transport.
    fn tag(&self) -> &str;

    /// Returns the type of transport (TCP/UDP).
    fn l4_protocol(&self) -> crate::engine::metadata::L4Protocol;
}

/// Interface for inbound listeners that accept incoming connections.
#[async_trait]
pub trait InboundListener: Send + Sync {
    /// The unique tag for this inbound.
    fn tag(&self) -> &str;

    /// Starts the listener loop.
    async fn listen(&self) -> Result<()>;
}

/// Interface for outbound dialers that establish connections to remote destinations.
#[async_trait]
pub trait OutboundDialer: Send + Sync {
    /// The unique tag for this outbound.
    fn tag(&self) -> &str;

    /// Establishes a TCP-like stream to the destination defined in the context.
    async fn dial_stream(&self, context: SharedContext) -> Result<Box<dyn AsyncIoStream>>;

    /// Sends a UDP packet to the destination defined in the context and
    /// returns the reply payload when one arrives within the protocol's
    /// reply window (RFC-012 G2). Outbounds that cannot carry replies
    /// (fire-and-forget transports) return an empty Vec.
    async fn send_packet(
        &self,
        context: SharedContext,
        payload: &[u8],
        source: SocketAddr,
    ) -> Result<Vec<u8>>;
}

/// Interface for protocol-specific handlers (e.g., DNS, Sniffing).
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// The name of the protocol.
    fn name(&self) -> &str;

    /// Attempts to handle or transform the data based on the protocol.
    /// Returns true if the protocol was identified and metadata updated.
    async fn sniff(&self, context: SharedContext, data: &[u8]) -> Result<bool>;
}
