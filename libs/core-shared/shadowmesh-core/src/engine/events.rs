use crate::engine::context::SharedContext;
use crate::engine::metadata::DnsQueryType;
use crate::transport::traits::AsyncIoStream;
use std::net::SocketAddr;

/// Core event types for the ShadowMesh engine orchestration.
pub enum EngineEvent {
    /// A new connection has been initiated.
    ConnectionInitiated { context: SharedContext },
    /// A new TCP-like stream connection has been established by an inbound.
    NewStream { context: SharedContext, stream: Box<dyn AsyncIoStream> },
    /// A UDP packet has been received. The optional reply channel (RFC-012
    /// G2) receives the upstream response payload (or None for
    /// fire-and-forget/timeout) so UDP-capable inbounds can answer their
    /// client without coupling to the dispatcher.
    UdpPacket {
        context: SharedContext,
        payload: Vec<u8>,
        source: SocketAddr,
        reply: Option<tokio::sync::oneshot::Sender<Option<Vec<u8>>>>,
    },
    /// A connection has been successfully established to the outbound.
    ConnectionEstablished { id: u64, outbound_tag: String },
    /// A connection has been terminated.
    ConnectionClosed { id: u64, tx_bytes: u64, rx_bytes: u64, reason: String },
}

/// Events related to routing and policy evaluation.
pub enum RoutingEvent {
    /// A request to determine the outbound path for a connection.
    RouteRequest { context: SharedContext },
    /// The result of a routing decision.
    RouteDecision { id: u64, outbound_tag: String },
    /// Routing failed due to policy or no match.
    RouteFailed { id: u64, reason: String },
}

/// Events related to DNS resolution.
pub enum DnsEvent {
    /// A DNS resolution request.
    Query { domain: String, query_type: DnsQueryType },
    /// The result of a DNS resolution.
    Response { domain: String, ips: Vec<std::net::IpAddr> },
    /// DNS resolution failed.
    Failure { domain: String, reason: String },
}
