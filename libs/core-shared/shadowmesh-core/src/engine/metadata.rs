use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// Represents a network address, either an IP or a Domain name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Addr {
    /// An IP address (v4 or v6).
    Ip(IpAddr),
    /// A domain name string.
    Domain(String),
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::Ip(ip) => write!(f, "{}", ip),
            Addr::Domain(domain) => write!(f, "{}", domain),
        }
    }
}

/// A combination of an address and a port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub addr: Addr,
    pub port: u16,
}

impl Endpoint {
    pub fn new_ip(ip: IpAddr, port: u16) -> Self {
        Self { addr: Addr::Ip(ip), port }
    }

    pub fn new_domain(domain: String, port: u16) -> Self {
        Self { addr: Addr::Domain(domain), port }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(addr: SocketAddr) -> Self {
        Self { addr: Addr::Ip(addr.ip()), port: addr.port() }
    }
}

/// The transport layer protocol (Layer 4).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum L4Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown,
}

/// Common application layer protocols detected via sniffing (Layer 7).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ApplicationProtocol {
    Http,
    Https,
    Tls,
    Quic,
    Dns,
    Ssh,
    Smtp,
    Ftp,
    BitTorrent,
    Unknown(String),
}

/// Whose socket [`Identity::source`] names.
///
/// This exists because "source" means two different things depending on which
/// side of the connection the metadata was built on, and process attribution
/// only makes sense for one of them.
///
/// [`ProcessSearcher`](crate::engine::process::ProcessSearcher) answers "which
/// process *on this host* owns a socket bound to this port", by reading this
/// host's `/proc/net/tcp{,6}`. That question has an answer only when the source
/// endpoint is a socket this host opened. On an inbound proxy the source
/// endpoint is the *remote peer's* address -- an address this host has never
/// bound -- and its port is an ephemeral port chosen by the peer's kernel. Any
/// local listener that happens to sit on that number would be reported as the
/// owner, so an inbound packet gets labelled with the name of an unrelated
/// process. That label reaches `Condition::ProcessName` in the routing rules
/// and traffic shaping, which makes it a routing decision, not telemetry.
///
/// So the transport states which of the two it has, through
/// [`Identity::set_local_source`] or [`Identity::set_remote_peer_source`], and
/// attribution is only performed for [`SourceOrigin::Local`]. Anything that
/// does not state an origin is treated as **not local** -- see the `None`
/// documentation on [`Identity::source_origin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceOrigin {
    /// The source endpoint is a socket this host opened: traffic this node
    /// originated, so a local process can own it and `process_name` is
    /// meaningful.
    Local,
    /// The source endpoint is the far end of a connection this host accepted.
    /// No local process owns it, so `process_name` must stay `None`.
    RemotePeer,
}

/// Identity information about the connection source and destination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    /// The source endpoint.
    ///
    /// Do not assign this directly. Use [`Identity::set_local_source`] or
    /// [`Identity::set_remote_peer_source`] so that
    /// [`source_origin`](Self::source_origin) is set with it; an endpoint
    /// without an origin is treated as a remote peer and is never attributed to
    /// a process.
    pub source: Option<Endpoint>,
    /// Which side's socket [`source`](Self::source) names.
    ///
    /// `None` means "the transport did not say", and is read as
    /// [`SourceOrigin::RemotePeer`] by the attribution path -- the safe
    /// reading, since it suppresses a lookup that could only produce a wrong
    /// answer. `#[serde(default)]` keeps metadata written before this field
    /// existed deserialising, and it deserialises to exactly that safe value.
    #[serde(default)]
    pub source_origin: Option<SourceOrigin>,
    pub destination: Endpoint,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub user_id: Option<u32>,
}

impl Identity {
    /// Record a source endpoint that is a socket this host opened.
    ///
    /// This is the only path by which `process_name` can be filled in later.
    pub fn set_local_source(&mut self, source: Endpoint) {
        self.source = Some(source);
        self.source_origin = Some(SourceOrigin::Local);
    }

    /// Record a source endpoint that is the remote peer of a connection this
    /// host accepted.
    ///
    /// Every inbound listener that fills in `identity.source` from `peer_addr`
    /// -- Shadowsocks, SOCKS5, HTTP, VLESS, Trojan, Hysteria -- is a remote
    /// peer. Marking it here is what keeps an ephemeral peer port from being
    /// resolved against this host's listeners.
    pub fn set_remote_peer_source(&mut self, source: Endpoint) {
        self.source = Some(source);
        self.source_origin = Some(SourceOrigin::RemotePeer);
    }
}

/// The type of network being used.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkType {
    Cellular,
    Ethernet,
    WiFi,
    Other,
}

/// Environmental metadata about where the connection originated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Environment {
    pub inbound_tag: Option<String>,
    pub interface_name: Option<String>,
    pub wifi_ssid: Option<String>,
    pub wifi_bssid: Option<String>,
    pub network_type: Option<NetworkType>,
}

/// Data recovered through protocol sniffing (DPI).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SniffedData {
    pub protocol: Option<ApplicationProtocol>,
    pub domain: Option<String>,
}

/// DNS Query Types (RFC 1035 and updates).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DnsQueryType {
    A,
    AAAA,
    Cname,
    Mx,
    Txt,
    Ptr,
    Srv,
    Https,
    Svcb,
    Unknown(u16),
}

/// Metadata related to DNS resolution for the connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsContext {
    pub original_destination: Option<IpAddr>,
    pub resolved_ips: Vec<IpAddr>,
    pub query_type: Option<DnsQueryType>,
}

/// Represents the progress of a protocol handshake.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state, no data exchanged.
    Unauthenticated,
    /// Handshake data received, validation in progress.
    Validating,
    /// Handshake completed successfully.
    Established,
    /// Handshake failed.
    Failed,
    /// Connection is being terminated.
    Terminated,
}

/// The unified Intermediate Representation (IR) of a network connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionMetadata {
    pub identity: Identity,
    pub l4_protocol: L4Protocol,
    pub environment: Environment,
    pub handshake: HandshakeState,
    pub sniffed: Option<SniffedData>,
    pub dns_context: Option<DnsContext>,
}

impl ConnectionMetadata {
    pub fn new(destination: Endpoint) -> Self {
        Self {
            identity: Identity {
                source: None,
                source_origin: None,
                destination,
                process_name: None,
                process_path: None,
                user_id: None,
            },
            l4_protocol: L4Protocol::Unknown,
            environment: Environment {
                inbound_tag: None,
                interface_name: None,
                wifi_ssid: None,
                wifi_bssid: None,
                network_type: None,
            },
            handshake: HandshakeState::Unauthenticated,
            sniffed: None,
            dns_context: None,
        }
    }
}
