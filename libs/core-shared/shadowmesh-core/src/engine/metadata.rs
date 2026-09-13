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

/// Identity information about the connection source and destination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub source: Option<Endpoint>,
    pub destination: Endpoint,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub user_id: Option<u32>,
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
