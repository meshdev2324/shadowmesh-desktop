use crate::engine::metadata::{Addr, ConnectionMetadata};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    Domain(String),
    DomainSuffix(String),
    IpCidr(String),
    SourceIpCidr(String),
    Port(u16),
    Protocol(String),
    ProcessName(String),
    InboundTag(String),
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),
}

impl Condition {
    pub fn matches(&self, metadata: &ConnectionMetadata) -> bool {
        match self {
            Condition::Domain(d) => match &metadata.identity.destination.addr {
                Addr::Domain(domain) => domain == d,
                _ => false,
            },
            Condition::DomainSuffix(s) => match &metadata.identity.destination.addr {
                Addr::Domain(domain) => domain.ends_with(s),
                _ => false,
            },
            Condition::IpCidr(cidr) => {
                if let Addr::Ip(dest_ip) = &metadata.identity.destination.addr {
                    if let Ok(net) = IpNet::from_str(cidr) {
                        return net.contains(dest_ip);
                    }
                }
                false
            }
            Condition::SourceIpCidr(cidr) => {
                if let Some(source) = &metadata.identity.source {
                    if let Addr::Ip(src_ip) = &source.addr {
                        if let Ok(net) = IpNet::from_str(cidr) {
                            return net.contains(src_ip);
                        }
                    }
                }
                false
            }
            Condition::Port(p) => metadata.identity.destination.port == *p,
            Condition::Protocol(proto) => {
                // Check sniffed protocol first, then metadata protocol
                if let Some(sniffed) = &metadata.sniffed {
                    if let Some(p) = &sniffed.protocol {
                        if format!("{:?}", p).eq_ignore_ascii_case(proto) {
                            return true;
                        }
                    }
                }
                format!("{:?}", metadata.l4_protocol).eq_ignore_ascii_case(proto)
            }
            Condition::ProcessName(name) => metadata.identity.process_name.as_ref() == Some(name),
            Condition::InboundTag(t) => metadata.environment.inbound_tag.as_ref() == Some(t),
            Condition::And(conds) => conds.iter().all(|c| c.matches(metadata)),
            Condition::Or(conds) => conds.iter().any(|c| c.matches(metadata)),
            Condition::Not(c) => !c.matches(metadata),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::metadata::{ApplicationProtocol, ConnectionMetadata, Endpoint, L4Protocol};

    #[test]
    fn test_cidr_matching() {
        let dest = Endpoint::new_ip("1.2.3.4".parse().unwrap(), 80);
        let mut metadata = ConnectionMetadata::new(dest);
        metadata.identity.source = Some(Endpoint::new_ip("192.168.1.10".parse().unwrap(), 12345));

        let cond = Condition::IpCidr("1.2.3.0/24".to_string());
        assert!(cond.matches(&metadata));

        let cond = Condition::IpCidr("1.2.4.0/24".to_string());
        assert!(!cond.matches(&metadata));

        let cond = Condition::SourceIpCidr("192.168.1.0/24".to_string());
        assert!(cond.matches(&metadata));
    }

    #[test]
    fn test_protocol_matching() {
        let dest = Endpoint::new_domain("example.com".to_string(), 443);
        let mut metadata = ConnectionMetadata::new(dest);
        metadata.l4_protocol = L4Protocol::Tcp;

        let cond = Condition::Protocol("TCP".to_string());
        assert!(cond.matches(&metadata));

        let cond = Condition::Protocol("tcp".to_string());
        assert!(cond.matches(&metadata));

        metadata.sniffed = Some(crate::engine::metadata::SniffedData {
            protocol: Some(ApplicationProtocol::Tls),
            domain: None,
        });

        let cond = Condition::Protocol("TLS".to_string());
        assert!(cond.matches(&metadata));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Route(String), // Outbound tag
    Reject,
    Bypass,
    Sniff,
    Resolve,
    HijackDNS,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    pub tag: String,
    pub condition: Condition,
    pub action: Action,
}
