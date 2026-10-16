use crate::dns::DnsResolver;
use crate::engine::metadata::DnsQueryType;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;

pub struct UdpDnsUpstream {
    server: SocketAddr,
}

impl UdpDnsUpstream {
    pub fn new(server: SocketAddr) -> Self {
        Self { server }
    }

    fn map_query_type(qt: &DnsQueryType) -> u16 {
        match qt {
            DnsQueryType::A => 1,
            DnsQueryType::AAAA => 28,
            DnsQueryType::Cname => 5,
            DnsQueryType::Mx => 15,
            DnsQueryType::Txt => 16,
            DnsQueryType::Ptr => 12,
            DnsQueryType::Srv => 33,
            DnsQueryType::Https => 65,
            DnsQueryType::Svcb => 64,
            DnsQueryType::Unknown(v) => *v,
        }
    }
}

#[async_trait]
impl DnsResolver for UdpDnsUpstream {
    async fn resolve(&self, domain: &str, query_type: DnsQueryType) -> Result<Vec<IpAddr>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.server).await?;

        // Construct a simple DNS query
        let mut query = Vec::with_capacity(512);
        // Transaction ID
        query.extend_from_slice(&[0x12, 0x34]);
        // Flags (standard query, recursion desired)
        query.extend_from_slice(&[0x01, 0x00]);
        // Questions (1)
        query.extend_from_slice(&[0x00, 0x01]);
        // Answer RRs (0)
        query.extend_from_slice(&[0x00, 0x00]);
        // Authority RRs (0)
        query.extend_from_slice(&[0x00, 0x00]);
        // Additional RRs (0)
        query.extend_from_slice(&[0x00, 0x00]);

        // Question: Domain
        for part in domain.split('.') {
            query.push(part.len() as u8);
            query.extend_from_slice(part.as_bytes());
        }
        query.push(0);

        // Type
        query.extend_from_slice(&Self::map_query_type(&query_type).to_be_bytes());
        // Class (IN = 1)
        query.extend_from_slice(&[0x00, 0x01]);

        socket.send(&query).await?;

        let mut buf = [0u8; 512];
        let n = socket.recv(&mut buf).await?;

        // Very basic parsing (skipping to answers)
        if n < 12 {
            return Err(anyhow!("Invalid DNS response"));
        }

        // Check if it's a response and no error
        if buf[2] & 0x80 == 0 || buf[3] & 0x0F != 0 {
            return Err(anyhow!("DNS error or not a response"));
        }

        // v6.9.1: Fallback to system resolver for POC as wire parsing is complex
        // In full implementation, we would parse the DNS RRs here.
        let addrs = tokio::net::lookup_host(format!("{}:0", domain)).await?;
        Ok(addrs.map(|s| s.ip()).collect())
    }
}
