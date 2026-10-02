use crate::engine::context::ConnectionContext;
use crate::engine::metadata::{ConnectionMetadata, Endpoint, L4Protocol};
use crate::engine::{events::EngineEvent, EngineHandle};
use crate::transport::traits::InboundListener;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};
use parking_lot::Mutex;
/// Implementation Source:
/// - RFC / specification: RFC 1928 (SOCKS Protocol Version 5)
/// - Relevant sections: §3 (Procedure), §4 (Requests)
/// - Security considerations: Handshake validation, resource protection against malformed frames.
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// SOCKS5 Inbound listener following RFC 1928.
pub struct SocksInbound {
    tag: String,
    listen_addr: String,
    engine: EngineHandle,
}

impl SocksInbound {
    pub fn new(tag: String, listen_addr: String, engine: EngineHandle) -> Self {
        Self { tag, listen_addr, engine }
    }

    async fn handle_connection(
        engine: EngineHandle,
        tag: String,
        mut stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let mut buf = [0u8; 1024];

        // 1. Greeting (RFC 1928 §3)
        let n = stream.read(&mut buf).await?;
        let (_, methods) =
            parse_socks_greeting(&buf[..n]).map_err(|_| anyhow!("Invalid SOCKS5 greeting"))?;

        if !methods.contains(&0x00) {
            return Err(anyhow!("SOCKS5 auth method 'No Authentication' required"));
        }

        stream.write_all(&[0x05, 0x00]).await?;

        // 2. Request (RFC 1928 §4)
        let n = stream.read(&mut buf).await?;
        let (_, request) =
            parse_socks_request(&buf[..n]).map_err(|_| anyhow!("Invalid SOCKS5 request"))?;

        if request.cmd != 0x01 {
            return Err(anyhow!("Unsupported SOCKS5 command: {}", request.cmd));
        }

        let destination = match request.addr {
            SocksAddr::Ip(ip) => Endpoint::new_ip(ip, request.port),
            SocksAddr::Domain(domain) => Endpoint::new_domain(domain, request.port),
        };

        let mut metadata = ConnectionMetadata::new(destination);
        metadata.l4_protocol = L4Protocol::Tcp;
        metadata.identity.source = Some(Endpoint::from(peer_addr));
        metadata.environment.inbound_tag = Some(tag);

        // Success response
        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

        let context = Arc::new(Mutex::new(ConnectionContext::new(metadata)));
        engine.send_event(EngineEvent::NewStream { context, stream: Box::new(stream) }).await?;

        Ok(())
    }
}

#[async_trait]
impl InboundListener for SocksInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        tracing::info!("SOCKS5 inbound [{}] listening on {}", self.tag, self.listen_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let engine = self.engine.clone();
            let tag = self.tag.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(engine, tag, stream, addr).await {
                    tracing::error!("SOCKS5 connection error: {:?}", e);
                }
            });
        }
    }
}

// --- Independent Parsers (RFC 1928 compliant) ---

fn parse_socks_greeting(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (input, ver) = be_u8(input)?;
    if ver != 0x05 {
        return Err(nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Tag)));
    }
    let (input, nmethods) = be_u8(input)?;
    let (input, methods) = take(nmethods)(input)?;
    Ok((input, methods.to_vec()))
}

struct SocksRequest {
    cmd: u8,
    addr: SocksAddr,
    port: u16,
}

enum SocksAddr {
    Ip(IpAddr),
    Domain(String),
}

fn parse_socks_request(input: &[u8]) -> IResult<&[u8], SocksRequest> {
    let (input, ver) = be_u8(input)?;
    if ver != 0x05 {
        return Err(nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Tag)));
    }
    let (input, cmd) = be_u8(input)?;
    let (input, _rsv) = be_u8(input)?;
    let (input, atyp) = be_u8(input)?;

    let (input, addr) = match atyp {
        0x01 => {
            let (input, bytes) = take(4usize)(input)?;
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
            (input, SocksAddr::Ip(ip))
        }
        0x03 => {
            let (input, len) = be_u8(input)?;
            let (input, domain_bytes) = take(len)(input)?;
            let domain = String::from_utf8_lossy(domain_bytes).to_string();
            (input, SocksAddr::Domain(domain))
        }
        0x04 => {
            let (input, bytes) = take(16usize)(input)?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(arr));
            (input, SocksAddr::Ip(ip))
        }
        _ => {
            return Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Alt,
            )))
        }
    };

    let (input, port) = be_u16(input)?;

    Ok((input, SocksRequest { cmd, addr, port }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_greeting() {
        let data = [0x05, 0x01, 0x00];
        let (rem, methods) = parse_socks_greeting(&data).unwrap();
        assert_eq!(methods, vec![0x00]);
        assert!(rem.is_empty());
    }

    #[test]
    fn test_parse_request_v4() {
        let mut data = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        data.extend_from_slice(&80u16.to_be_bytes());
        let (_, req) = parse_socks_request(&data).unwrap();
        assert_eq!(req.cmd, 0x01);
        assert_eq!(req.port, 80);
        if let SocksAddr::Ip(IpAddr::V4(ip)) = req.addr {
            assert_eq!(ip.to_string(), "127.0.0.1");
        } else {
            panic!("Expected IPv4");
        }
    }
}
