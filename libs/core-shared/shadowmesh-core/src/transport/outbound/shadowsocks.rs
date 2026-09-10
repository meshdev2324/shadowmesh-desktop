use crate::engine::context::SharedContext;
use crate::engine::metadata::{Addr, Endpoint};
use crate::protocol::shadowsocks::{ShadowsocksCipher, ShadowsocksMethod, ShadowsocksStream};
use crate::transport::traits::{AsyncIoStream, OutboundDialer};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use socket2::{Domain, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, trace};

#[derive(Clone)]
pub struct ShadowsocksOutbound {
    tag: String,
    server: String,
    port: u16,
    method: ShadowsocksMethod,
    password: String,
}

impl ShadowsocksOutbound {
    pub fn new(
        tag: String,
        server: String,
        port: u16,
        method: String,
        password: String,
    ) -> Result<Self> {
        let method = method.parse()?;
        Ok(Self { tag, server, port, method, password })
    }
}

#[async_trait]
impl OutboundDialer for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, context: SharedContext) -> Result<Box<dyn AsyncIoStream>> {
        let destination = {
            let ctx = context.lock();
            ctx.metadata.identity.destination.clone()
        };

        debug!(
            "Shadowsocks outbound [{}] connecting to {} via {}:{}",
            self.tag, destination, self.server, self.port
        );

        let server_addr = format!("{}:{}", self.server, self.port);
        let addr: std::net::SocketAddr =
            server_addr.parse().map_err(|_| anyhow!("Invalid server address"))?;

        let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)
            .map_err(|e| anyhow!("Socket creation failed: {}", e))?;

        if !crate::protect_socket(socket.as_raw_fd()) {
            tracing::error!("⚠️ FAILED TO PROTECT SOCKET FD: {}", socket.as_raw_fd());
        }

        socket.set_nonblocking(true).map_err(|e| anyhow!("Failed to set non-blocking: {}", e))?;

        match socket.connect(&addr.into()) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(anyhow!("TCP connect failed: {}", e)),
        }

        let std_stream: std::net::TcpStream = socket.into();
        let outbound_stream =
            TcpStream::from_std(std_stream).map_err(|e| anyhow!("TCP conversion failed: {}", e))?;

        outbound_stream.writable().await.map_err(|e| anyhow!("TCP connect timeout: {}", e))?;

        let mut encrypted_stream =
            ShadowsocksStream::new(outbound_stream, self.method, &self.password);

        trace!("Sending shadowsocks target address {}", destination);
        let addr_buf = format_ss_address(&destination)?;
        encrypted_stream.write_all(&addr_buf).await?;

        Ok(Box::new(encrypted_stream))
    }

    async fn send_packet(
        &self,
        context: SharedContext,
        packet: &[u8],
        _source: SocketAddr,
    ) -> Result<Vec<u8>> {
        let destination = {
            let ctx = context.lock();
            ctx.metadata.identity.destination.clone()
        };

        trace!(
            "Shadowsocks UDP outbound [{}] sending to {} via {}:{}",
            self.tag,
            destination,
            self.server,
            self.port
        );

        // 1. Format Shadowsocks target address
        let mut wrapped = format_ss_address(&destination)?;
        // 2. Append original payload
        wrapped.extend_from_slice(packet);

        // 3. Encrypt for UDP (SIP007)
        let encrypted = ShadowsocksCipher::encrypt_udp(self.method, &self.password, &wrapped)?;

        // 4. Send to Shadowsocks server UDP port
        let server_addr = format!("{}:{}", self.server, self.port);
        let addr: SocketAddr = server_addr.parse()?;
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, None)?;

        if !crate::protect_socket(socket.as_raw_fd()) {
            tracing::error!("⚠️ FAILED TO PROTECT UDP SOCKET FD: {}", socket.as_raw_fd());
        }

        // tokio::net::UdpSocket::from_std contract: the fd must be
        // non-blocking, or registration is rejected at runtime.
        socket.set_nonblocking(true)?;
        let std_socket: std::net::UdpSocket = socket.into();
        let socket = UdpSocket::from_std(std_socket)?;

        socket.send_to(&encrypted, server_addr).await?;

        // RFC-012 G2: bounded reply wait; decrypt the SIP007 UDP response.
        let mut rbuf = [0u8; 65535];
        match tokio::time::timeout(
            std::time::Duration::from_millis(2000),
            socket.recv_from(&mut rbuf),
        )
        .await
        {
            Ok(Ok((n, _))) => {
                match ShadowsocksCipher::decrypt_udp(self.method, &self.password, &rbuf[..n]) {
                    // The reply carries [address][payload]; strip the address.
                    Ok(plain) => {
                        match crate::transport::inbound::shadowsocks::parse_ss_address(&plain) {
                            Ok((payload, _ep)) => Ok(payload.to_vec()),
                            Err(_) => Ok(plain),
                        }
                    }
                    Err(_) => Ok(Vec::new()),
                }
            }
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Ok(Vec::new()),
        }
    }
}

pub(crate) fn format_ss_address(endpoint: &Endpoint) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    match &endpoint.addr {
        Addr::Ip(IpAddr::V4(ip)) => {
            buf.push(1);
            buf.extend_from_slice(&ip.octets());
        }
        Addr::Ip(IpAddr::V6(ip)) => {
            buf.push(4);
            buf.extend_from_slice(&ip.octets());
        }
        Addr::Domain(domain) => {
            buf.push(3);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
        }
    }
    buf.extend_from_slice(&endpoint.port.to_be_bytes());
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_ss_address() {
        // IPv4
        let ep = Endpoint::new_ip("1.2.3.4".parse().unwrap(), 443);
        let buf = format_ss_address(&ep).unwrap();
        assert_eq!(buf, vec![1, 1, 2, 3, 4, 1, 187]);

        // Domain
        let ep = Endpoint::new_domain("example.com".to_string(), 80);
        let buf = format_ss_address(&ep).unwrap();
        let mut expected = vec![3, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(buf, expected);

        // IPv6
        let ep = Endpoint::new_ip("::1".parse().unwrap(), 1080);
        let buf = format_ss_address(&ep).unwrap();
        let mut expected = vec![4];
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        expected.extend_from_slice(&1080u16.to_be_bytes());
        assert_eq!(buf, expected);
    }
}
