//! Shadowsocks AEAD Inbound Implementation.
//!
//! Implementation Source:
//! - Specification: Shadowsocks AEAD (SIP007)
//! - Relevant Sections: TCP Inbound framing and address parsing.
//!
//! Independent implementation for ShadowMesh Core.

use crate::engine::context::ConnectionContext;
use crate::engine::metadata::{Addr, ConnectionMetadata, Endpoint, L4Protocol};
use crate::engine::{events::EngineEvent, EngineHandle};
use crate::protocol::shadowsocks::{ShadowsocksCipher, ShadowsocksMethod, ShadowsocksStream};
use crate::transport::traits::InboundListener;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};
use parking_lot::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};

pub struct ShadowsocksInbound {
    tag: String,
    listen_addr: String,
    method: ShadowsocksMethod,
    password: String,
    engine: EngineHandle,
}

impl ShadowsocksInbound {
    pub fn new(
        tag: String,
        listen_addr: String,
        method: String,
        password: String,
        engine: EngineHandle,
    ) -> Result<Self> {
        let method = method.parse()?;
        Ok(Self { tag, listen_addr, method, password, engine })
    }

    async fn handle_tcp(
        engine: EngineHandle,
        tag: String,
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
        method: ShadowsocksMethod,
        password: String,
    ) -> Result<()> {
        let mut ss_stream = ShadowsocksStream::new(stream, method, &password);

        // 1. Read Target Address
        // The address is at the beginning of the decrypted stream.
        // We use a small buffer to parse it.
        let mut addr_buf = [0u8; 1];
        ss_stream.read_exact(&mut addr_buf).await?;

        let atyp = addr_buf[0];
        let destination = match atyp {
            1 => {
                // IPv4
                let mut ip_buf = [0u8; 4];
                ss_stream.read_exact(&mut ip_buf).await?;
                let mut port_buf = [0u8; 2];
                ss_stream.read_exact(&mut port_buf).await?;
                let ip = IpAddr::V4(ip_buf.into());
                let port = u16::from_be_bytes(port_buf);
                Endpoint::new_ip(ip, port)
            }
            3 => {
                // Domain
                let mut len_buf = [0u8; 1];
                ss_stream.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; len];
                ss_stream.read_exact(&mut domain_buf).await?;
                let mut port_buf = [0u8; 2];
                ss_stream.read_exact(&mut port_buf).await?;
                let domain = String::from_utf8_lossy(&domain_buf).to_string();
                let port = u16::from_be_bytes(port_buf);
                Endpoint::new_domain(domain, port)
            }
            4 => {
                // IPv6
                let mut ip_buf = [0u8; 16];
                ss_stream.read_exact(&mut ip_buf).await?;
                let mut port_buf = [0u8; 2];
                ss_stream.read_exact(&mut port_buf).await?;
                let ip = IpAddr::V6(ip_buf.into());
                let port = u16::from_be_bytes(port_buf);
                Endpoint::new_ip(ip, port)
            }
            _ => return Err(anyhow!("Unsupported address type: {}", atyp)),
        };

        let mut metadata = ConnectionMetadata::new(destination);
        metadata.l4_protocol = L4Protocol::Tcp;
        metadata.identity.source = Some(Endpoint::from(peer_addr));
        metadata.environment.inbound_tag = Some(tag);

        let context = Arc::new(Mutex::new(ConnectionContext::new(metadata)));
        engine.send_event(EngineEvent::NewStream { context, stream: Box::new(ss_stream) }).await?;

        Ok(())
    }

    async fn listen_udp(&self) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(&self.listen_addr).await?);
        tracing::info!(
            "Shadowsocks inbound [{}] listening for UDP on {}",
            self.tag,
            self.listen_addr
        );

        let mut buf = [0u8; 65535];
        loop {
            let (n, peer_addr) = socket.recv_from(&mut buf).await?;
            let packet = &buf[..n];

            // Decrypt UDP packet
            match ShadowsocksCipher::decrypt_udp(self.method, &self.password, packet) {
                Ok(decrypted) => {
                    // Parse address and payload
                    if let Ok((payload, destination)) = parse_ss_address(&decrypted) {
                        let mut metadata = ConnectionMetadata::new(destination);
                        metadata.l4_protocol = L4Protocol::Udp;
                        metadata.identity.source = Some(Endpoint::from(peer_addr));
                        metadata.environment.inbound_tag = Some(self.tag.clone());

                        let context = ConnectionContext::new(metadata);
                        // RFC-012 G2: request the upstream reply so it can be
                        // encrypted straight back to the client (DNS over SS
                        // becomes fully functional).
                        let (reply_tx, reply_rx) =
                            tokio::sync::oneshot::channel::<Option<Vec<u8>>>();
                        if let Err(e) = self
                            .engine
                            .send_event(EngineEvent::UdpPacket {
                                context: Arc::new(Mutex::new(context)),
                                payload: payload.to_vec(),
                                source: peer_addr,
                                reply: Some(reply_tx),
                            })
                            .await
                        {
                            tracing::error!("Failed to dispatch SS UDP packet: {:?}", e);
                            continue;
                        }

                        // Bounded wait: a slow upstream must not stall the
                        // listener loop; None/timeout both mean no reply.
                        match tokio::time::timeout(std::time::Duration::from_millis(2500), reply_rx)
                            .await
                        {
                            Ok(Ok(Some(reply))) if !reply.is_empty() => {
                                // SIP007 reply framing: [address][payload],
                                // encrypted exactly like the request.
                                let mut wrapped = Vec::with_capacity(
                                    decrypted.len() - payload.len() + reply.len(),
                                );
                                wrapped.extend_from_slice(
                                    &decrypted[..decrypted.len() - payload.len()],
                                );
                                wrapped.extend_from_slice(&reply);
                                if let Ok(encrypted_reply) = ShadowsocksCipher::encrypt_udp(
                                    self.method,
                                    &self.password,
                                    &wrapped,
                                ) {
                                    if let Err(e) =
                                        socket.send_to(&encrypted_reply, peer_addr).await
                                    {
                                        tracing::warn!("SS UDP reply send failed: {:?}", e);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("SS UDP decryption failed from {}: {:?}", peer_addr, e);
                }
            }
        }
    }
}

#[async_trait]
impl InboundListener for ShadowsocksInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(&self) -> Result<()> {
        let tcp_listener = TcpListener::bind(&self.listen_addr).await?;
        tracing::info!(
            "Shadowsocks inbound [{}] listening for TCP on {}",
            self.tag,
            self.listen_addr
        );

        let engine = self.engine.clone();
        let tag = self.tag.clone();
        let method = self.method;
        let password = self.password.clone();

        // Spawn UDP listener
        let ss_inbound = Arc::new(self.clone_config());
        tokio::spawn(async move {
            if let Err(e) = ss_inbound.listen_udp().await {
                tracing::error!("SS UDP listener error: {:?}", e);
            }
        });

        loop {
            let (stream, addr) = tcp_listener.accept().await?;
            let engine = engine.clone();
            let tag = tag.clone();
            let password = password.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_tcp(engine, tag, stream, addr, method, password).await
                {
                    tracing::error!("SS TCP connection error: {:?}", e);
                }
            });
        }
    }
}

impl ShadowsocksInbound {
    fn clone_config(&self) -> Self {
        Self {
            tag: self.tag.clone(),
            listen_addr: self.listen_addr.clone(),
            method: self.method,
            password: self.password.clone(),
            engine: self.engine.clone(),
        }
    }
}

pub fn parse_ss_address(input: &[u8]) -> IResult<&[u8], Endpoint> {
    let (input, atyp) = be_u8(input)?;
    let (input, addr) = match atyp {
        1 => {
            let (input, bytes) = take(4usize)(input)?;
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
            (input, Addr::Ip(ip))
        }
        3 => {
            let (input, len) = be_u8(input)?;
            let (input, domain_bytes) = take(len)(input)?;
            let domain = String::from_utf8_lossy(domain_bytes).to_string();
            (input, Addr::Domain(domain))
        }
        4 => {
            let (input, bytes) = take(16usize)(input)?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(arr));
            (input, Addr::Ip(ip))
        }
        _ => {
            return Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Alt,
            )))
        }
    };

    let (input, port) = be_u16(input)?;
    Ok((input, Endpoint { addr, port }))
}
