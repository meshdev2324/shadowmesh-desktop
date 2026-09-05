use crate::engine::context::ConnectionContext;
use crate::engine::metadata::{ConnectionMetadata, Endpoint, HandshakeState, L4Protocol};
use crate::engine::{events::EngineEvent, EngineHandle};
use crate::transport::traits::InboundListener;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nom::{
    bytes::complete::{tag as nom_tag, take},
    number::complete::{be_u16, be_u8},
    IResult,
};
use parking_lot::Mutex;
use sha2::{Digest, Sha224};
/// Implementation Source:
/// - RFC / specification: Trojan Protocol (Public Documentation)
/// - Relevant sections: Handshake (Header Parsing), Command handling.
/// - Security considerations: Constant-time authentication comparison, robust parsing of variable length addresses.
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

/// Trojan Inbound handler with decoupled parsing logic.
pub struct TrojanInbound {
    tag: String,
    listen_addr: String,
    password_hash: String,
    engine: EngineHandle,
    /// Optional server-side TLS termination (Trojan-GFW requires TLS on the
    /// wire; when absent, TLS must be terminated by an external front).
    tls: Option<tokio_rustls::TlsAcceptor>,
}

impl TrojanInbound {
    pub fn new(tag: String, listen_addr: String, password: &str, engine: EngineHandle) -> Self {
        Self::with_tls(tag, listen_addr, password, engine, None)
    }

    pub fn with_tls(
        tag: String,
        listen_addr: String,
        password: &str,
        engine: EngineHandle,
        tls: Option<tokio_rustls::TlsAcceptor>,
    ) -> Self {
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let hash = hex::encode(hasher.finalize());
        Self { tag, listen_addr, password_hash: hash, engine, tls }
    }

    async fn handle_connection<S>(&self, mut stream: S, peer: Option<SocketAddr>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await?;

        let (remaining, request) =
            parse_trojan_handshake(&buf[..n]).map_err(|_| anyhow!("Invalid Trojan handshake"))?;

        // Constant-time authentication: compare fixed-length SHA-224 hex
        // digests without an early-exit byte comparison (both sides are
        // always 56 bytes, so lengths match by construction).
        let auth_ok = {
            use subtle::ConstantTimeEq;
            let expected: [u8; 56] = self.password_hash.as_bytes()[..56]
                .try_into()
                .map_err(|_| anyhow!("Trojan password digest length invalid"))?;
            let presented: [u8; 56] = request.password_hash.as_bytes()[..56]
                .try_into()
                .map_err(|_| anyhow!("Trojan handshake digest length invalid"))?;
            bool::from(expected.ct_eq(&presented))
        };
        if !auth_ok {
            return Err(anyhow!("Trojan authentication failed"));
        }

        let mut metadata = ConnectionMetadata::new(request.destination);
        metadata.l4_protocol = if request.cmd == 1 { L4Protocol::Tcp } else { L4Protocol::Udp };
        metadata.identity.source = peer.map(Endpoint::from);
        metadata.environment.inbound_tag = Some(self.tag.clone());
        metadata.handshake = HandshakeState::Established;

        let context = Arc::new(Mutex::new(ConnectionContext::new(metadata)));

        if request.cmd == 1 {
            // v6.9.4: Re-inject any remaining data read after the Trojan header
            let final_stream: Box<dyn crate::transport::traits::AsyncIoStream> =
                if remaining.is_empty() {
                    Box::new(stream)
                } else {
                    Box::new(crate::transport::inbound::http::PrefixedStream::new(
                        remaining.to_vec(),
                        stream,
                    ))
                };

            self.engine
                .send_event(EngineEvent::NewStream { context, stream: final_stream })
                .await?;
        } else {
            return Err(anyhow!("Trojan UDP command not supported yet in this implementation"));
        }

        Ok(())
    }
}

#[async_trait]
impl InboundListener for TrojanInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!("Trojan inbound {} listening on {}", self.tag, self.listen_addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let peer = stream.peer_addr().ok();
            let tag = self.tag.clone();
            let password_hash = self.password_hash.clone();
            let engine = self.engine.clone();
            let tls = self.tls.clone();

            tokio::spawn(async move {
                let handler = TrojanInbound {
                    tag,
                    listen_addr: String::new(),
                    password_hash,
                    engine,
                    tls: tls.clone(),
                };
                // TLS termination happens here so the protocol handler below
                // always sees the plaintext Trojan stream.
                let result = match (tls, stream) {
                    (Some(acceptor), raw) => match acceptor.accept(raw).await {
                        Ok(tls_stream) => handler.handle_connection(tls_stream, peer).await,
                        Err(e) => {
                            // A failed TLS handshake is expected noise under
                            // active probing — never fatal to the listener.
                            warn!("Trojan TLS handshake rejected: {e}");
                            Ok(())
                        }
                    },
                    (None, plaintext) => handler.handle_connection(plaintext, peer).await,
                };
                if let Err(e) = result {
                    error!("Trojan connection handling failed: {:?}", e);
                }
            });
        }
    }
}

// --- Independent Trojan Handshake Parser ---

pub struct TrojanRequest {
    pub password_hash: String,
    pub cmd: u8,
    pub destination: Endpoint,
}

pub fn parse_trojan_handshake(input: &[u8]) -> IResult<&[u8], TrojanRequest> {
    let (input, hash_bytes) = take(56usize)(input)?;
    let password_hash = String::from_utf8_lossy(hash_bytes).to_string();

    let (input, _) = nom_tag("\r\n")(input)?;
    let (input, cmd) = be_u8(input)?;
    let (input, atyp) = be_u8(input)?;

    let (input, addr) = match atyp {
        0x01 => {
            let (input, bytes) = take(4usize)(input)?;
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            ));
            (input, crate::engine::metadata::Addr::Ip(ip))
        }
        0x03 => {
            let (input, len) = be_u8(input)?;
            let (input, domain_bytes) = take(len)(input)?;
            let domain = String::from_utf8_lossy(domain_bytes).to_string();
            (input, crate::engine::metadata::Addr::Domain(domain))
        }
        0x04 => {
            let (input, bytes) = take(16usize)(input)?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(arr));
            (input, crate::engine::metadata::Addr::Ip(ip))
        }
        _ => {
            return Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Alt,
            )))
        }
    };

    let (input, port) = be_u16(input)?;
    let (input, _) = nom_tag("\r\n")(input)?;

    Ok((input, TrojanRequest { password_hash, cmd, destination: Endpoint { addr, port } }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_trojan_header() {
        let mut data = Vec::new();
        data.extend_from_slice(b"0123456789abcdef0123456789abcdef0123456789abcdef01234567"); // 56 bytes
        data.extend_from_slice(b"\r\n");
        data.push(0x01); // CMD Connect
        data.push(0x01); // ATYP IPv4
        data.extend_from_slice(&[127, 0, 0, 1]); // Addr
        data.extend_from_slice(&80u16.to_be_bytes()); // Port
        data.extend_from_slice(b"\r\n");
        data.extend_from_slice(b"GET / HTTP/1.1\r\n"); // Payload

        let (rem, req) = parse_trojan_handshake(&data).unwrap();
        assert_eq!(req.cmd, 1);
        assert_eq!(req.destination.port, 80);
        assert_eq!(rem, b"GET / HTTP/1.1\r\n");
    }
}
