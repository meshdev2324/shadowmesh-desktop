use crate::engine::context::SharedContext;
use crate::engine::metadata::{Addr, L4Protocol};
use crate::transport::traits::{AsyncIoStream, OutboundDialer};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha224};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Client-side TLS parameters for the Trojan session (RFC-015 §4.4).
/// Trojan-GFW requires TLS on the wire; `insecure` accepts self-signed
/// edge certificates (explicit operator choice, never a default).
#[derive(Clone, Debug)]
pub struct TlsClientParams {
    pub sni: String,
    pub insecure: bool,
}

/// Persistent UDP-over-TCP tunnel state for TrojanOutbound.
type UdpTunnelSlot = Arc<tokio::sync::Mutex<Option<Box<dyn AsyncIoStream>>>>;

/// Trojan outbound. Wire format per public Trojan protocol documentation:
/// `[56-byte hex SHA224 password][CRLF][CMD][ATYP][ADDR][PORT][CRLF]`
/// CMD 1 = TCP CONNECT, CMD 3 = UDP ASSOCIATE; UDP packets then flow as
/// `[ATYP][ADDR][PORT][u16 LEN][payload]` frames on the same stream.
pub struct TrojanOutbound {
    tag: String,
    server: String,
    port: u16,
    password_hash: String,
    /// Optional client TLS (Trojan-GFW: TLS is mandatory on the wire; the
    /// plaintext path exists only for loopback tests).
    tls: Option<TlsClientParams>,
    /// Lazily-established UDP ASSOCIATE tunnel (CMD 3).
    udp_tunnel: UdpTunnelSlot,
}

impl TrojanOutbound {
    pub fn new(tag: String, server: String, port: u16, password: &str) -> Self {
        Self::with_tls(tag, server, port, password, None)
    }

    pub fn with_tls(
        tag: String,
        server: String,
        port: u16,
        password: &str,
        tls: Option<TlsClientParams>,
    ) -> Self {
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let hash = hex::encode(hasher.finalize());
        Self {
            tag,
            server,
            port,
            password_hash: hash,
            tls,
            udp_tunnel: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    fn tls_connector(params: &TlsClientParams) -> Result<tokio_rustls::TlsConnector> {
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?;
        let config = if params.insecure {
            warn!(
                "Trojan TLS: certificate verification DISABLED (insecure mode — self-signed edge only)"
            );
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerify))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs()
                .map_err(|e| anyhow!("native cert load failed: {e}"))?
            {
                let _ = roots.add(cert);
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
    }

    /// Builds the fixed Trojan request header for the given command and
    /// destination. Pure function: same inputs always produce the same wire
    /// bytes (pinned by tests).
    fn build_header(
        hex_password: &str,
        cmd: u8,
        destination: &crate::engine::metadata::Endpoint,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(64);
        header.extend_from_slice(hex_password.as_bytes());
        header.extend_from_slice(b"\r\n");
        header.push(cmd);
        Self::push_address(&mut header, &destination.addr);
        header.extend_from_slice(&destination.port.to_be_bytes());
        header.extend_from_slice(b"\r\n");
        header
    }

    /// SOCKS5-style address block shared by the handshake header and the
    /// per-packet UDP frames: `[ATYP][addr bytes]` (no port).
    fn push_address(out: &mut Vec<u8>, addr: &Addr) {
        match addr {
            Addr::Ip(IpAddr::V4(ip)) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
            }
            Addr::Ip(IpAddr::V6(ip)) => {
                out.push(0x04);
                out.extend_from_slice(&ip.octets());
            }
            Addr::Domain(domain) => {
                out.push(0x03);
                out.push(domain.len() as u8);
                out.extend_from_slice(domain.as_bytes());
            }
        }
    }
}

#[async_trait]
impl OutboundDialer for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, context: SharedContext) -> Result<Box<dyn AsyncIoStream>> {
        let (destination, l4_protocol) = {
            let ctx = context.lock();
            (ctx.metadata.identity.destination.clone(), ctx.metadata.l4_protocol)
        };

        debug!(
            "Trojan outbound [{}] connecting to {} via {}:{}",
            self.tag, destination, self.server, self.port
        );

        let tcp = TcpStream::connect(format!("{}:{}", self.server, self.port)).await?;
        // RFC-015 §4.4: TLS wraps the whole session when configured.
        let mut stream: Box<dyn AsyncIoStream> = match &self.tls {
            Some(params) => {
                let connector = Self::tls_connector(params)?;
                let server_name = ServerName::try_from(params.sni.clone())
                    .map_err(|e| anyhow!("invalid TLS SNI '{}': {e}", params.sni))?;
                Box::new(
                    connector
                        .connect(server_name, tcp)
                        .await
                        .map_err(|e| anyhow!("Trojan TLS handshake failed: {e}"))?,
                )
            }
            None => Box::new(tcp),
        };

        // CMD per context: 1 = CONNECT (TCP), 3 = UDP ASSOCIATE.
        let cmd: u8 = match l4_protocol {
            L4Protocol::Udp => 0x03,
            _ => 0x01,
        };

        let header = Self::build_header(&self.password_hash, cmd, &destination);
        stream.write_all(&header).await?;
        stream.flush().await?;

        Ok(stream)
    }

    async fn send_packet(
        &self,
        context: SharedContext,
        payload: &[u8],
        _source: SocketAddr,
    ) -> Result<Vec<u8>> {
        // Trojan UDP: one UDP ASSOCIATE session per outbound; each packet is
        // framed as [ATYP][ADDR][PORT][u16 LEN][payload] on that stream.
        {
            let mut ctx = context.lock();
            ctx.metadata.l4_protocol = L4Protocol::Udp;
        }

        let mut tunnel_slot = self.udp_tunnel.lock().await;
        if tunnel_slot.is_none() {
            *tunnel_slot = Some(self.dial_stream(context.clone()).await?);
        }

        let stream =
            tunnel_slot.as_mut().ok_or_else(|| anyhow!("Trojan UDP tunnel unavailable"))?;

        let destination = {
            let ctx = context.lock();
            ctx.metadata.identity.destination.clone()
        };

        let mut frame = Vec::with_capacity(4 + 255 + 2 + payload.len());
        Self::push_address(&mut frame, &destination.addr);
        frame.extend_from_slice(&destination.port.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        stream.write_all(&frame).await?;
        stream.flush().await?;
        // Replies flow back on the UDP ASSOCIATE stream; surfaced via the
        // session reply plumbing (G2 phase 2), not from this call.
        Ok(Vec::new())
    }
}

/// Certificate verifier that accepts everything — ONLY for `insecure: true`
/// (self-signed edge certificates). The explicit type name keeps the risky
/// mode greppable and impossible to enable silently.
#[derive(Debug)]
struct SkipServerVerify;

impl ServerCertVerifier for SkipServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::metadata::Endpoint;

    #[test]
    fn test_trojan_header_shape_tcp() {
        // The header is fully determined by (password_hash, cmd, endpoint).
        const HASH: &str = "00000000000000000000000000000000000000000000000000000000";
        let ep = Endpoint::new_domain("example.com".into(), 443);
        let header = TrojanOutbound::build_header(HASH, 0x01, &ep);
        // [56 hex][CRLF][cmd][atyp=3][len][domain][port BE][CRLF]
        assert_eq!(header.len(), 56 + 2 + 1 + 1 + 1 + 11 + 2 + 2);
        assert_eq!(&header[..56], HASH.as_bytes());
        assert_eq!(&header[56..58], b"\r\n");
        assert_eq!(header[58], 0x01); // CMD CONNECT
        assert_eq!(header[59], 0x03); // ATYP domain
        assert_eq!(header[60], 11); // domain length
        assert_eq!(&header[61..72], b"example.com");
        assert_eq!(&header[72..74], &443u16.to_be_bytes());
        assert_eq!(&header[74..76], b"\r\n");
    }

    #[test]
    fn test_trojan_header_shape_udp_ipv4() {
        const HASH: &str = "00000000000000000000000000000000000000000000000000000000";
        let ep = Endpoint::new_ip("10.0.0.1".parse().unwrap(), 5353);
        let header = TrojanOutbound::build_header(HASH, 0x03, &ep);
        assert_eq!(header[58], 0x03); // CMD UDP ASSOCIATE
        assert_eq!(header[59], 0x01); // ATYP IPv4
        assert_eq!(&header[60..64], &[10, 0, 0, 1]);
        assert_eq!(&header[64..66], &5353u16.to_be_bytes());
    }
}
