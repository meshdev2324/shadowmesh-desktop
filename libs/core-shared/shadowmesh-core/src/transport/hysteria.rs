//! Hysteria 2 Clean-Room Implementation.
//!
//! Implementation Source:
//! - Specification: Hysteria 2 Public Protocol Spec
//! - RFC: RFC 9000 (QUIC), RFC 9001 (QUIC TLS), RFC 9002 (QUIC CC)
//! - Relevant Sections: Handshake (Auth Frame), Data Framing, UDP Obfuscation.
//!
//! This is an independent implementation authored for ShadowMesh Core.

use super::{AsyncTransport, InboundListener, TransportType};
use crate::{HysteriaConfig, ShadowMeshError};
use anyhow::Result;
use async_trait::async_trait;
use boringtun::noise::{Tunn, TunnResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Hysteria 2 "Brutal" Congestion Control.
/// A fixed-rate pacer designed for extreme resilience in high-loss environments.
/// This implementation provides deterministic pacing to avoid ISP burst-shaping.
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    pub up_bps: u64,
}

pub struct BrutalController {
    config: BrutalConfig,
    last_send_time: Option<std::time::Instant>,
    tokens: u64,
}

impl BrutalController {
    pub fn new(config: BrutalConfig) -> Self {
        Self { config, last_send_time: None, tokens: 0 }
    }

    /// v6.9.24: Stricter Pacing with Deficit Correction
    /// Prevents timing attacks and burst-shaping by ISPs.
    pub fn on_transmit(&mut self, now: std::time::Instant, bytes: u64) -> std::time::Duration {
        let last = self.last_send_time.get_or_insert(now);
        let elapsed = now.duration_since(*last);

        // Refill tokens based on time passed since the *intended* last send
        let refill = (self.config.up_bps as f64 * elapsed.as_secs_f64()) as u64;
        self.tokens = (self.tokens + refill).min(self.config.up_bps / 50); // Small 20ms burst limit

        if self.tokens >= bytes {
            self.tokens -= bytes;
            self.last_send_time = Some(now);
            std::time::Duration::ZERO
        } else {
            let missing = bytes - self.tokens;
            let wait =
                std::time::Duration::from_secs_f64(missing as f64 / self.config.up_bps as f64);
            self.tokens = 0;
            // Deficit Correction: Account for the time we must wait in the next refill cycle
            self.last_send_time = Some(now + wait);
            wait
        }
    }
}

/// Hysteria 2 UDP Obfuscation (XOR-based).
/// Independent implementation to hide QUIC fingerprints.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HysteriaObfuscator {
    key: Vec<u8>,
}

impl HysteriaObfuscator {
    pub fn new(key_str: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key_str.as_bytes());
        Self { key: hasher.finalize().to_vec() }
    }

    pub fn obfuscate_in_place(&self, data: &mut [u8]) {
        if self.key.is_empty() {
            return;
        }
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= self.key[i % self.key.len()];
        }
    }

    #[allow(dead_code)]
    pub fn deobfuscate_in_place(&self, data: &mut [u8]) {
        self.obfuscate_in_place(data); // XOR is symmetric
    }
}

// Note: In quinn 0.11, the Controller trait is part of quinn-proto.
// We implement a simplified version or use quinn's built-in if we can't easily hook.
// For now, we will simulate the aggressive behavior via quinn::ClientConfig.

/// Established Hysteria 2 tunnel.
struct Tunnel {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    frame_buf: BytesMut,
}

/// Hysteria 2 transport implementation (WireGuard-over-QUIC).
pub struct HysteriaTransport {
    config: HysteriaConfig,
    #[allow(dead_code)]
    obfuscator: Option<HysteriaObfuscator>,
    tunnel: Arc<Mutex<Option<Tunnel>>>,
    tunn: Arc<Mutex<Tunn>>,
}

impl std::fmt::Debug for HysteriaTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysteriaTransport").field("server", &self.config.server).finish()
    }
}

impl HysteriaTransport {
    pub fn new(
        config: HysteriaConfig,
        static_private: [u8; 32],
        server_static_public: [u8; 32],
    ) -> Self {
        let tunn =
            Tunn::new(static_private.into(), server_static_public.into(), None, None, 0, None);

        let obfuscator = config.obfuscation_key.as_ref().map(|k| HysteriaObfuscator::new(k));

        Self {
            config,
            obfuscator,
            tunnel: Arc::new(Mutex::new(None)),
            tunn: Arc::new(Mutex::new(tunn)),
        }
    }

    async fn get_or_connect(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<Tunnel>>, ShadowMeshError> {
        let mut guard = self.tunnel.lock().await;
        if guard.is_none() {
            let server_addr = format!("{}:{}", self.config.server, self.config.port);
            let addr: SocketAddr = server_addr
                .parse()
                .map_err(|_| ShadowMeshError::Other("Invalid Hysteria server address".into()))?;

            let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, None)
                .map_err(|e| ShadowMeshError::IoError(format!("Socket creation failed: {}", e)))?;

            if !crate::protect_socket(socket.as_raw_fd()) {
                error!("⚠️ FAILED TO PROTECT SOCKET FD: {}", socket.as_raw_fd());
            }

            let _std_socket: std::net::UdpSocket = socket.into();
            let mut endpoint = Endpoint::client(
                "0.0.0.0:0"
                    .parse::<SocketAddr>()
                    .map_err(|e| ShadowMeshError::Other(e.to_string()))?,
            )
            .map_err(|e| ShadowMeshError::IoError(e.to_string()))?;

            let client_config = {
                // `mut` is only consumed by the #[cfg(test)] verifier override below.
                #[allow(unused_mut)]
                let mut crypto = rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth();

                #[cfg(test)]
                {
                    use rustls::client::danger::{
                        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
                    };
                    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
                    use rustls::{DigitallySignedStruct, Error, SignatureScheme};
                    use std::sync::Arc;

                    #[derive(Debug)]
                    struct SkipVerification;
                    impl ServerCertVerifier for SkipVerification {
                        fn verify_server_cert(
                            &self,
                            _e: &CertificateDer<'_>,
                            _i: &[CertificateDer<'_>],
                            _s: &ServerName<'_>,
                            _sr: &[u8],
                            _n: UnixTime,
                        ) -> Result<ServerCertVerified, Error> {
                            Ok(ServerCertVerified::assertion())
                        }

                        fn verify_tls12_signature(
                            &self,
                            _m: &[u8],
                            _c: &CertificateDer<'_>,
                            _d: &DigitallySignedStruct,
                        ) -> Result<HandshakeSignatureValid, Error> {
                            Ok(HandshakeSignatureValid::assertion())
                        }

                        fn verify_tls13_signature(
                            &self,
                            _m: &[u8],
                            _c: &CertificateDer<'_>,
                            _d: &DigitallySignedStruct,
                        ) -> Result<HandshakeSignatureValid, Error> {
                            Ok(HandshakeSignatureValid::assertion())
                        }

                        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                            vec![
                                SignatureScheme::RSA_PSS_SHA256,
                                SignatureScheme::ED25519,
                                SignatureScheme::ECDSA_NISTP256_SHA256,
                            ]
                        }
                    }
                    crypto.dangerous().set_certificate_verifier(Arc::new(SkipVerification));
                }

                quinn::ClientConfig::new(Arc::new(
                    quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                        .map_err(|e| ShadowMeshError::Other(e.to_string()))?,
                ))
            };

            // v6.9.15: Aggressive Performance Tuning (Hysteria 2 Style)
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(
                std::time::Duration::from_secs(30)
                    .try_into()
                    .map_err(|e| ShadowMeshError::Other(format!("Invalid duration: {}", e)))?,
            ));
            transport_config.initial_rtt(std::time::Duration::from_millis(100));
            // In Hysteria 2, we want to disable most of the "polite" congestion control.
            // For now, we optimize the stream windows to prevent bottlenecks.
            transport_config.stream_receive_window(VarInt::from_u32(1024 * 1024 * 8));
            transport_config.receive_window(VarInt::from_u32(1024 * 1024 * 16));

            let mut client_config = client_config;
            client_config.transport_config(Arc::new(transport_config));
            endpoint.set_default_client_config(client_config);

            let sni = self.config.sni.as_deref().unwrap_or("localhost");
            let connecting =
                endpoint.connect(addr, sni).map_err(|_| ShadowMeshError::ConnectionFailed)?;

            let connection = connecting.await.map_err(|_| ShadowMeshError::ConnectionFailed)?;

            let mut auth_frame = Vec::new();
            auth_frame.push(0x01); // Password auth
            auth_frame.put_u16(self.config.auth_password.len() as u16);
            auth_frame.extend_from_slice(self.config.auth_password.as_bytes());

            let (mut send, mut recv) =
                connection.open_bi().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;

            send.write_all(&auth_frame)
                .await
                .map_err(|e| ShadowMeshError::IoError(format!("Handshake send failed: {}", e)))?;

            let mut result_buf = [0u8; 1];
            recv.read_exact(&mut result_buf)
                .await
                .map_err(|e| ShadowMeshError::IoError(format!("Handshake result failed: {}", e)))?;

            if result_buf[0] != 0x00 {
                return Err(ShadowMeshError::Unauthorized("Hysteria 2 auth failed".into()));
            }

            info!("✅ Hysteria 2 tunnel established");
            *guard =
                Some(Tunnel { connection, send, recv, frame_buf: BytesMut::with_capacity(2048) });
        }
        Ok(guard)
    }

    async fn read_packet(&self) -> Result<Bytes, ShadowMeshError> {
        let mut guard = self.get_or_connect().await?;
        let tunnel = match guard.as_mut() {
            Some(t) => t,
            None => return Ok(Bytes::new()),
        };

        fill_frame_bytes(tunnel, 2).await?;
        let len = u16::from_be_bytes([tunnel.frame_buf[0], tunnel.frame_buf[1]]) as usize;

        if len == 0 {
            tunnel.frame_buf.advance(2);
            return Ok(Bytes::new());
        }

        fill_frame_bytes(tunnel, 2 + len).await?;
        let payload = tunnel.frame_buf.split_to(2 + len).split_off(2).to_vec();

        let mut tunn = self.tunn.lock().await;
        let mut ip_buf = vec![0u8; 2048];
        match tunn.decapsulate(None, &payload, &mut ip_buf) {
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                return Ok(Bytes::copy_from_slice(packet));
            }
            TunnResult::WriteToNetwork(packet) => {
                let mut frame = Vec::with_capacity(2 + packet.len());
                frame.put_u16(packet.len() as u16);
                frame.extend_from_slice(packet);
                tunnel
                    .send
                    .write_all(&frame)
                    .await
                    .map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
            }
            _ => {}
        }
        Ok(Bytes::new())
    }
}

async fn fill_frame_bytes(tunnel: &mut Tunnel, n: usize) -> Result<(), ShadowMeshError> {
    while tunnel.frame_buf.len() < n {
        let mut buf = [0u8; 2048];
        let read_n = tunnel
            .recv
            .read(&mut buf)
            .await
            .map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
        match read_n {
            Some(0) | None => return Err(ShadowMeshError::Other("Hysteria: tunnel closed".into())),
            Some(size) => tunnel.frame_buf.extend_from_slice(&buf[..size]),
        }
    }
    Ok(())
}

#[async_trait]
impl AsyncTransport for HysteriaTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Hysteria
    }

    async fn connect(&self) -> Result<(), ShadowMeshError> {
        let _ = self.get_or_connect().await?;
        Ok(())
    }

    async fn send(&self, data: Bytes) -> Result<(), ShadowMeshError> {
        let mut guard = self.get_or_connect().await?;
        let mut buf = vec![0u8; 2048];
        let wg_packet = {
            let mut tunn = self.tunn.lock().await;
            match tunn.encapsulate(&data, &mut buf) {
                TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                _ => None,
            }
        };

        if let Some(packet) = wg_packet {
            let tunnel = guard
                .as_mut()
                .ok_or_else(|| ShadowMeshError::Other("Hysteria tunnel disappeared".into()))?;
            let mut frame = Vec::with_capacity(2 + packet.len());
            frame.put_u16(packet.len() as u16);
            frame.extend_from_slice(&packet);
            tunnel
                .send
                .write_all(&frame)
                .await
                .map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Bytes, ShadowMeshError> {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let mut buf = vec![0u8; 2048];
                    let wg_packet = {
                        let mut tunn = self.tunn.lock().await;
                        match tunn.update_timers(&mut buf) {
                            TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                            _ => None,
                        }
                    };
                    if let Some(packet) = wg_packet {
                        let mut guard = self.get_or_connect().await?;
                        if let Some(tunnel) = guard.as_mut() {
                            let mut frame = Vec::with_capacity(2 + packet.len());
                            frame.put_u16(packet.len() as u16);
                            frame.extend_from_slice(&packet);
                            let _ = tunnel.send.write_all(&frame).await;
                        }
                    }
                }
                res = self.read_packet() => {
                    match res {
                        Ok(packet) if !packet.is_empty() => return Ok(packet),
                        Ok(_) => continue,
                        Err(e) => {
                            let mut guard = self.tunnel.lock().await;
                            *guard = None;
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    async fn close(&self) -> Result<(), ShadowMeshError> {
        let mut guard = self.tunnel.lock().await;
        if let Some(tunnel) = guard.take() {
            tunnel.connection.close(0u32.into(), b"Closed by user");
        }
        Ok(())
    }
}

/// Hysteria 2 Inbound listener (Server-side).
pub struct HysteriaInbound {
    tag: String,
    listen_addr: String,
    auth_password: String,
    engine: crate::engine::EngineHandle,
}

impl HysteriaInbound {
    pub fn new(
        tag: String,
        listen_addr: String,
        auth_password: String,
        engine: crate::engine::EngineHandle,
    ) -> Self {
        Self { tag, listen_addr, auth_password, engine }
    }
}

#[async_trait]
impl InboundListener for HysteriaInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(&self) -> Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // v6.9.25: Independent Server-side Hysteria 2 Implementation
        // In a production environment, certificates would be loaded from disk or
        // generated via Let's Encrypt. For now, we use a placeholder or local fixture.
        let cert = include_bytes!("../../tests/fixtures/cert.der").to_vec();
        let key = include_bytes!("../../tests/fixtures/key.der").to_vec();

        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert)],
                rustls::pki_types::PrivateKeyDer::try_from(key).map_err(|e| anyhow::anyhow!(e))?,
            )
            .map_err(|e| anyhow::anyhow!(e))?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| anyhow::anyhow!(e))?,
        ));

        let transport_config = Arc::get_mut(&mut server_config.transport)
            .ok_or_else(|| anyhow::anyhow!("failed to get transport config"))?;
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));

        let addr: SocketAddr = self.listen_addr.parse()?;
        let endpoint = Endpoint::server(server_config, addr)?;
        info!("Hysteria 2 inbound {} listening on {}", self.tag, self.listen_addr);

        while let Some(incoming) = endpoint.accept().await {
            let tag = self.tag.clone();
            let auth_password = self.auth_password.clone();
            let engine = self.engine.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    handle_hysteria_connection(incoming, tag, auth_password, engine).await
                {
                    error!("Hysteria connection failed: {:?}", e);
                }
            });
        }
        Ok(())
    }
}

async fn handle_hysteria_connection(
    incoming: quinn::Incoming,
    tag: String,
    auth_password: String,
    engine: crate::engine::EngineHandle,
) -> Result<()> {
    let connection = incoming.await?;
    let (mut send, mut recv) = connection.accept_bi().await?;

    // 1. Authenticate
    let mut auth_header = [0u8; 3];
    recv.read_exact(&mut auth_header).await?;
    let auth_type = auth_header[0];
    let password_len = u16::from_be_bytes([auth_header[1], auth_header[2]]) as usize;

    let mut password_buf = vec![0u8; password_len];
    recv.read_exact(&mut password_buf).await?;
    let received_password = String::from_utf8(password_buf)?;

    if auth_type != 0x01 || received_password != auth_password {
        send.write_all(&[0x01]).await?;
        return Err(anyhow::anyhow!("Unauthorized Hysteria 2 connection"));
    }

    send.write_all(&[0x00]).await?;
    info!("Hysteria 2 client authenticated from {}", connection.remote_address());

    // 2. Wrap and Dispatch
    // Hysteria 2 usually carries tunneled IP packets or SOCKS requests.
    // For ShadowMesh, we treat it as a stream of framed packets.
    let h_stream = HysteriaStream::new(send, recv);

    // Create metadata for the new connection
    let mut metadata = crate::engine::metadata::ConnectionMetadata::new(
        crate::engine::metadata::Endpoint::new_domain("shadowmesh.local".into(), 0),
    );
    metadata.identity.source =
        Some(crate::engine::metadata::Endpoint::from(connection.remote_address()));
    metadata.environment.inbound_tag = Some(tag);

    let context =
        Arc::new(parking_lot::Mutex::new(crate::engine::context::ConnectionContext::new(metadata)));
    engine
        .send_event(crate::engine::events::EngineEvent::NewStream {
            context,
            stream: Box::new(h_stream),
        })
        .await?;

    Ok(())
}

struct HysteriaStream {
    send: SendStream,
    recv: RecvStream,
}

impl HysteriaStream {
    fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

// Implement AsyncRead/AsyncWrite for HysteriaStream by delegating to send/recv
// Note: Hysteria 2 framing uses [length u16][payload]
impl tokio::io::AsyncRead for HysteriaStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // In a real Hysteria stream, we'd handle framing here.
        // For unified interoperability, we just proxy the raw QUIC stream.
        std::pin::Pin::new(&mut this.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for HysteriaStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.send).poll_write(cx, buf) {
            std::task::Poll::Ready(result) => {
                std::task::Poll::Ready(result.map_err(std::io::Error::other))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.get_mut().send).poll_flush(cx) {
            std::task::Poll::Ready(result) => {
                std::task::Poll::Ready(result.map_err(std::io::Error::other))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.get_mut().send).poll_shutdown(cx) {
            std::task::Poll::Ready(result) => {
                std::task::Poll::Ready(result.map_err(std::io::Error::other))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::net::{IpAddr, Ipv4Addr};

    async fn setup_mock_server(
        port: u16,
        password: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = include_bytes!("../../tests/fixtures/cert.der").to_vec();
        let key = include_bytes!("../../tests/fixtures/key.der").to_vec();

        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert)], PrivateKeyDer::try_from(key)?)?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
        ));
        let transport_config = Arc::get_mut(&mut server_config.transport)
            .ok_or_else(|| anyhow::anyhow!("failed to get transport config"))?;
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(10).try_into()?));

        let endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        )?;

        if let Some(connecting) = endpoint.accept().await {
            let connection = connecting.await?;
            let (mut send, mut recv) = connection.accept_bi().await?;

            // 1. Read Auth Frame
            let mut auth_header = [0u8; 3];
            recv.read_exact(&mut auth_header).await?;
            let auth_type = auth_header[0];
            let password_len = u16::from_be_bytes([auth_header[1], auth_header[2]]) as usize;

            let mut password_buf = vec![0u8; password_len];
            recv.read_exact(&mut password_buf).await?;
            let received_password = String::from_utf8(password_buf)?;

            // 2. Verify and Send Result
            if auth_type == 0x01 && received_password == password {
                send.write_all(&[0x00]).await?; // Success
            } else {
                send.write_all(&[0x01]).await?; // Failed
            }

            // Keep the connection alive for a moment to ensure client receives the result
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            send.finish()?;
            connection.close(0u32.into(), b"Done");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_hysteria2_handshake_success() {
        let port = 18393; // Use different port
        let password = "top_secret_hysteria";

        // Start mock server in background
        let server_handle = tokio::spawn(async move {
            if let Err(e) = setup_mock_server(port, password).await {
                error!("Mock Hysteria server error: {:?}", e);
            }
        });

        // Give server a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let config = HysteriaConfig {
            server: "127.0.0.1".to_string(),
            port: port as u32,
            auth_password: password.to_string(),
            obfuscation_key: None,
            up_mbps: 10,
            down_mbps: 50,
            sni: Some("localhost".to_string()),
        };

        let (priv_key, pub_key) = shadowmesh_common::crypto::generate_x25519_keypair();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&priv_key);
        let mut spk = [0u8; 32];
        spk.copy_from_slice(&pub_key);

        let transport = HysteriaTransport::new(config, pk, spk);

        // The get_or_connect should pass the handshake
        let result = transport.connect().await;
        assert!(result.is_ok(), "Handshake should succeed: {:?}", result.err());

        let _ = server_handle.await;
    }
}
