use super::reality_tls::RealityTlsStream;
use super::{AsyncTransport, TransportType};
use crate::{RealityConfig, ShadowMeshError};
use async_trait::async_trait;
use boringtun::noise::{Tunn, TunnResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use socket2::{Domain, Socket, Type};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

/// Upper sanity bound for one VLESS-UDP framed WG packet.
const MAX_PACKET: usize = 4096;

/// Established REALITY tunnel: TLS stream + VLESS UDP frame reassembly buffer.
struct Tunnel {
    tls: RealityTlsStream,
    /// Decrypted app-data bytes not yet consumed as a complete [len][pkt] frame.
    frame_buf: BytesMut,
}

/// REALITY-based transport implementation for high-censorship regions.
/// SOP 04 §2: Composes WireGuard (boringtun) over flow-less VLESS UDP,
/// carried by a REALITY-authenticated TLS 1.3 session (see `reality_tls`).
pub struct RealityTransport {
    config: RealityConfig,
    tunnel: Arc<Mutex<Option<Tunnel>>>,
    tunn: Arc<Mutex<Tunn>>,
}

impl std::fmt::Debug for RealityTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityTransport").field("config", &self.config).finish()
    }
}

impl RealityTransport {
    /// Creates a new `RealityTransport` instance.
    ///
    /// `static_private`/`server_static_public` are the client's WireGuard
    /// static key and the peer (server) WireGuard public key for boringtun.
    pub fn new(
        config: RealityConfig,
        static_private: [u8; 32],
        server_static_public: [u8; 32],
    ) -> Self {
        let tunn =
            Tunn::new(static_private.into(), server_static_public.into(), None, None, 0, None);

        Self { config, tunnel: Arc::new(Mutex::new(None)), tunn: Arc::new(Mutex::new(tunn)) }
    }

    /// Establishes the REALITY TLS session + VLESS UDP channel if needed.
    async fn get_or_connect(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<Tunnel>>, ShadowMeshError> {
        let mut guard = self.tunnel.lock().await;
        if guard.is_none() {
            let server_addr = format!("{}:{}", self.config.server_ip, self.config.port);
            let addr: std::net::SocketAddr = server_addr
                .parse()
                .map_err(|_| ShadowMeshError::Other("Invalid server address".into()))?;

            // v6.9.5: Advanced Socket Protection (Pre-Handshake)
            let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)
                .map_err(|e| ShadowMeshError::IoError(format!("Socket creation failed: {}", e)))?;

            // Critical: Protect the raw socket FD BEFORE connecting
            if !crate::protect_socket(socket.as_raw_fd()) {
                error!("⚠️ FAILED TO PROTECT SOCKET FD: {}", socket.as_raw_fd());
            }

            socket.set_nonblocking(true).map_err(|e| {
                ShadowMeshError::IoError(format!("Failed to set non-blocking: {}", e))
            })?;

            // v6.9.5: Proper non-blocking connect handling
            match socket.connect(&addr.into()) {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {
                    // This is expected for non-blocking sockets
                }
                Err(e) => {
                    return Err(ShadowMeshError::IoError(format!("TCP connect failed: {}", e)));
                }
            }

            // Hand over to tokio for the async connection
            let std_stream: std::net::TcpStream = socket.into();
            let tcp = TcpStream::from_std(std_stream)
                .map_err(|e| ShadowMeshError::IoError(format!("TCP conversion failed: {}", e)))?;

            // Wait for the socket to be writable (connection established)
            tcp.writable()
                .await
                .map_err(|e| ShadowMeshError::IoError(format!("TCP connect timeout: {}", e)))?;

            // REALITY-authenticated TLS 1.3 (ClientHello session_id auth).
            let mut tls = RealityTlsStream::connect(
                tcp,
                &self.config.public_key,
                &self.config.short_id,
                &self.config.sni_target,
            )
            .await?;

            // v6.9.14: Flow-less VLESS UDP Handshake
            // Format: [Version 0][UUID 16b][Addon Len 0][Cmd 2 (UDP)][Port 2b][AddrType 1b][Addr 4b]
            let mut header = Vec::with_capacity(24);
            header.push(0x00); // Version 0
            let uuid =
                uuid::Uuid::parse_str(&self.config.uuid).unwrap_or_else(|_| uuid::Uuid::nil());
            header.extend_from_slice(uuid.as_bytes());
            header.push(0x00); // Addon length 0 (empty flow: required, Vision+UDP is rejected by Xray)
            header.push(0x02); // Command: UDP
            header.put_u16(51820); // Target Port (node-local WireGuard)
            header.push(0x01); // IPv4
            header.extend_from_slice(&[127, 0, 0, 1]); // Target Address: 127.0.0.1

            tls.write_app(&header).await.map_err(|e| {
                error!("⚠️ VLESS request send failed: {}", e);
                e
            })?;

            // Response header [Version 1b][AddonLen 1b] arrives as app data.
            let mut tunnel = Tunnel { tls, frame_buf: BytesMut::with_capacity(2048) };
            fill_frame_bytes(&mut tunnel, 2).await?;
            let resp: Vec<u8> = tunnel.frame_buf.split_to(2).to_vec();
            if resp[0] != 0x00 {
                return Err(ShadowMeshError::Other(format!(
                    "VLESS: unexpected response version {:#04x} (not a REALITY VLESS endpoint)",
                    resp[0]
                )));
            }
            if resp[1] > 0 {
                fill_frame_bytes(&mut tunnel, 2 + resp[1] as usize).await?;
                let _addon = tunnel.frame_buf.split_to(resp[1] as usize);
            }

            info!("✅ REALITY tunnel established (VLESS UDP → 127.0.0.1:51820)");
            *guard = Some(tunnel);
        }
        Ok(guard)
    }

    /// Reads the next complete VLESS UDP frame and decapsulates it through
    /// boringtun. Returns the inner IP packet, or empty if the frame was a
    /// WG control packet (handshake/cookie) that was answered inline.
    async fn read_packet(&self) -> Result<Bytes, ShadowMeshError> {
        let mut guard = self.get_or_connect().await?;
        let tunnel = match guard.as_mut() {
            Some(t) => t,
            None => return Ok(Bytes::new()),
        };

        fill_frame_bytes(tunnel, 2).await?;
        let len = u16::from_be_bytes([tunnel.frame_buf[0], tunnel.frame_buf[1]]) as usize;
        if len > MAX_PACKET {
            error!("⚠️ RealityTransport: Packet too large ({} bytes). Stream out of sync.", len);
            *guard = None;
            return Err(ShadowMeshError::Other(format!("Packet too large: {}", len)));
        }
        if len == 0 {
            tunnel.frame_buf.advance(2);
            return Ok(Bytes::new());
        }
        fill_frame_bytes(tunnel, 2 + len).await?;
        let payload = tunnel.frame_buf.split_to(2 + len).split_off(2).to_vec();

        // Decapsulate WireGuard packet
        let mut tunn = self.tunn.lock().await;
        let mut ip_buf = vec![0u8; 2048];
        match tunn.decapsulate(None, &payload, &mut ip_buf) {
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                return Ok(Bytes::copy_from_slice(packet));
            }
            TunnResult::WriteToNetwork(packet) => {
                // WireGuard control reply (e.g. re-handshake under load): send inline.
                let mut frame = Vec::with_capacity(2 + packet.len());
                frame.put_u16(packet.len() as u16);
                frame.extend_from_slice(packet);
                tunnel.tls.write_app(&frame).await?;
            }
            _ => {}
        }
        Ok(Bytes::new())
    }
}

/// Reads from the TLS stream until at least `n` bytes are buffered for
/// framing. Cancel-safe: `read_app` keeps partial TCP reads buffered, and the
/// returned payload is appended to `frame_buf` immediately after each await.
async fn fill_frame_bytes(tunnel: &mut Tunnel, n: usize) -> Result<(), ShadowMeshError> {
    while tunnel.frame_buf.len() < n {
        match tunnel.tls.read_app().await? {
            Some(data) => tunnel.frame_buf.extend_from_slice(&data),
            None => return Err(ShadowMeshError::Other("REALITY: tunnel closed by server".into())),
        }
    }
    Ok(())
}

#[async_trait]
impl AsyncTransport for RealityTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Reality
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
                TunnResult::Err(e) => {
                    error!("WireGuard encapsulation error: {:?}", e);
                    None
                }
                _ => None,
            }
        };

        if let Some(packet) = wg_packet {
            let tunnel = guard.as_mut().ok_or_else(|| {
                ShadowMeshError::Other("REALITY: tunnel disappeared during send".into())
            })?;
            // v6.9.14: Standard VLESS UDP Framing [u16 BE length][payload]
            let mut frame = Vec::with_capacity(2 + packet.len());
            frame.put_u16(packet.len() as u16);
            frame.extend_from_slice(&packet);

            if let Err(e) = tunnel.tls.write_app(&frame).await {
                *guard = None;
                return Err(ShadowMeshError::IoError(e.to_string()));
            }
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Bytes, ShadowMeshError> {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // SOP 04 §2: Trigger Tunn::update_timers() every second.
                    // Scope the tunn lock so it is released before acquiring
                    // the tunnel lock (avoids lock-order inversion with send).
                    let wg_packet = {
                        let mut tunn = self.tunn.lock().await;
                        let mut buf = vec![0u8; 2048];
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
                            let _ = tunnel.tls.write_app(&frame).await;
                        }
                    }
                }
                res = self.read_packet() => {
                    match res {
                        Ok(packet) => {
                            if !packet.is_empty() {
                                return Ok(packet);
                            }
                        }
                        Err(e) => {
                            warn!("REALITY recv error: {} — resetting tunnel", e);
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
        if let Some(mut tunnel) = guard.take() {
            tunnel.tls.close().await;
        }
        Ok(())
    }
}
