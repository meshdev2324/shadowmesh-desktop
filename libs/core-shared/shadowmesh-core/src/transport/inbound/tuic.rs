//! TUIC v5 inbound (server role) — RFC-023 phase 2.
//!
//! Clean-room implementation from the public TUIC v5 wire-format
//! specification (protocol version `0x05`); shares the byte-exact codec in
//! [`crate::transport::outbound::tuic::wire`] with the client role.
//!
//! Connection lifecycle per connection:
//! 1. First unidirectional stream carries the Authenticate command
//!    (`UUID(16)` + `TOKEN(32)`). The token is re-derived server-side via
//!    the TLS Keying Material Exporter (label = UUID, context = password)
//!    and compared in constant time. Failure closes the connection.
//! 2. Connect commands arrive on bidirectional streams — one TCP relay
//!    each, dispatched to the engine as `NewStream` with the destination
//!    from the Connect header.
//! 3. Packet commands arrive as QUIC datagrams (`native` relay mode) —
//!    reassembled if fragmented, dispatched as `UdpPacket`, and the engine
//!    reply is echoed back as a single-fragment Packet command carrying the
//!    original destination (the same reply-address convention as the
//!    Shadowsocks inbound).
//!
//! Security notes: TLS is mandatory (fail-closed on missing cert/key);
//! authentication is bound to the live TLS session by construction; no
//! credential material is ever logged. Reassembly state is bounded
//! (protocol-rules §13).

use crate::engine::events::EngineEvent;
use crate::engine::metadata::{Addr, ConnectionMetadata, Endpoint, L4Protocol};
use crate::transport::outbound::tuic::wire::{self, FragmentReassembler, Reassemble};
use crate::transport::traits::InboundListener;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Upper bound on concurrently reassembling UDP packets per connection.
/// Exceeding it drops the oldest partial reassembly (bounded memory).
const REASSEMBLY_CAP: usize = 64;

/// Bounded wait for the Authenticate stream before the connection is
/// dropped (slow-loris resistance).
const AUTH_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

/// Bounded wait for an upstream UDP reply before answering with nothing.
const UDP_REPLY_WINDOW: std::time::Duration = std::time::Duration::from_millis(2500);

/// TUIC v5 server listener (RFC-023 phase 2).
pub struct TuicInbound {
    tag: String,
    listen_addr: String,
    uuid: uuid::Uuid,
    password: String,
    /// PEM certificate chain for the QUIC TLS layer. Required — the inbound
    /// fails closed rather than serving bundled credentials.
    cert_path: String,
    /// PEM private key matching `cert_path`. Required.
    key_path: String,
    engine: crate::engine::EngineHandle,
}

impl TuicInbound {
    /// Creates a TUIC v5 inbound listener.
    ///
    /// # Errors
    /// Returns an error when `uuid` is not a valid UUID string.
    pub fn new(
        tag: String,
        listen_addr: String,
        uuid: &str,
        password: &str,
        cert_path: String,
        key_path: String,
        engine: crate::engine::EngineHandle,
    ) -> Result<Self> {
        let parsed_uuid = uuid::Uuid::parse_str(uuid)
            .map_err(|e| anyhow!("inbound '{tag}': invalid tuic uuid: {e}"))?;
        Ok(Self {
            tag,
            listen_addr,
            uuid: parsed_uuid,
            password: password.to_owned(),
            cert_path,
            key_path,
            engine,
        })
    }

    /// Loads the operator-provided PEM pair into a rustls server config.
    /// Fail-closed on missing/unparsable files (same contract as the
    /// Hysteria inbound — never a bundled fallback).
    fn load_server_crypto(&self) -> Result<rustls::ServerConfig> {
        let cert_file = std::fs::File::open(&self.cert_path).map_err(|e| {
            anyhow!("inbound '{}': open certificate file '{}': {e}", self.tag, self.cert_path)
        })?;
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| {
                anyhow!("inbound '{}': parse certificates from '{}': {e}", self.tag, self.cert_path)
            })?;
        if certs.is_empty() {
            return Err(anyhow!(
                "inbound '{}': no certificates found in '{}'",
                self.tag,
                self.cert_path
            ));
        }
        let key_file = std::fs::File::open(&self.key_path).map_err(|e| {
            anyhow!("inbound '{}': open key file '{}': {e}", self.tag, self.key_path)
        })?;
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
            .map_err(|e| {
                anyhow!("inbound '{}': parse private key from '{}': {e}", self.tag, self.key_path)
            })?
            .ok_or_else(|| {
                anyhow!("inbound '{}': no private key found in '{}'", self.tag, self.key_path)
            })?;

        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("inbound '{}': invalid TLS certificate/key pair: {e}", self.tag))
    }
}

#[async_trait]
impl InboundListener for TuicInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(&self) -> Result<()> {
        let server_crypto = self.load_server_crypto()?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
        ));
        {
            let transport = Arc::get_mut(&mut server_config.transport).ok_or_else(|| {
                anyhow!("inbound '{}': transport config already shared", self.tag)
            })?;
            transport.max_idle_timeout(Some(
                std::time::Duration::from_secs(30)
                    .try_into()
                    .map_err(|e| anyhow!("invalid idle timeout: {e}"))?,
            ));
        }

        let addr: SocketAddr = self.listen_addr.parse()?;
        let endpoint = quinn::Endpoint::server(server_config, addr)?;
        info!("TUIC v5 inbound {} listening on {}", self.tag, self.listen_addr);

        while let Some(incoming) = endpoint.accept().await {
            let tag = self.tag.clone();
            let uuid = self.uuid;
            let password = self.password.clone();
            let engine = self.engine.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(incoming, tag, uuid, password, engine).await {
                    debug!("TUIC connection ended: {e:#}");
                }
            });
        }
        Ok(())
    }
}

/// Handles one QUIC connection: Authenticate, then Connect streams and the
/// UDP datagram pump run concurrently for the connection's lifetime.
async fn handle_connection(
    incoming: quinn::Incoming,
    tag: String,
    uuid: uuid::Uuid,
    password: String,
    engine: crate::engine::EngineHandle,
) -> Result<()> {
    let conn = incoming.await?;

    // 1. Authenticate on the first unidirectional stream (bounded wait).
    let auth = tokio::time::timeout(AUTH_WINDOW, async {
        let mut uni = conn.accept_uni().await.map_err(|e| anyhow!("accept failed: {e}"))?;
        match uni.read_to_end(64).await {
            Ok(auth) => Ok(auth),
            Err(e) => Err(anyhow!("auth read failed: {e}")),
        }
    })
    .await
    .map_err(|_| anyhow!("inbound '{tag}': authenticate window expired"))??;
    if auth.len() != 50 || auth[0] != wire::VERSION || auth[1] != wire::CMD_AUTHENTICATE {
        conn.close(quinn::VarInt::from_u32(1), b"malformed authenticate");
        return Err(anyhow!("inbound '{tag}': malformed authenticate frame"));
    }
    let claimed_uuid: [u8; 16] = auth[2..18].try_into().map_err(|_| anyhow!("uuid slice"))?;
    let claimed_token: [u8; 32] = auth[18..50].try_into().map_err(|_| anyhow!("token slice"))?;
    let mut expected = [0u8; 32];
    conn.export_keying_material(&mut expected, &claimed_uuid, password.as_bytes())
        .map_err(|e| anyhow!("inbound '{tag}': exporter failed: {e:?}"))?;
    {
        use subtle::ConstantTimeEq;
        // Both comparisons always run (no short-circuit): the duration must
        // not reveal whether the UUID or the token mismatched first.
        let uuid_ok = claimed_uuid.ct_eq(uuid.as_bytes());
        let token_ok = claimed_token.ct_eq(&expected);
        if !bool::from(uuid_ok & token_ok) {
            conn.close(quinn::VarInt::from_u32(2), b"authentication failed");
            return Err(anyhow!(
                "inbound '{tag}': authentication failed from {}",
                conn.remote_address()
            ));
        }
    }
    info!("TUIC inbound {tag}: client authenticated from {}", conn.remote_address());

    // 2. UDP datagram pump (native mode) — runs concurrently with relays.
    let pump = TuicUdpPump::new(conn.clone(), engine.clone(), tag.clone());
    tokio::spawn(pump.run());

    // 3. Connect relays: one bidirectional stream per TCP connection.
    while let Ok((send, recv)) = conn.accept_bi().await {
        let engine = engine.clone();
        let tag = tag.clone();
        tokio::spawn(async move {
            if let Err(e) = relay_connect(send, recv, engine, tag).await {
                debug!("TUIC relay ended: {e:#}");
            }
        });
    }
    Ok(())
}

/// Relays one Connect stream into the engine as a `NewStream` event.
async fn relay_connect(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    engine: crate::engine::EngineHandle,
    tag: String,
) -> Result<()> {
    let mut header = [0u8; 2];
    recv.read_exact(&mut header).await?;
    if header[0] != wire::VERSION || header[1] != wire::CMD_CONNECT {
        return Err(anyhow!("unexpected stream command 0x{:02x}", header[1]));
    }
    // Exact per-field reads: an over-read here would swallow relay payload
    // bytes that belong to the engine stream (partial frames are legal).
    let mut atyp = [0u8; 1];
    recv.read_exact(&mut atyp).await?;
    let addr_len = match atyp[0] {
        wire::ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            recv.read_exact(&mut len).await?;
            len[0] as usize
        }
        wire::ATYP_IPV4 => 4,
        wire::ATYP_IPV6 => 16,
        other => return Err(anyhow!("unknown address TYPE byte 0x{other:02x}")),
    };
    let mut rest = vec![0u8; addr_len + 2];
    recv.read_exact(&mut rest).await?;
    let (host_bytes, port_bytes) = rest.split_at(addr_len);
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    let destination = match atyp[0] {
        wire::ATYP_DOMAIN => {
            let domain = std::str::from_utf8(host_bytes)
                .map_err(|_| anyhow!("connect domain is not valid UTF-8"))?;
            if domain.is_empty() {
                return Err(anyhow!("connect domain is empty"));
            }
            Endpoint::new_domain(domain.to_owned(), port)
        }
        wire::ATYP_IPV4 => Endpoint::new_ip(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                host_bytes[0],
                host_bytes[1],
                host_bytes[2],
                host_bytes[3],
            )),
            port,
        ),
        _ => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(host_bytes);
            Endpoint::new_ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)), port)
        }
    };
    debug!("TUIC relay opened to {destination}");

    let mut metadata = ConnectionMetadata::new(destination);
    metadata.l4_protocol = L4Protocol::Tcp;
    metadata.environment.inbound_tag = Some(tag);
    let context =
        Arc::new(parking_lot::Mutex::new(crate::engine::context::ConnectionContext::new(metadata)));
    engine
        .send_event(EngineEvent::NewStream {
            context,
            stream: Box::new(crate::transport::outbound::tuic::BiStream { send, recv }),
        })
        .await?;
    Ok(())
}

/// Per-connection UDP pump: datagram in → reassemble → engine dispatch →
/// reply Packet command back out (single fragment, original destination).
struct TuicUdpPump {
    conn: quinn::Connection,
    engine: crate::engine::EngineHandle,
    tag: String,
    reassembler: FragmentReassembler,
}

impl TuicUdpPump {
    fn new(conn: quinn::Connection, engine: crate::engine::EngineHandle, tag: String) -> Self {
        Self { conn, engine, tag, reassembler: FragmentReassembler::new(REASSEMBLY_CAP) }
    }

    async fn run(mut self) {
        while let Ok(dgram) = self.conn.read_datagram().await {
            let cmd = match wire::decode_packet(&dgram) {
                Ok(cmd) => cmd,
                Err(_) => {
                    debug!(
                        "TUIC inbound {}: ignored non-conforming datagram ({} bytes)",
                        self.tag,
                        dgram.len()
                    );
                    continue;
                }
            };
            let (assoc_id, pkt_id) = (cmd.assoc_id, cmd.pkt_id);
            match self.reassembler.accept(&cmd) {
                Reassemble::Pending => continue,
                Reassemble::Rejected => {
                    debug!("TUIC inbound {}: rejected oversized fragment group", self.tag);
                    continue;
                }
                Reassemble::Complete { address, payload } => {
                    self.dispatch(assoc_id, pkt_id, address, payload).await;
                }
            }
        }
    }

    /// Dispatches one complete UDP packet and sends the reply, if any.
    async fn dispatch(
        &mut self,
        assoc_id: u16,
        pkt_id: u16,
        address: Option<wire::WireAddress>,
        payload: Vec<u8>,
    ) {
        let Some(address) = address else {
            debug!("TUIC inbound {}: dropping tail fragment with no group start", self.tag);
            return;
        };
        let destination =
            Endpoint::from(wire::WireAddress { host: address.host.clone(), port: address.port });
        let mut metadata = ConnectionMetadata::new(destination);
        metadata.l4_protocol = L4Protocol::Udp;
        metadata.environment.inbound_tag = Some(self.tag.clone());
        let context = Arc::new(parking_lot::Mutex::new(
            crate::engine::context::ConnectionContext::new(metadata),
        ));

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<Option<Vec<u8>>>();
        if let Err(e) = self
            .engine
            .send_event(EngineEvent::UdpPacket {
                context,
                payload: payload.clone(),
                source: self.conn.remote_address(),
                reply: Some(reply_tx),
            })
            .await
        {
            error!("TUIC inbound {}: UDP dispatch failed: {e:#}", self.tag);
            return;
        }

        // Bounded reply window: a slow upstream must not stall the pump.
        let reply = match tokio::time::timeout(UDP_REPLY_WINDOW, reply_rx).await {
            Ok(Ok(Some(reply))) if !reply.is_empty() => reply,
            _ => return, // fire-and-forget or timeout — nothing to echo
        };
        let datagram = wire::encode_packet(
            assoc_id,
            pkt_id,
            1,
            0,
            Some(&wire::WireAddress { host: address.host, port: address.port }),
            &reply,
        );
        match datagram {
            Ok(dgram) => {
                if let Err(e) = self.conn.send_datagram(Bytes::from(dgram)) {
                    debug!("TUIC inbound {}: reply datagram not sent: {e}", self.tag);
                }
            }
            Err(e) => warn!("TUIC inbound {}: reply encode failed: {e}", self.tag),
        }
    }
}

/// Maps a wire address onto the engine endpoint type.
impl From<wire::WireAddress> for Endpoint {
    fn from(address: wire::WireAddress) -> Self {
        match address.host {
            Addr::Ip(ip) => Endpoint::new_ip(ip, address.port),
            Addr::Domain(domain) => Endpoint::new_domain(domain, address.port),
        }
    }
}
