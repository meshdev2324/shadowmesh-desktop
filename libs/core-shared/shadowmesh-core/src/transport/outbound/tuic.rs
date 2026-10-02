//! TUIC v5 outbound transport (RFC-023).
//!
//! Clean-room implementation authored from public specifications only.
//!
//! Implementation Source:
//! - Specification: TUIC protocol v5 wire-format specification (protocol
//!   version `0x05`) and RFC 5705 (TLS Keying Material Exporter).
//! - Relevant sections: command types `0x00`–`0x04`; address `TYPE` bytes
//!   `0x00` (FQDN) / `0x01` (IPv4) / `0x02` (IPv6) / `0xff` (None);
//!   Authenticate TOKEN via the TLS exporter (label = client UUID, context =
//!   raw password, 32 bytes); Packet fragmentation (`ASSOC_ID`/`PKT_ID`/
//!   `FRAG_TOTAL`/`FRAG_ID`); UDP relay mode `native` (QUIC datagrams).
//! - Security considerations: the Authenticate token is derived from the
//!   live TLS session, so it cannot be replayed on a different connection.
//!   Credential material is never logged. `Debug` is deliberately not
//!   implemented for the outbound so secrets cannot end up in traces.
//!
//! UDP relay uses the spec's `native` mode exclusively (the client's mode is
//! authoritative for the session, so a native-only client is conformant).
//! `Connect` commands get one bidirectional QUIC stream each; there is no
//! server reply to a Connect — a rejected relay surfaces as stream reset or
//! EOF on the returned stream.

use crate::engine::context::SharedContext;
use crate::engine::metadata::{Addr, Endpoint, L4Protocol};
use crate::transport::traits::{AsyncIoStream, OutboundDialer};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use rand::rngs::OsRng;
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

/// Wire-format codec and protocol constants.
pub mod wire;

/// Bounded wait for a UDP reply after sending a Packet command (RFC-012 G2
/// parity with the Shadowsocks outbound). Loss surfaces as an empty reply.
const REPLY_WINDOW: Duration = Duration::from_millis(2000);

/// Polling cadence while waiting for a matching reply.
const REPLY_POLL: Duration = Duration::from_millis(25);

/// Upper bound on queued inbound UDP replies — backpressure, never unbounded
/// memory (protocol-rules §13). The oldest reply is dropped when full.
const REPLY_QUEUE_CAP: usize = 1024;

/// Upper bound on concurrently reassembling fragmented replies per session.
const REPLY_REASSEMBLY_CAP: usize = 64;

/// Keep-alive cadence for the Heartbeat command while a session is alive.
/// The spec requires "periodically" without a number; 15 s sits comfortably
/// under typical QUIC idle timeouts (this client negotiates 30 s).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// QUIC idle timeout negotiated on the transport.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Fallback QUIC datagram capacity when the connection has not reported
/// `max_datagram_size` (never below the IPv6 minimum MTU).
const DATAGRAM_FALLBACK: usize = 1200;

/// Lazily-established session slot shared across dial/packet calls.
type SessionSlot = tokio::sync::Mutex<Option<Arc<TuicSession>>>;

/// Bounded inbound-reply queue shared between the datagram reader task and
/// the per-call reply windows.
type ReplyQueue = Arc<tokio::sync::Mutex<VecDeque<(Addr, u16, Vec<u8>)>>>;

/// TUIC v5 outbound dialer (RFC-023).
///
/// One QUIC connection is established lazily and amortized across all TCP
/// relays (bidirectional streams) and UDP relays (datagrams). Credential
/// material is bound to that connection's TLS session at authentication time.
pub struct TuicOutbound {
    tag: String,
    server: String,
    port: u16,
    uuid: uuid::Uuid,
    password: String,
    sni: String,
    insecure: bool,
    session: SessionSlot,
}

impl TuicOutbound {
    /// Creates a TUIC v5 outbound.
    ///
    /// # Arguments
    /// * `tag` - Registry tag for this outbound.
    /// * `server` - TUIC server host (IP or FQDN; resolved per dial).
    /// * `port` - TUIC server QUIC port.
    /// * `uuid` - Client UUID string; malformed UUIDs are hard errors here,
    ///   at configuration load, never at first dial.
    /// * `password` - Raw password used as the TLS-exporter context.
    /// * `sni` - TLS SNI; falls back to `server` when `None`.
    /// * `insecure` - Accept self-signed edge certificates. Explicit operator
    ///   choice only; never a default and always logged when enabled.
    ///
    /// # Errors
    /// Returns an error when `uuid` is not a valid UUID string.
    pub fn new(
        tag: String,
        server: String,
        port: u16,
        uuid: &str,
        password: &str,
        sni: Option<String>,
        insecure: bool,
    ) -> Result<Self> {
        if server.is_empty() {
            return Err(anyhow!("outbound '{tag}': tuic server must not be empty"));
        }
        let parsed_uuid = uuid::Uuid::parse_str(uuid)
            .map_err(|e| anyhow!("outbound '{tag}': invalid tuic uuid: {e}"))?;
        let sni = sni.unwrap_or_else(|| server.clone());
        if insecure {
            warn!(
                "TUIC outbound [{}]: certificate verification DISABLED (insecure mode — self-signed edge only)",
                tag
            );
        }
        Ok(Self {
            tag,
            server,
            port,
            uuid: parsed_uuid,
            password: password.to_owned(),
            sni,
            insecure,
            session: tokio::sync::Mutex::new(None),
        })
    }

    /// Returns the live session, establishing (or re-establishing after
    /// connection loss) exactly once per call under the slot lock.
    async fn session(&self) -> Result<Arc<TuicSession>> {
        let mut slot = self.session.lock().await;
        if let Some(existing) = slot.as_ref() {
            if !existing.closed.load(Ordering::Relaxed) {
                return Ok(existing.clone());
            }
        }
        let session = self.establish().await?;
        if let Some(stale) = slot.replace(session.clone()) {
            // Best-effort release of the superseded QUIC connection. Per the
            // spec the server frees a session's UDP socket when the
            // connection dies, so no Dissociate is needed here.
            stale.conn.close(quinn::VarInt::from_u32(0), b"replaced");
        }
        Ok(session)
    }

    /// Establishes the QUIC connection and performs TUIC authentication.
    async fn establish(&self) -> Result<Arc<TuicSession>> {
        let server_addr = tokio::net::lookup_host((self.server.as_str(), self.port))
            .await?
            .next()
            .ok_or_else(|| {
                anyhow!("tuic [{}]: server '{}' resolved to no addresses", self.tag, self.server)
            })?;

        let bind = SocketAddr::new(
            if server_addr.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        );
        // socket2 + protect: on Android the fd must be protected before use or
        // the OS routes it through the VPN itself (same contract as the SS
        // outbound's TCP/UDP sockets).
        let socket =
            socket2::Socket::new(socket2::Domain::for_address(bind), socket2::Type::DGRAM, None)?;
        if !crate::protect_socket(socket.as_raw_fd()) {
            tracing::error!("⚠️ FAILED TO PROTECT SOCKET FD: {}", socket.as_raw_fd());
        }
        socket.set_nonblocking(true)?;
        socket.bind(&bind.into())?;
        let std_socket: std::net::UdpSocket = socket.into();

        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            std_socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(Self::client_config(self.insecure)?);

        let conn = endpoint
            .connect(server_addr, &self.sni)
            .map_err(|e| anyhow!("tuic [{}]: connect setup failed: {e}", self.tag))?
            .await
            .map_err(|e| anyhow!("tuic [{}]: QUIC handshake failed: {e}", self.tag))?;

        // Authentication TOKEN: TLS Keying Material Exporter over the live
        // session — label = client UUID, context = raw password (spec §3).
        let uuid_bytes = *self.uuid.as_bytes();
        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, &uuid_bytes, self.password.as_bytes())
            .map_err(|e| anyhow!("tuic [{}]: token export failed: {e:?}", self.tag))?;

        let mut uni = conn.open_uni().await?;
        uni.write_all(&wire::encode_authenticate(&uuid_bytes, &token)).await?;
        // FIN the auth stream; delivery rides QUIC's reliability. Per spec the
        // server may receive relaying commands in parallel and pauses them
        // until this stream authenticates.
        uni.finish()
            .map_err(|e| anyhow!("tuic [{}]: auth stream already closed: {e}", self.tag))?;

        Ok(Arc::new(TuicSession::spawn(conn, endpoint)))
    }

    /// Builds the QUIC client TLS configuration. The ring provider is pinned
    /// explicitly so selection never depends on process-global install state.
    fn client_config(insecure: bool) -> Result<quinn::ClientConfig> {
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?;
        let crypto = if insecure {
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
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            IDLE_TIMEOUT.try_into().map_err(|e| anyhow!("invalid idle timeout: {e}"))?,
        ));
        config.transport_config(Arc::new(transport));
        Ok(config)
    }
}

#[async_trait]
impl OutboundDialer for TuicOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// Opens a TCP relay: one bidirectional QUIC stream carrying the Connect
    /// header, then raw application bytes. No server reply exists for a
    /// Connect; rejection surfaces as stream reset/EOF after dial.
    async fn dial_stream(&self, context: SharedContext) -> Result<Box<dyn AsyncIoStream>> {
        let destination = {
            let ctx = context.lock();
            ctx.metadata.identity.destination.clone()
        };
        let session = self.session().await?;
        let (mut send, recv) = session.conn.open_bi().await.map_err(|e| {
            anyhow!("tuic [{}]: open relay stream to {destination} failed: {e}", self.tag)
        })?;
        let header = wire::encode_connect(&destination.addr, destination.port)?;
        send.write_all(&header).await?;
        debug!(
            "TUIC outbound [{}] relay opened to {} via {}:{} (QUIC)",
            self.tag, destination, self.server, self.port
        );
        Ok(Box::new(BiStream { send, recv }))
    }

    /// Sends one UDP datagram through the tunnel in `native` mode and waits
    /// the bounded reply window for the response from the same destination
    /// (RFC-012 G2). Oversized payloads are fragmented per spec.
    async fn send_packet(
        &self,
        context: SharedContext,
        payload: &[u8],
        _source: SocketAddr,
    ) -> Result<Vec<u8>> {
        {
            let mut ctx = context.lock();
            ctx.metadata.l4_protocol = L4Protocol::Udp;
        }
        let destination = {
            let ctx = context.lock();
            ctx.metadata.identity.destination.clone()
        };

        let session = self.session().await?;
        let max_datagram = session.conn.max_datagram_size().unwrap_or(DATAGRAM_FALLBACK);
        let pkt_id = session.next_pkt_id();
        let datagrams = wire::encode_fragments(
            session.assoc_id,
            pkt_id,
            &destination.addr,
            destination.port,
            payload,
            max_datagram,
        )?;
        for datagram in datagrams {
            session.conn.send_datagram_wait(Bytes::from(datagram)).await.map_err(|e| {
                anyhow!("tuic [{}]: UDP send to {destination} failed: {e}", self.tag)
            })?;
        }

        let deadline = Instant::now() + REPLY_WINDOW;
        loop {
            if let Some(reply) = session.take_reply(&destination).await {
                return Ok(reply);
            }
            if Instant::now() >= deadline || session.closed.load(Ordering::Relaxed) {
                // No reply in the window (loss or none expected) — the trait
                // contract maps this to an empty reply, never a hang.
                return Ok(Vec::new());
            }
            tokio::time::sleep(REPLY_POLL).await;
        }
    }
}

/// A live TUIC session: one authenticated QUIC connection, its association
/// ID, and the bounded inbound-reply demultiplexing queue.
struct TuicSession {
    conn: quinn::Connection,
    /// Held so the QUIC endpoint (and its socket) outlives every connection.
    #[allow(dead_code)] // liveness anchor; never dialed directly
    endpoint: quinn::Endpoint,
    assoc_id: u16,
    next_pkt_id: AtomicU16,
    closed: Arc<AtomicBool>,
    replies: ReplyQueue,
}

impl TuicSession {
    /// Spawns the session and its background tasks (datagram reader for
    /// replies, heartbeat keep-alive).
    fn spawn(conn: quinn::Connection, endpoint: quinn::Endpoint) -> Self {
        let mut assoc = [0u8; 2];
        OsRng.fill_bytes(&mut assoc);
        let closed = Arc::new(AtomicBool::new(false));

        // Datagram reader: every inbound Packet command becomes a queued
        // reply addressed by its responder. Third-party servers may
        // fragment UDP replies — reassembly is bounded per protocol-rules
        // §13. Malformed or non-Packet datagrams are dropped (only lengths
        // are logged, never contents).
        let reader_conn = conn.clone();
        let reader_closed = closed.clone();
        let session_replies = Arc::new(tokio::sync::Mutex::new(VecDeque::new()));
        let pump_replies = session_replies.clone();
        tokio::spawn(async move {
            let mut reassembler = wire::FragmentReassembler::new(REPLY_REASSEMBLY_CAP);
            loop {
                match reader_conn.read_datagram().await {
                    Ok(dgram) => match wire::decode_packet(&dgram) {
                        Ok(cmd) => match reassembler.accept(&cmd) {
                            wire::Reassemble::Complete { address: Some(address), payload } => {
                                let mut q = pump_replies.lock().await;
                                if q.len() >= REPLY_QUEUE_CAP {
                                    q.pop_front();
                                    debug!("tuic: reply queue full, dropped oldest reply");
                                }
                                q.push_back((address.host, address.port, payload));
                            }
                            wire::Reassemble::Pending
                            | wire::Reassemble::Rejected
                            | wire::Reassemble::Complete { address: None, .. } => {}
                        },
                        Err(_) => {
                            debug!("tuic: ignored non-conforming datagram ({} bytes)", dgram.len())
                        }
                    },
                    Err(_) => {
                        reader_closed.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });

        // Heartbeat keep-alive while the session lives.
        let hb_conn = conn.clone();
        let hb_closed = closed.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(HEARTBEAT_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                match hb_conn
                    .send_datagram(Bytes::from_static(&[wire::VERSION, wire::CMD_HEARTBEAT]))
                {
                    Ok(()) => {}
                    // Every error variant (unsupported/disabled/too-large/
                    // connection-lost) is terminal for a native-mode session.
                    Err(_) => {
                        hb_closed.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });

        Self {
            conn,
            endpoint,
            assoc_id: u16::from_be_bytes(assoc),
            next_pkt_id: AtomicU16::new(0),
            closed,
            replies: session_replies,
        }
    }

    /// Allocates the next Packet identifier for reassembly tagging.
    fn next_pkt_id(&self) -> u16 {
        self.next_pkt_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Removes and returns the oldest queued reply from the requested
    /// responder, if one has arrived.
    async fn take_reply(&self, destination: &Endpoint) -> Option<Vec<u8>> {
        let mut q = self.replies.lock().await;
        let idx = q
            .iter()
            .position(|(host, port, _)| *host == destination.addr && *port == destination.port)?;
        q.remove(idx).map(|(_, _, payload)| payload)
    }
}

/// Bidirectional QUIC stream exposed as a single `AsyncRead + AsyncWrite`
/// value so it can flow through the engine's `AsyncIoStream` seam. Shared
/// with the server-side inbound (`transport::inbound::tuic`), which hands
/// relay streams to the engine the same way.
pub(crate) struct BiStream {
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
}

impl AsyncRead for BiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for BiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Fully qualified: quinn's inherent `poll_write` (WriteError) would
        // otherwise shadow the tokio trait method (io::Error).
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

/// Certificate verifier that accepts everything — ONLY for `insecure: true`
/// (self-signed edge certificates). The explicit type name keeps the risky
/// mode greppable and impossible to enable silently (same pattern as the
/// Trojan outbound).
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
