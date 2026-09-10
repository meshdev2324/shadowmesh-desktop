use crate::engine::context::{ConnectionContext, SharedContext};
use crate::engine::metadata::{Addr, ConnectionMetadata, Endpoint};
use crate::transport::reality_tls::RealityTlsStream;
use crate::transport::traits::{AsyncIoStream, OutboundDialer};
use crate::{RealityConfig, ShadowMeshError, VmessConfig};
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use hmac::Hmac;
use md5::{Digest, Md5};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::debug;
use uuid::Uuid;

// --- VLESS Independent Implementation ---

/// Persistent UDP-over-TCP tunnel state for VlessOutbound.
type UdpTunnelSlot = Arc<tokio::sync::Mutex<Option<Box<dyn AsyncIoStream>>>>;

pub struct VlessOutbound {
    tag: String,
    server: String,
    port: u16,
    uuid: Uuid,
    flow: String,
    /// Live REALITY config (RFC-015 §4.3): when present, the session runs
    /// over a REALITY-authenticated TLS 1.3 stream.
    reality_config: Option<RealityConfig>,
    /// Lazily-established cmd=0x02 tunnel carrying length-prefixed UDP
    /// frames; one per outbound because VLESS multiplexes the client's UDP
    /// destinations over a single stream.
    udp_tunnel: UdpTunnelSlot,
}

impl VlessOutbound {
    pub fn new(
        tag: String,
        server: String,
        port: u16,
        uuid_str: &str,
        flow: String,
        reality_config: Option<RealityConfig>,
    ) -> Result<Self> {
        let uuid = Uuid::parse_str(uuid_str)?;
        Ok(Self {
            tag,
            server,
            port,
            uuid,
            flow,
            reality_config,
            udp_tunnel: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }
}

#[async_trait]
impl OutboundDialer for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, context: SharedContext) -> Result<Box<dyn AsyncIoStream>> {
        let (destination, l4_protocol) = {
            let ctx = context.lock();
            (ctx.metadata.identity.destination.clone(), ctx.metadata.l4_protocol)
        };

        debug!(
            "VLESS outbound [{}] connecting to {} via {}:{}",
            self.tag, destination, self.server, self.port
        );

        let tcp = TcpStream::connect(format!("{}:{}", self.server, self.port)).await?;
        // RFC-015 §4.3: REALITY-configured sessions are encrypted end to end
        // (TLS 1.3 with session_id authentication); plaintext remains only
        // for configs without a reality block (loopback/testing).
        let mut stream: Box<dyn crate::transport::traits::AsyncIoStream> =
            match &self.reality_config {
                Some(rc) => Box::new(
                    RealityTlsStream::connect(tcp, &rc.public_key, &rc.short_id, &rc.sni_target)
                        .await
                        .map_err(|e| anyhow!("VLESS REALITY handshake failed: {e}"))?,
                ),
                None => Box::new(tcp),
            };

        // Command per public VLESS spec: 0x01 = TCP connect, 0x02 = UDP.
        // The context's L4 protocol decides; default stays TCP for
        // compatibility with callers that never set it.
        let cmd: u8 = match l4_protocol {
            crate::engine::metadata::L4Protocol::Udp => 0x02,
            _ => 0x01,
        };

        let mut header = Vec::with_capacity(32);
        header.push(0x00); // Version 0
        header.extend_from_slice(self.uuid.as_bytes());

        if !self.flow.is_empty() {
            header.push(self.flow.len() as u8);
            header.extend_from_slice(self.flow.as_bytes());
        } else {
            header.push(0x00);
        }

        header.push(cmd);
        header.extend_from_slice(&destination.port.to_be_bytes());

        match &destination.addr {
            Addr::Ip(IpAddr::V4(ip)) => {
                header.push(0x01);
                header.extend_from_slice(&ip.octets());
            }
            Addr::Ip(IpAddr::V6(ip)) => {
                header.push(0x04);
                header.extend_from_slice(&ip.octets());
            }
            Addr::Domain(domain) => {
                header.push(0x03);
                header.push(domain.len() as u8);
                header.extend_from_slice(domain.as_bytes());
            }
        }

        stream.write_all(&header).await?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response[0] != 0 {
            return Err(anyhow!("VLESS server returned error version: {}", response[0]));
        }
        if response[1] > 0 {
            let mut addons = vec![0u8; response[1] as usize];
            stream.read_exact(&mut addons).await?;
        }

        if cmd == 0x02 {
            // UDP mode: the raw TCP stream carries length-prefixed packet
            // frames ([u16 BE len][payload]) driven by send_packet; the
            // engine's reply path reads the symmetric framing.
            Ok(Box::new(stream))
        } else {
            Ok(Box::new(stream))
        }
    }

    async fn send_packet(
        &self,
        context: SharedContext,
        payload: &[u8],
        _source: SocketAddr,
    ) -> Result<Vec<u8>> {
        // One persistent UDP tunnel per outbound instance; each send_packet
        // call frames [u16 len][payload] onto it. VLESS multiplexes all UDP
        // destinations of one client over a single tunnel stream.
        // Establish lazily, flagging UDP mode on the context first. The
        // parking_lot guard is scoped before any await (it is not Send).
        {
            let mut ctx = context.lock();
            ctx.metadata.l4_protocol = crate::engine::metadata::L4Protocol::Udp;
        }

        let mut tunnel_slot = self.udp_tunnel.lock().await;
        if tunnel_slot.is_none() {
            *tunnel_slot = Some(self.dial_stream(context.clone()).await?);
        }

        let stream = tunnel_slot.as_mut().ok_or_else(|| anyhow!("VLESS UDP tunnel unavailable"))?;

        use tokio::io::AsyncWriteExt;
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        stream.write_all(&frame).await?;
        stream.flush().await?;
        // Replies arrive on the tunnel stream; the engine's reply plumbing
        // (G2 phase 2) reads them from the session, not from this call.
        Ok(Vec::new())
    }
}

// --- VMess Independent Implementation (RFC-010) ---

pub struct VmessOutbound {
    pub tag: String,
    server: String,
    port: u16,
    uuid: Uuid,
    security: String,
}

impl VmessOutbound {
    pub fn new(
        tag: String,
        server: String,
        port: u16,
        uuid_str: &str,
        security: String,
    ) -> Result<Self> {
        let uuid = Uuid::parse_str(uuid_str)?;
        Ok(Self { tag, server, port, uuid, security })
    }

    fn generate_auth_id(&self, timestamp: i64) -> Result<[u8; 16]> {
        use aes::cipher::KeyInit;
        use hmac::Mac;
        let mut hmac: Hmac<Md5> = KeyInit::new_from_slice(self.uuid.as_bytes())
            .map_err(|e| anyhow!("HMAC-MD5 auth id key init failed: {}", e))?;
        hmac.update(&timestamp.to_be_bytes());
        let result = hmac.finalize().into_bytes();
        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&result);
        Ok(auth_id)
    }

    fn get_header_crypto_params(&self, timestamp: i64) -> ([u8; 16], [u8; 16]) {
        let mut key_md5 = Md5::new();
        key_md5.update(self.uuid.as_bytes());
        key_md5.update(b"c4861939-ed4a-43f6-932c-354924a4f89d");
        let key = key_md5.finalize().into();

        let mut iv_md5 = Md5::new();
        let ts_bytes = (timestamp as u64).wrapping_mul(4).to_be_bytes();
        for _ in 0..4 {
            iv_md5.update(ts_bytes);
        }
        let iv = iv_md5.finalize().into();

        (key, iv)
    }
}

#[async_trait]
impl OutboundDialer for VmessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, context: SharedContext) -> Result<Box<dyn AsyncIoStream>> {
        let destination = {
            let ctx = context.lock();
            ctx.metadata.identity.destination.clone()
        };

        debug!(
            "VMess outbound [{}] connecting to {} via {}:{}",
            self.tag, destination, self.server, self.port
        );

        let mut stream = TcpStream::connect(format!("{}:{}", self.server, self.port)).await?;

        let now = chrono::Utc::now().timestamp();
        let auth_id = self.generate_auth_id(now)?;
        let (key, iv) = self.get_header_crypto_params(now);

        let mut header = Vec::with_capacity(128);
        header.push(0x01); // Version 1

        // Per-connection AEAD material: CSPRNG (OS entropy). Predictable
        // IV/keys here would break VMess session confidentiality outright.
        let request_iv: [u8; 16] = crate::secure_random_bytes(16)
            .and_then(|v| <[u8; 16]>::try_from(v).ok())
            .ok_or_else(|| anyhow!("OS entropy source failed for VMess IV"))?;
        let request_key: [u8; 16] = crate::secure_random_bytes(16)
            .and_then(|v| <[u8; 16]>::try_from(v).ok())
            .ok_or_else(|| anyhow!("OS entropy source failed for VMess key"))?;

        header.extend_from_slice(&request_iv);
        header.extend_from_slice(&request_key);
        header.push(0x00); // Response Header Hash
        header.push(0x01); // Option: ChunkStream

        let security_type = match self.security.as_str() {
            "aes-128-gcm" => 0x03,
            "chacha20-poly1305" => 0x04,
            _ => 0x02,
        };
        header.push(security_type); // P/S nibble: padding length is 0 (see below)
        header.push(0x00); // Reserved
        header.push(0x01); // Command: TCP

        header.extend_from_slice(&destination.port.to_be_bytes());
        match &destination.addr {
            Addr::Ip(IpAddr::V4(ip)) => {
                header.push(0x01);
                header.extend_from_slice(&ip.octets());
            }
            Addr::Ip(IpAddr::V6(ip)) => {
                header.push(0x04);
                header.extend_from_slice(&ip.octets());
            }
            Addr::Domain(domain) => {
                header.push(0x03);
                header.push(domain.len() as u8);
                header.extend_from_slice(domain.as_bytes());
            }
        }

        // v6.9.21: Finalize VMess Header with HMAC-MD5 Checksum (Standard)
        // Fixed padding for deterministic testing (RFC-010 Integration). The
        // P/S byte at index 35 encodes (padding_len << 4) | security_type and
        // the padding bytes trail the address field.
        let padding_len = 0u8;
        if padding_len > 0 {
            header.extend_from_slice(&vec![0u8; padding_len as usize]);
        }

        use hmac::Mac;
        let mut hmac: Hmac<Md5> = KeyInit::new_from_slice(&key)
            .map_err(|e| anyhow!("HMAC-MD5 header checksum key init failed: {}", e))?;
        hmac.update(&header);
        let checksum = hmac.finalize().into_bytes();
        header.extend_from_slice(&checksum[..4]);

        let cipher = Aes128::new(&key.into());
        let mut encrypted_header = header.clone();
        let mut feedback = iv;
        for byte in encrypted_header.iter_mut() {
            let mut block = feedback;
            cipher.encrypt_block((&mut block).into());
            *byte ^= block[0];
            feedback.rotate_left(1);
            feedback[15] = *byte;
        }

        let mut packet = Vec::with_capacity(auth_id.len() + encrypted_header.len());
        packet.extend_from_slice(&auth_id);
        packet.extend_from_slice(&encrypted_header);

        stream.write_all(&packet).await?;

        Ok(Box::new(VmessStream::new(stream, request_key, request_iv)?))
    }

    async fn send_packet(
        &self,
        _context: SharedContext,
        _payload: &[u8],
        _source: SocketAddr,
    ) -> Result<Vec<u8>> {
        Err(anyhow!("VMess UDP not implemented"))
    }
}

pub struct VmessStream<S> {
    inner: S,
    sealing_key: LessSafeKey,
    opening_key: LessSafeKey,
    read_buf: BytesMut,
    payload_buf: BytesMut,
    write_buf: BytesMut,
    /// Chunk size of the in-flight frame whose bytes are still in `write_buf`.
    /// `Some(n)` means: drain `write_buf`, then report `Ready(Ok(n))`. Never
    /// re-encrypt a frame while a previous one is still in flight — that would
    /// duplicate the payload on the wire when `write_all` retries.
    pending_chunk_size: Option<usize>,
    write_seq: u64,
    read_seq: u64,
    reading_length: bool,
    remaining_payload: usize,
}

impl<S> VmessStream<S> {
    pub fn new(inner: S, key: [u8; 16], _iv: [u8; 16]) -> Result<Self> {
        let unbound_send = UnboundKey::new(&AES_128_GCM, &key)
            .map_err(|e| anyhow!("VMess AEAD send key init failed: {}", e))?;
        let unbound_recv = UnboundKey::new(&AES_128_GCM, &key)
            .map_err(|e| anyhow!("VMess AEAD recv key init failed: {}", e))?;

        Ok(Self {
            inner,
            sealing_key: LessSafeKey::new(unbound_send),
            opening_key: LessSafeKey::new(unbound_recv),
            read_buf: BytesMut::with_capacity(4096),
            payload_buf: BytesMut::with_capacity(4096),
            write_buf: BytesMut::with_capacity(4096),
            pending_chunk_size: None,
            write_seq: 0,
            read_seq: 0,
            reading_length: true,
            remaining_payload: 0,
        })
    }

    fn next_nonce(&self, seq: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&seq.to_be_bytes());
        Nonce::assume_unique_for_key(nonce_bytes)
    }
}

const VMESS_TAG_SIZE: usize = 16;
const MAX_VMESS_CHUNK: usize = 16384;

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if !this.payload_buf.is_empty() {
            let n = std::cmp::min(this.payload_buf.len(), buf.remaining());
            buf.put_slice(&this.payload_buf[..n]);
            this.payload_buf.advance(n);
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.reading_length {
                let needed = 2 + VMESS_TAG_SIZE;
                if this.read_buf.len() < needed {
                    let mut temp = [0u8; 4096];
                    let mut rb = ReadBuf::new(&mut temp);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            if rb.filled().is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            this.read_buf.extend_from_slice(rb.filled());
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let mut length_chunk = this.read_buf.split_to(needed);
                let nonce = this.next_nonce(this.read_seq);
                let decrypted = this
                    .opening_key
                    .open_in_place(nonce, Aad::empty(), &mut length_chunk)
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "VMess length decryption failed",
                        )
                    })?;

                this.remaining_payload = u16::from_be_bytes([decrypted[0], decrypted[1]]) as usize;
                if this.remaining_payload > MAX_VMESS_CHUNK {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "VMess chunk too large",
                    )));
                }
                this.reading_length = false;
            } else {
                let needed = this.remaining_payload + VMESS_TAG_SIZE;
                if this.read_buf.len() < needed {
                    let mut temp = [0u8; 4096];
                    let mut rb = ReadBuf::new(&mut temp);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            if rb.filled().is_empty() {
                                return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
                            }
                            this.read_buf.extend_from_slice(rb.filled());
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let mut payload_chunk = this.read_buf.split_to(needed);
                let nonce = this.next_nonce(this.read_seq);
                this.read_seq += 1;
                let decrypted = this
                    .opening_key
                    .open_in_place(nonce, Aad::empty(), &mut payload_chunk)
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "VMess payload decryption failed",
                        )
                    })?;

                this.payload_buf.extend_from_slice(decrypted);
                this.reading_length = true;

                let n = std::cmp::min(this.payload_buf.len(), buf.remaining());
                buf.put_slice(&this.payload_buf[..n]);
                this.payload_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // In-flight frame from a previous poll_write: drain it fully, then
        // report the size accepted for THAT write. Never re-encrypt.
        if let Some(pending_chunk) = this.pending_chunk_size {
            while !this.write_buf.is_empty() {
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                    Poll::Ready(Ok(n)) => this.write_buf.advance(n),
                    Poll::Ready(Err(e)) => {
                        this.pending_chunk_size = None;
                        this.write_buf.clear();
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            this.pending_chunk_size = None;
            return Poll::Ready(Ok(pending_chunk));
        }

        let chunk_size = std::cmp::min(buf.len(), MAX_VMESS_CHUNK);
        let nonce_len = this.next_nonce(this.write_seq);
        let nonce_payload = this.next_nonce(this.write_seq);
        this.write_seq += 1;

        let mut length_data = (chunk_size as u16).to_be_bytes().to_vec();
        let tag = this
            .sealing_key
            .seal_in_place_separate_tag(nonce_len, Aad::empty(), &mut length_data)
            .map_err(|_| std::io::Error::other("VMess length encryption failed"))?;
        this.write_buf.extend_from_slice(&length_data);
        this.write_buf.extend_from_slice(tag.as_ref());

        let mut payload_data = buf[..chunk_size].to_vec();
        let tag = this
            .sealing_key
            .seal_in_place_separate_tag(nonce_payload, Aad::empty(), &mut payload_data)
            .map_err(|_| std::io::Error::other("VMess payload encryption failed"))?;
        this.write_buf.extend_from_slice(&payload_data);
        this.write_buf.extend_from_slice(tag.as_ref());

        // Push the whole frame; if the transport cannot take it all, mark the
        // frame in-flight and report Pending. The next call drains the rest and
        // then reports Ready(Ok(chunk_size)) — the AsyncWrite contract holds:
        // success is only ever reported for fully written frames.
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => this.write_buf.advance(n),
                Poll::Ready(Err(e)) => {
                    this.write_buf.clear();
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    this.pending_chunk_size = Some(chunk_size);
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(chunk_size))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => this.write_buf.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// --- VMess AsyncTransport Implementation ---

pub struct VmessTransport {
    config: VmessConfig,
    _priv_key: [u8; 32],
    _pub_key: [u8; 32],
    active_stream: Arc<Mutex<Option<Box<dyn AsyncIoStream>>>>,
}

impl VmessTransport {
    pub fn new(config: VmessConfig, priv_key: [u8; 32], pub_key: [u8; 32]) -> Self {
        Self {
            config,
            _priv_key: priv_key,
            _pub_key: pub_key,
            active_stream: Arc::new(Mutex::new(None)),
        }
    }
}

impl std::fmt::Debug for VmessTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessTransport").field("config", &self.config).finish()
    }
}

#[async_trait]
impl crate::transport::AsyncTransport for VmessTransport {
    fn transport_type(&self) -> crate::transport::TransportType {
        crate::transport::TransportType::Reality // RFC-010: Escalates to Reality metadata
    }

    async fn connect(&self) -> Result<(), ShadowMeshError> {
        let outbound = VmessOutbound::new(
            "vmess-out".into(),
            self.config.server.clone(),
            self.config.port as u16,
            &self.config.uuid,
            self.config.security.clone(),
        )
        .map_err(|e| ShadowMeshError::Other(e.to_string()))?;

        let metadata = ConnectionMetadata::new(Endpoint::new_domain("google.com".into(), 443));
        let context = Arc::new(parking_lot::Mutex::new(ConnectionContext::new(metadata)));

        let stream =
            outbound.dial_stream(context).await.map_err(|_| ShadowMeshError::ConnectionFailed)?;

        let mut guard = self.active_stream.lock().await;
        *guard = Some(stream);
        Ok(())
    }

    async fn send(&self, data: Bytes) -> Result<(), ShadowMeshError> {
        let mut guard = self.active_stream.lock().await;
        if let Some(ref mut stream) = *guard {
            stream.write_all(&data).await.map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
            stream.flush().await.map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
            Ok(())
        } else {
            Err(ShadowMeshError::Other("VMess not connected".into()))
        }
    }

    async fn recv(&self) -> Result<Bytes, ShadowMeshError> {
        let mut guard = self.active_stream.lock().await;
        if let Some(ref mut stream) = *guard {
            let mut buf = [0u8; 2048];
            let n =
                stream.read(&mut buf).await.map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
            Ok(Bytes::copy_from_slice(&buf[..n]))
        } else {
            Err(ShadowMeshError::Other("VMess not connected".into()))
        }
    }

    async fn close(&self) -> Result<(), ShadowMeshError> {
        let mut guard = self.active_stream.lock().await;
        if let Some(mut stream) = guard.take() {
            let _ = stream.shutdown().await;
        }
        Ok(())
    }
}
