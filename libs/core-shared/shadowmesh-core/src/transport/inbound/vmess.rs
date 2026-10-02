use crate::engine::context::ConnectionContext;
use crate::engine::metadata::{ConnectionMetadata, Endpoint, HandshakeState, L4Protocol};
use crate::engine::{events::EngineEvent, EngineHandle};
use crate::transport::traits::InboundListener;
use crate::RealityServerConfig;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};
use parking_lot::Mutex;
/// Implementation Source:
/// - RFC / specification: VLESS Protocol (Public Specification)
/// - Relevant sections: Handshake (Header Parsing), Command handling.
/// - Security considerations: Secure UUID validation, robust parsing of variable length addons and addresses.
use std::sync::Arc;
use subtle::ConstantTimeEq as _;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// VLESS Inbound handler with independent protocol parsing and Active Probing Resistance.
pub struct VlessInbound {
    tag: String,
    listen_addr: String,
    uuid: Uuid,
    engine: EngineHandle,
    reality_config: Option<RealityServerConfig>,
    decoy_target: String,
}

impl VlessInbound {
    pub fn new(
        tag: String,
        listen_addr: String,
        uuid_str: &str,
        engine: EngineHandle,
        reality_config: Option<RealityServerConfig>,
        decoy_target: Option<String>,
    ) -> Result<Self> {
        let uuid = Uuid::parse_str(uuid_str)?;
        let decoy_target = decoy_target.unwrap_or_else(|| "www.google.com:443".to_string());
        Ok(Self { tag, listen_addr, uuid, engine, reality_config, decoy_target })
    }

    async fn handle_connection(&self, mut stream: tokio::net::TcpStream) -> Result<()> {
        let peer = stream.peer_addr().ok();
        // RFC-015 §4.2: with REALITY configured, the TLS 1.3 REALITY
        // handshake gates everything; failures are transparently relayed to
        // the masquerade target (active probing resistance). Without it,
        // the plaintext VLESS path falls back to the decoy.
        if let Some(ref reality) = self.reality_config {
            match crate::transport::reality_server::accept(stream, reality).await {
                crate::transport::reality_server::Accepted::Stream(reality_stream) => {
                    let mut boxed: Box<dyn crate::transport::traits::AsyncIoStream> =
                        Box::new(reality_stream);
                    match read_vless_request(&mut boxed).await? {
                        Some(VlessRead::Request { request, remaining, .. })
                            if uuid_eq(&request.uuid, &self.uuid) =>
                        {
                            return self.handle_established(boxed, request, remaining, peer).await;
                        }
                        Some(_) => {
                            // Authenticated at the REALITY layer but wrong
                            // UUID or garbage: close silently (already
                            // indistinguishable from a TLS session).
                            debug!("VLESS auth failed inside REALITY session — closing");
                            return Ok(());
                        }
                        None => return Ok(()),
                    }
                }
                crate::transport::reality_server::Accepted::Fallback(sock, buffered) => {
                    return self
                        .fallback_proxy_with_initial_data(sock, &reality.sni_target, &buffered)
                        .await;
                }
            }
        }

        match read_vless_request(&mut stream).await? {
            Some(VlessRead::Request { request, remaining, .. })
                if uuid_eq(&request.uuid, &self.uuid) =>
            {
                self.handle_established(stream, request, remaining, peer).await
            }
            Some(read) => {
                warn!("VLESS probe rejected (invalid UUID or garbage) — falling back to decoy");
                self.fallback_proxy_with_initial_data(stream, &self.decoy_target, read.consumed())
                    .await
            }
            None => Ok(()),
        }
    }

    /// Post-handshake dispatch: cmd=1 → engine stream, cmd=2 → persistent
    /// UDP session relay (WireGuard-over-VLESS, RFC-015 §4.2).
    async fn handle_established<S>(
        &self,
        mut stream: S,
        request: VlessRequest,
        remaining: Vec<u8>,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<()>
    where
        S: crate::transport::traits::AsyncIoStream,
    {
        let mut metadata = ConnectionMetadata::new(request.destination.clone());
        metadata.l4_protocol = if request.cmd == 1 { L4Protocol::Tcp } else { L4Protocol::Udp };
        metadata.identity.source = peer.map(Endpoint::from);
        metadata.environment.inbound_tag = Some(self.tag.clone());
        metadata.handshake = HandshakeState::Established;

        stream.write_all(&[0, 0]).await?;

        let context = Arc::new(Mutex::new(ConnectionContext::new(metadata)));

        if request.cmd == 1 {
            let final_stream: Box<dyn crate::transport::traits::AsyncIoStream> = if remaining
                .is_empty()
            {
                Box::new(stream)
            } else {
                Box::new(crate::transport::inbound::http::PrefixedStream::new(remaining, stream))
            };
            self.engine
                .send_event(EngineEvent::NewStream { context, stream: final_stream })
                .await?;
        } else if request.cmd == 2 {
            // Persistent UDP session: one socket per stream, frames both
            // ways ([u16 BE len][payload]). The destination here is the
            // node-local WireGuard endpoint for the REALITY tier.
            udp_relay_session(stream, request.destination).await?;
        } else {
            return Err(anyhow!("unsupported VLESS command {}", request.cmd));
        }
        Ok(())
    }

    async fn fallback_proxy_with_initial_data(
        &self,
        mut client_stream: TcpStream,
        target: &str,
        initial_data: &[u8],
    ) -> Result<()> {
        debug!("Proxying connection to fallback target: {} with initial data", target);
        let target_addr =
            if target.contains(':') { target.to_string() } else { format!("{}:443", target) };
        let mut target_stream = TcpStream::connect(target_addr).await?;
        target_stream.write_all(initial_data).await?;
        copy_bidirectional(&mut client_stream, &mut target_stream).await?;
        Ok(())
    }
}

/// Outcome of the handshake read phase.
enum VlessRead {
    /// A valid VLESS request plus its framing context.
    Request { request: VlessRequest, remaining: Vec<u8>, consumed: Vec<u8> },
    /// Garbage or an incomplete probe — `consumed` carries every byte seen
    /// so the caller can relay them to the decoy (probing resistance).
    Garbage { consumed: Vec<u8> },
}

impl VlessRead {
    /// Every byte consumed from the wire (for decoy re-injection).
    fn consumed(&self) -> &[u8] {
        match self {
            VlessRead::Request { consumed, .. } | VlessRead::Garbage { consumed } => consumed,
        }
    }
}

/// Per-read window for the handshake phase: a legit client completes its
/// header in milliseconds; a silent prober must not pin the task forever.
const HANDSHAKE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Constant-time VLESS UUID comparison: `uuid::Uuid`'s derived `PartialEq`
/// short-circuits on the first differing byte, leaking a prefix-match
/// oracle through timing. Both sides are `[u8; 16]`, so the
/// `subtle::ConstantTimeEq` comparison runs a fixed number of branchless
/// byte comparisons regardless of where the values differ.
fn uuid_eq(a: &Uuid, b: &Uuid) -> bool {
    let x: [u8; 16] = *a.as_bytes();
    let y: [u8; 16] = *b.as_bytes();
    bool::from(x.ct_eq(&y))
}

/// Loop-reads a VLESS handshake (RFC-015 F3): a header split across TCP
/// segments accumulates instead of failing. Oversized garbage and read
/// timeouts both resolve to [`VlessRead::Garbage`] with the consumed bytes.
async fn read_vless_request<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Option<VlessRead>> {
    const MAX_HEADER: usize = 512;
    let mut acc: Vec<u8> = Vec::with_capacity(256);
    let mut chunk = [0u8; 1024];
    loop {
        if let Ok((remaining, request)) = parse_vless_handshake(&acc) {
            return Ok(Some(VlessRead::Request {
                request,
                remaining: remaining.to_vec(),
                consumed: acc.clone(),
            }));
        }
        if acc.len() >= MAX_HEADER {
            return Ok(Some(VlessRead::Garbage { consumed: acc }));
        }
        let n = match tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, stream.read(&mut chunk)).await {
            Ok(n) => n?,
            Err(_) => return Ok(Some(VlessRead::Garbage { consumed: acc })),
        };
        if n == 0 {
            return Ok(None);
        }
        acc.extend_from_slice(&chunk[..n]);
    }
}

/// One iteration outcome of the UDP relay select loop.
enum RelayEvent {
    /// A frame flowed in either direction; keep the session alive.
    Progress,
    /// Client closed the session or the socket reported a terminal error.
    Closed,
}

/// Relays one VLESS cmd=2 session: [u16 BE len][payload] frames over the
/// stream to/from a UDP socket bound for the requested destination.
///
/// Idle timeout: each loop iteration wraps the `select!` in a fresh 60s
/// deadline. A `Sleep` pinned with `tokio::pin!` cannot be reset, so the
/// deadline is re-created every iteration instead — any frame exchange in
/// either direction restarts the window, and a silent client can never
/// pin this session (and its task/socket) forever.
async fn udp_relay_session<S>(mut stream: S, dest: Endpoint) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    const UDP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    let addr: std::net::SocketAddr = match &dest.addr {
        crate::engine::metadata::Addr::Ip(ip) => std::net::SocketAddr::new(*ip, dest.port),
        crate::engine::metadata::Addr::Domain(domain) => {
            tokio::net::lookup_host((domain.as_str(), dest.port))
                .await?
                .next()
                .ok_or_else(|| anyhow!("VLESS UDP: cannot resolve {domain}"))?
        }
    };
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(addr).await?;
    debug!("VLESS UDP session opened to {}", addr);

    let mut net_buf = vec![0u8; 65535];
    loop {
        let step = tokio::time::timeout(UDP_IDLE_TIMEOUT, async {
            let outcome: std::io::Result<RelayEvent> = tokio::select! {
                frame = read_udp_frame(&mut stream) => match frame {
                    Some(payload) => {
                        sock.send(&payload).await?;
                        Ok(RelayEvent::Progress)
                    }
                    None => Ok(RelayEvent::Closed), // client closed the session
                },
                r = sock.recv(&mut net_buf) => match r {
                    Ok(n) => {
                        stream.write_all(&(n as u16).to_be_bytes()).await?;
                        stream.write_all(&net_buf[..n]).await?;
                        stream.flush().await?;
                        Ok(RelayEvent::Progress)
                    }
                    Err(_) => Ok(RelayEvent::Closed),
                },
            };
            outcome
        })
        .await;

        match step {
            Ok(Ok(RelayEvent::Progress)) => {} // activity: restart the 60s window
            Ok(Ok(RelayEvent::Closed)) => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_elapsed) => {
                // 60s with no frame in either direction: drop the idle session.
                debug!("VLESS UDP session to {} idle-timeout after 60s", addr);
                break;
            }
        }
    }
    Ok(())
}

/// Reads one [u16 BE len][payload] frame; `None` on clean stream EOF.
async fn read_udp_frame<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt as _;
    let mut len_buf = [0u8; 2];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(_) => return None,
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Some(Vec::new());
    }
    let mut payload = vec![0u8; len];
    match stream.read_exact(&mut payload).await {
        Ok(_) => Some(payload),
        Err(_) => None,
    }
}

#[async_trait]
impl InboundListener for VlessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!("VLESS inbound {} listening on {}", self.tag, self.listen_addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let tag = self.tag.clone();
            let uuid = self.uuid;
            let engine = self.engine.clone();
            let reality_config = self.reality_config.clone();
            let decoy_target = self.decoy_target.clone();

            tokio::spawn(async move {
                let handler = VlessInbound {
                    tag,
                    listen_addr: String::new(),
                    uuid,
                    engine,
                    reality_config,
                    decoy_target,
                };
                if let Err(e) = handler.handle_connection(stream).await {
                    error!("VLESS connection handling failed: {:?}", e);
                }
            });
        }
    }
}

// --- Independent VLESS Handshake Parser ---

pub struct VlessRequest {
    pub uuid: Uuid,
    pub cmd: u8,
    pub destination: Endpoint,
}

pub fn parse_vless_handshake(input: &[u8]) -> IResult<&[u8], VlessRequest> {
    let (input, ver) = be_u8(input)?;
    if ver != 0 {
        return Err(nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Tag)));
    }

    let (input, uuid_bytes) = take(16usize)(input)?;
    let uuid = Uuid::from_slice(uuid_bytes).map_err(|_| {
        nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
    })?;

    let (input, addons_len) = be_u8(input)?;
    let (input, _addons) = take(addons_len)(input)?;

    let (input, cmd) = be_u8(input)?;
    let (input, port) = be_u16(input)?;
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

    Ok((input, VlessRequest { uuid, cmd, destination: Endpoint { addr, port } }))
}

pub struct VmessInbound {
    tag: String,
    listen_addr: String,
    uuid: Uuid,
    engine: EngineHandle,
}

pub struct VmessRequestHeader {
    pub version: u8,
    pub request_iv: [u8; 16],
    pub request_key: [u8; 16],
    pub response_header_hash: u8,
    pub option: u8,
    pub padding_len: u8,
    pub security_type: u8,
    pub reserved: u8,
    pub cmd: u8,
    pub port: u16,
    pub destination: Endpoint,
}

pub fn parse_vmess_header(input: &[u8]) -> IResult<&[u8], VmessRequestHeader> {
    let (input, version) = be_u8(input)?;
    let (input, request_iv_raw) = take(16usize)(input)?;
    let (input, request_key_raw) = take(16usize)(input)?;
    let (input, response_header_hash) = be_u8(input)?;
    let (input, option) = be_u8(input)?;
    let (input, p_s) = be_u8(input)?;
    let padding_len = p_s >> 4;
    let security_type = p_s & 0x0F;
    let (input, reserved) = be_u8(input)?;
    let (input, cmd) = be_u8(input)?;
    let (input, port) = be_u16(input)?;
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

    let mut request_iv = [0u8; 16];
    request_iv.copy_from_slice(request_iv_raw);
    let mut request_key = [0u8; 16];
    request_key.copy_from_slice(request_key_raw);

    Ok((
        input,
        VmessRequestHeader {
            version,
            request_iv,
            request_key,
            response_header_hash,
            option,
            padding_len,
            security_type,
            reserved,
            cmd,
            port,
            destination: Endpoint { addr, port },
        },
    ))
}

impl VmessInbound {
    pub fn new(
        tag: String,
        listen_addr: String,
        uuid_str: &str,
        engine: EngineHandle,
    ) -> Result<Self> {
        let uuid = Uuid::parse_str(uuid_str)?;
        Ok(Self { tag, listen_addr, uuid, engine })
    }
}

#[async_trait]
impl InboundListener for VmessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!("VMess inbound {} listening on {}", self.tag, self.listen_addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let tag = self.tag.clone();
            let uuid = self.uuid;
            let engine = self.engine.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_vmess_connection(stream, tag, uuid, engine).await {
                    error!("VMess connection handling failed: {:?}", e);
                }
            });
        }
    }
}

async fn handle_vmess_connection(
    mut stream: TcpStream,
    tag: String,
    uuid: Uuid,
    engine: EngineHandle,
) -> Result<()> {
    // v6.9.26: Independent VMess Inbound Handshake (Standard Compliance)

    // Slowloris guard (mirrors the VLESS `read_vless_request` window): every
    // pre-auth read is capped at 5s. A dribbling prober otherwise pins one
    // task (and its buffers) per connection for as long as it cares to wait.
    const VMESS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    macro_rules! timed_read {
        ($fut:expr) => {
            match tokio::time::timeout(VMESS_HANDSHAKE_TIMEOUT, $fut).await {
                Ok(r) => r?,
                Err(_) => return Err(anyhow!("VMess handshake timed out")),
            }
        };
    }

    // 1. Read AuthID
    let mut auth_id = [0u8; 16];
    timed_read!(stream.read_exact(&mut auth_id));

    // 2. Verify AuthID across allowed timestamp window (±30s)
    let now = chrono::Utc::now().timestamp();
    let mut found_ts = None;
    for ts in now - 30..=now + 30 {
        use aes::cipher::KeyInit;
        let mut hmac: hmac::Hmac<md5::Md5> =
            KeyInit::new_from_slice(uuid.as_bytes()).map_err(|_| anyhow!("HMAC key size error"))?;
        use hmac::Mac;
        hmac.update(&ts.to_be_bytes());
        // Constant-time compare: a `==` on byte slices short-circuits on the
        // first differing byte and leaks an AuthID prefix-match oracle through
        // handshake latency. Both sides are fixed [u8; 16].
        let computed: [u8; 16] = hmac.finalize().into_bytes().into();
        if bool::from(auth_id.ct_eq(&computed)) {
            found_ts = Some(ts);
            break;
        }
    }

    let ts = found_ts.ok_or_else(|| anyhow!("VMess authentication failed: invalid AuthID"))?;

    // 3. Decrypt Header using the derived Key/IV
    let mut key_md5 = md5::Md5::new();
    use md5::Digest;
    key_md5.update(uuid.as_bytes());
    key_md5.update(b"c4861939-ed4a-43f6-932c-354924a4f89d");
    let key: [u8; 16] = key_md5.finalize().into();

    let mut iv_md5 = md5::Md5::new();
    let ts_bytes = (ts as u64).wrapping_mul(4).to_be_bytes();
    for _ in 0..4 {
        iv_md5.update(ts_bytes);
    }
    let iv: [u8; 16] = iv_md5.finalize().into();

    // Independent AES-128-CFB-8 Decryption
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new(&key.into());
    let mut decrypted_header = Vec::new();
    let mut feedback = iv;

    // Read fixed part (41 bytes)
    for _ in 0..41 {
        let b = timed_read!(stream.read_u8());
        let mut block = feedback;
        cipher.encrypt_block((&mut block).into());
        decrypted_header.push(b ^ block[0]);
        feedback.rotate_left(1);
        feedback[15] = b;
    }

    // Parse fixed part to get address type
    let atyp = decrypted_header[40];
    match atyp {
        0x01 => {
            // IPv4
            for _ in 0..4 {
                let b = timed_read!(stream.read_u8());
                let mut block = feedback;
                cipher.encrypt_block((&mut block).into());
                decrypted_header.push(b ^ block[0]);
                feedback.rotate_left(1);
                feedback[15] = b;
            }
        }
        0x03 => {
            // Domain
            let b = timed_read!(stream.read_u8());
            let mut block = feedback;
            cipher.encrypt_block((&mut block).into());
            let len = b ^ block[0];
            decrypted_header.push(len);
            feedback.rotate_left(1);
            feedback[15] = b;

            for _ in 0..len {
                let b = timed_read!(stream.read_u8());
                let mut block = feedback;
                cipher.encrypt_block((&mut block).into());
                decrypted_header.push(b ^ block[0]);
                feedback.rotate_left(1);
                feedback[15] = b;
            }
        }
        0x04 => {
            // IPv6
            for _ in 0..16 {
                let b = timed_read!(stream.read_u8());
                let mut block = feedback;
                cipher.encrypt_block((&mut block).into());
                decrypted_header.push(b ^ block[0]);
                feedback.rotate_left(1);
                feedback[15] = b;
            }
        }
        _ => return Err(anyhow!("Unsupported VMess address type: {}", atyp)),
    }

    // Parse the fixed part to obtain padding length before consuming the tail.
    let (_, fixed_request) = parse_vmess_header(&decrypted_header)
        .map_err(|_| anyhow!("Invalid VMess header structure"))?;

    // v6.9.27: Consume padding + 4-byte HMAC-MD5 checksum that the client
    // appends after the address (RFC-010 wire format). Previously the inbound
    // stopped reading at the address, leaving 4 stray bytes that desynchronized
    // the subsequent AEAD chunk stream.
    let mut tail_len = fixed_request.padding_len as usize + 4;
    let mut tail = Vec::with_capacity(tail_len);
    while tail_len > 0 {
        let b = timed_read!(stream.read_u8());
        let mut block = feedback;
        cipher.encrypt_block((&mut block).into());
        tail.push(b ^ block[0]);
        feedback.rotate_left(1);
        feedback[15] = b;
        tail_len -= 1;
    }

    if tail.len() >= 4 {
        // Checksum covers the full plaintext header: fixed part + address +
        // padding (everything the client hashed before appending the tag).
        let mut hmac_input = decrypted_header.clone();
        let padding_len = fixed_request.padding_len as usize;
        hmac_input.extend_from_slice(&tail[..padding_len]);
        let checksum = &tail[padding_len..];
        let mut hmac: hmac::Hmac<md5::Md5> = aes::cipher::KeyInit::new_from_slice(&key)
            .map_err(|_| anyhow!("HMAC key size error"))?;
        use hmac::Mac;
        hmac.update(&hmac_input);
        if checksum != &hmac.finalize().into_bytes()[..4] {
            return Err(anyhow!("VMess header checksum mismatch"));
        }
    }

    let request = fixed_request;

    // 4. Wrap in VmessStream and Dispatch
    let v_stream = crate::transport::outbound::vmess::VmessStream::new(
        stream,
        request.request_key,
        request.request_iv,
    )?;

    let mut metadata = ConnectionMetadata::new(request.destination);
    metadata.environment.inbound_tag = Some(tag);
    metadata.handshake = HandshakeState::Established;

    let context = Arc::new(parking_lot::Mutex::new(ConnectionContext::new(metadata)));
    engine.send_event(EngineEvent::NewStream { context, stream: Box::new(v_stream) }).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vless_header() {
        let uuid = Uuid::new_v4();
        let mut data = Vec::new();
        data.push(0x00); // Version
        data.extend_from_slice(uuid.as_bytes()); // UUID
        data.push(0x00); // Addons length
        data.push(0x01); // CMD Connect
        data.extend_from_slice(&443u16.to_be_bytes()); // Port
        data.push(0x03); // ATYP Domain
        data.push(7); // Domain length
        data.extend_from_slice(b"abc.com"); // Domain
        data.extend_from_slice(b"payload"); // Payload

        let (rem, req) = parse_vless_handshake(&data).unwrap();
        assert_eq!(req.uuid, uuid);
        assert_eq!(req.cmd, 1);
        assert_eq!(req.destination.port, 443);
        assert_eq!(rem, b"payload");
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;
    use crate::engine::metadata::Addr;

    /// Byte offsets in the header, derived from the layout rather than counted
    /// by hand: version(1) iv(16) key(16) hash(1) option(1) p_s(1) reserved(1)
    /// cmd(1) port(2) atyp(1).
    const P_S: usize = 1 + 16 + 16 + 1 + 1;
    const PORT: usize = 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1;
    const ATYP: usize = PORT + 2;

    /// A well-formed VMess request header. Built by a helper rather than a
    /// hand-written hex blob: a mistyped constant desynchronises the header and
    /// every "valid" case then fails for an unrelated reason, which is a
    /// misleading way to learn the layout.
    fn header(atyp: u8, addr: &[u8], port: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(1); // version
        v.extend_from_slice(&[0xAB; 16]); // request IV
        v.extend_from_slice(&[0xCD; 16]); // request key
        v.push(0); // response header hash
        v.push(0x01); // option: chunked
        v.push(0x00); // P=0, S=0
        v.push(0); // reserved
        v.push(1); // cmd: TCP
        v.extend_from_slice(&port.to_be_bytes());
        v.push(atyp);
        v.extend_from_slice(addr);
        v
    }

    fn domain(host: &str) -> Vec<u8> {
        let mut v = vec![host.len() as u8];
        v.extend_from_slice(host.as_bytes());
        v
    }

    fn ok(input: &[u8]) -> VmessRequestHeader {
        parse_vmess_header(input).expect("should parse").1
    }

    // ---- happy paths -----------------------------------------------------

    #[test]
    fn parses_domain_destination() {
        let h = ok(&header(0x03, &domain("example.com"), 443));
        assert_eq!(h.version, 1);
        assert!(matches!(h.destination.addr, Addr::Domain(ref d) if d == "example.com"));
        assert_eq!(h.destination.port, 443);
    }

    #[test]
    fn parses_ipv4_destination() {
        let h = ok(&header(0x01, &[93, 184, 216, 34], 80));
        assert!(matches!(h.destination.addr, Addr::Ip(ip) if ip.to_string() == "93.184.216.34"));
    }

    #[test]
    fn parses_ipv6_destination() {
        let mut a = vec![0u8; 16];
        a[0] = 0x20;
        a[1] = 0x01;
        a[15] = 0x01;
        let h = ok(&header(0x04, &a, 443));
        assert!(matches!(h.destination.addr, Addr::Ip(ip) if ip.to_string().starts_with("2001:")));
    }

    #[test]
    fn captures_request_material_verbatim() {
        let h = ok(&header(0x03, &domain("a.io"), 443));
        assert_eq!(h.request_iv, [0xAB; 16]);
        assert_eq!(h.request_key, [0xCD; 16]);
    }

    /// P and S share one byte: padding is the high nibble, security the low.
    /// Getting this backwards silently disables both.
    #[test]
    fn splits_padding_and_security_nibbles() {
        let mut v = header(0x01, &[1, 2, 3, 4], 443);
        v[P_S] = 0xA7; // padding=0xA, security=0x7
        let h = ok(&v);
        assert_eq!(h.padding_len, 0xA);
        assert_eq!(h.security_type, 0x7);
    }

    #[test]
    fn returns_trailing_payload() {
        let mut v = header(0x03, &domain("a.io"), 443);
        v.extend_from_slice(b"payload");
        let (rest, _) = parse_vmess_header(&v).unwrap();
        assert_eq!(rest, b"payload");
    }

    // ---- truncation: the prober-facing surface --------------------------

    #[test]
    fn truncated_input_never_panics() {
        let full = header(0x03, &domain("example.com"), 443);
        for cut in 0..full.len() {
            let _ = parse_vmess_header(&full[..cut]);
        }
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(parse_vmess_header(&[]).is_err());
    }

    #[test]
    fn missing_iv_is_rejected() {
        let short = vec![1u8, 0xAB, 0xAB];
        assert!(parse_vmess_header(&short).is_err());
    }

    #[test]
    fn unknown_address_type_is_rejected() {
        assert!(parse_vmess_header(&header(0x05, &[0u8; 4], 443)).is_err());
    }

    /// A domain length that overruns the buffer must be rejected outright.
    ///
    /// Built as a clean domain frame first: the earlier version mutated an IPv4
    /// header into a domain header, which left the four address bytes in place
    /// and therefore satisfied the claimed length, so the parser correctly
    /// succeeded and the test was asserting the wrong thing.
    #[test]
    fn domain_length_exceeding_buffer_is_rejected() {
        let mut v = header(0x01, &[1, 2, 3, 4], 443);
        v.truncate(ATYP);
        v.push(0x03); // domain
        v.push(255); // claims 255 bytes
        v.extend_from_slice(b"ab"); // supplies two
        assert!(parse_vmess_header(&v).is_err(), "parser over-read past the supplied domain bytes");
    }

    /// The mirror case: a correctly-sized domain frame must still parse, so the
    /// test above is rejecting an overrun rather than rejecting domains.
    #[test]
    fn correctly_sized_domain_frame_still_parses() {
        let mut v = header(0x01, &[1, 2, 3, 4], 443);
        v.truncate(ATYP);
        v.push(0x03);
        v.push(2);
        v.extend_from_slice(b"ab");
        let h = ok(&v);
        assert!(matches!(h.destination.addr, Addr::Domain(ref d) if d == "ab"));
    }

    #[test]
    fn missing_port_is_rejected() {
        let v = header(0x01, &[1, 2, 3, 4], 443);
        assert!(parse_vmess_header(&v[..PORT]).is_err());
    }

    /// Random bytes must never panic. A parser panic reachable from the network
    /// is a remote denial of service.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x12345678u32;
        for _ in 0..2000 {
            let mut v = Vec::with_capacity(64);
            for _ in 0..64 {
                // xorshift: deterministic, so a failure is reproducible.
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                v.push((state & 0xFF) as u8);
            }
            let _ = parse_vmess_header(&v);
        }
    }

    // ---- security-relevant invariants ------------------------------------

    /// The request IV and key are AES material and must be exactly 16 bytes.
    /// A short read here would mean key material from the previous request.
    #[test]
    fn request_material_is_always_sixteen_bytes() {
        let h = ok(&header(0x03, &domain("a.io"), 443));
        assert_eq!(h.request_iv.len(), 16);
        assert_eq!(h.request_key.len(), 16);
    }

    #[test]
    fn security_nibble_is_in_range_for_every_input_byte() {
        // The low nibble of P|S is the security type, so it can never exceed
        // 0x0F regardless of input. Asserted over all 256 values because the
        // nibble split is the easy thing to get backwards.
        for byte in 0u8..=255 {
            let mut v = header(0x01, &[1, 2, 3, 4], 443);
            v[P_S] = byte;
            let h = ok(&v);
            assert_eq!(h.padding_len, byte >> 4);
            assert_eq!(h.security_type, byte & 0x0F);
            assert!(h.security_type <= 0x0F);
        }
    }
}
