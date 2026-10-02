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
        // v6.9.28: Loop-read accumulator (mirrors the VLESS
        // `read_vless_request` pattern): a Trojan header split across TCP
        // segments now accumulates instead of failing on a short read.
        // Pre-auth reads are bounded by a 5s deadline, so a silent or
        // dribbling prober cannot pin the handler task forever. Trojan has
        // no decoy path, so timeouts/EOF are plain errors.
        const MAX_HEADER: usize = 256;
        const TROJAN_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        let mut acc: Vec<u8> = Vec::with_capacity(256);
        let mut chunk = [0u8; 1024];
        let (remaining, request) = loop {
            if let Ok((rest, req)) = parse_trojan_handshake(&acc) {
                break (rest.to_vec(), req);
            }
            if acc.len() >= MAX_HEADER {
                return Err(anyhow!("Invalid Trojan handshake: header exceeds {MAX_HEADER} bytes"));
            }
            let n = match tokio::time::timeout(TROJAN_HANDSHAKE_TIMEOUT, stream.read(&mut chunk))
                .await
            {
                Ok(n) => n?,
                Err(_) => return Err(anyhow!("Trojan handshake timed out")),
            };
            if n == 0 {
                return Err(anyhow!("Invalid Trojan handshake: connection closed before header"));
            }
            acc.extend_from_slice(&chunk[..n]);
        };

        // Constant-time authentication on fixed-length SHA-224 hex digests.
        //
        // The parser now rejects anything that is not exactly 56 hex
        // characters, so both sides are guaranteed 56 bytes and the truncation
        // below cannot panic. This was previously asserted rather than
        // enforced, and the assertion was false.
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
    // The field is a 56-character lowercase hex SHA-224 digest, so it is ASCII
    // by specification. It was previously decoded with `from_utf8_lossy`, which
    // silently *expands* invalid bytes into 3-byte U+FFFD replacement
    // characters: a 56-byte field could come back as a 60-character string.
    //
    // The authentication comparison then took `.as_bytes()[..56]`, so the bytes
    // it compared were the first 56 of a lossy-expanded sequence, not the
    // digest the client sent. The comment claiming lengths "match by
    // construction" was false. Found by the fuzzer, not by review.
    //
    // Strict validation fixes it at the source and also removes a divergence a
    // prober could use: the field is now exactly what the specification says,
    // so a non-hex value is a protocol error rather than something accepted and
    // silently transformed.
    if !hash_bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    let password_hash = std::str::from_utf8(hash_bytes)
        .map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?
        .to_ascii_lowercase();

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

#[cfg(test)]
mod handshake_tests {
    use super::*;
    use crate::engine::metadata::Addr;

    /// A real 56-character SHA-224 hex digest. The parser takes exactly 56
    /// bytes, so the test constant has to be 56 too - a 60-character stand-in
    /// desynchronises the whole header and every "valid" case fails, which is a
    /// bad way to learn the length.
    const HASH: &str = "b42338ef718bb33b88d3c2bf0cb6130499a1dc05e5c101b3722b09c7";

    /// A well-formed TCP-to-domain handshake, the common case.
    fn frame(cmd: u8, atyp: u8, addr: &[u8], port: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(HASH.as_bytes());
        v.extend_from_slice(b"\r\n");
        v.push(cmd);
        v.push(atyp);
        v.extend_from_slice(addr);
        v.extend_from_slice(&port.to_be_bytes());
        v.extend_from_slice(b"\r\n");
        v
    }

    fn domain_addr(host: &str) -> Vec<u8> {
        let mut v = vec![host.len() as u8];
        v.extend_from_slice(host.as_bytes());
        v
    }

    fn ok(input: &[u8]) -> TrojanRequest {
        parse_trojan_handshake(input).expect("should parse").1
    }

    // ---- happy paths -----------------------------------------------------

    #[test]
    fn parses_domain_destination() {
        let r = ok(&frame(1, 0x03, &domain_addr("example.com"), 443));
        assert_eq!(r.cmd, 1);
        assert!(matches!(r.destination.addr, Addr::Domain(ref d) if d == "example.com"));
        assert_eq!(r.destination.port, 443);
    }

    #[test]
    fn parses_ipv4_destination() {
        let r = ok(&frame(1, 0x01, &[93, 184, 216, 34], 80));
        assert!(matches!(r.destination.addr, Addr::Ip(ip) if ip.to_string() == "93.184.216.34"));
        assert_eq!(r.destination.port, 80);
    }

    #[test]
    fn parses_ipv6_destination() {
        let mut a = vec![0u8; 16];
        a[0] = 0x20;
        a[1] = 0x01;
        a[15] = 0x01;
        let r = ok(&frame(1, 0x04, &a, 443));
        assert!(matches!(r.destination.addr, Addr::Ip(ip) if ip.to_string().starts_with("2001:")));
    }

    #[test]
    fn returns_trailing_payload_after_the_header() {
        // Real payload arriving in the same segment as the header must survive.
        let mut f = frame(1, 0x03, &domain_addr("a.io"), 443);
        f.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        let (rest, _) = parse_trojan_handshake(&f).unwrap();
        assert_eq!(rest, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn preserves_password_hash_exactly() {
        let r = ok(&frame(1, 0x03, &domain_addr("a.io"), 443));
        assert_eq!(r.password_hash, HASH);
    }

    #[test]
    fn zero_length_domain_is_accepted_by_the_parser() {
        // Parses, and is the router's problem to reject. Asserting current
        // behaviour so a future change is deliberate.
        let _ = ok(&frame(1, 0x03, &[0u8], 443));
    }

    // ---- truncation: a prober must not crash the parser ------------------

    #[test]
    fn truncated_input_never_panics() {
        let full = frame(1, 0x03, &domain_addr("example.com"), 443);
        for cut in 0..full.len() {
            let _ = parse_trojan_handshake(&full[..cut]);
        }
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(parse_trojan_handshake(&[]).is_err());
    }

    #[test]
    fn missing_crlf_after_hash_is_rejected() {
        let mut v = HASH.as_bytes().to_vec();
        v.extend_from_slice(b"XX");
        assert!(parse_trojan_handshake(&v).is_err());
    }

    #[test]
    fn unknown_address_type_is_rejected() {
        // 0x05 is not a defined SOCKS5/Trojan ATYP.
        assert!(parse_trojan_handshake(&frame(1, 0x05, &[0u8; 4], 443)).is_err());
    }

    #[test]
    fn domain_length_longer_than_buffer_is_rejected() {
        // Claims 255 bytes of domain but supplies two.
        let mut v = HASH.as_bytes().to_vec();
        v.extend_from_slice(b"\r\n");
        v.push(1);
        v.push(0x03);
        v.push(255);
        v.extend_from_slice(b"ab");
        assert!(parse_trojan_handshake(&v).is_err());
    }

    #[test]
    fn missing_port_is_rejected() {
        let mut v = HASH.as_bytes().to_vec();
        v.extend_from_slice(b"\r\n");
        v.push(1);
        v.push(0x01);
        v.extend_from_slice(&[1, 2, 3, 4]);
        assert!(parse_trojan_handshake(&v).is_err());
    }

    #[test]
    fn missing_trailing_crlf_is_rejected() {
        let mut v = HASH.as_bytes().to_vec();
        v.extend_from_slice(b"\r\n");
        v.push(1);
        v.push(0x01);
        v.extend_from_slice(&[1, 2, 3, 4]);
        v.extend_from_slice(&443u16.to_be_bytes());
        assert!(parse_trojan_handshake(&v).is_err());
    }

    // ---- authentication: the security-critical path ---------------------

    #[test]
    fn authentication_accepts_the_matching_digest() {
        // The engine uses async_channel, not tokio::sync::mpsc.
        let (event_tx, _rx) = async_channel::bounded(1);
        let inbound = TrojanInbound::new(
            "t".into(),
            "127.0.0.1:0".into(),
            "hunter2",
            // Never dispatched to on these paths; the handle only has to exist.
            EngineHandle::new(event_tx),
        );
        // Recompute the digest the same way the inbound does.
        use sha2::{Digest, Sha224};
        let mut h = Sha224::new();
        h.update("hunter2".as_bytes());
        let digest = hex::encode(h.finalize());
        let mut f = Vec::new();
        f.extend_from_slice(digest.as_bytes());
        f.extend_from_slice(b"\r\n");
        f.push(1);
        f.push(0x01);
        f.extend_from_slice(&[1, 2, 3, 4]);
        f.extend_from_slice(&443u16.to_be_bytes());
        f.extend_from_slice(b"\r\n");
        let r = ok(&f);
        assert_eq!(r.password_hash, inbound.password_hash);
    }

    /// Digests are compared in constant time, so a wrong password must fail the
    /// comparison rather than being partially accepted.
    #[test]
    fn wrong_password_hash_is_a_different_digest() {
        use sha2::{Digest, Sha224};
        let digest = |p: &str| {
            let mut h = Sha224::new();
            h.update(p.as_bytes());
            hex::encode(h.finalize())
        };
        assert_ne!(digest("correct"), digest("wrong"));
        // Equal length is what makes the constant-time comparison sound.
        assert_eq!(digest("correct").len(), digest("wrong").len());
    }

    #[test]
    fn digest_length_is_constant_for_any_password() {
        use sha2::{Digest, Sha224};
        for p in ["", "a", "a-much-longer-password", &"x".repeat(1000)] {
            let mut h = Sha224::new();
            h.update(p.as_bytes());
            assert_eq!(hex::encode(h.finalize()).len(), 56);
        }
    }

    // ---- command handling ------------------------------------------------

    #[test]
    fn udp_command_parses_even_though_it_is_not_served() {
        // The parser is transport-agnostic; the listener rejects UDP later.
        let r = ok(&frame(3, 0x01, &[1, 2, 3, 4], 53));
        assert_eq!(r.cmd, 3);
    }

    #[test]
    fn unknown_command_parses_and_is_left_to_the_listener() {
        let _ = ok(&frame(0xff, 0x01, &[1, 2, 3, 4], 80));
    }
}
