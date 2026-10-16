//! Byte-exact TUIC v5 wire codec (RFC-023).
//!
//! Typed parsers over raw bytes — every field is bounds-checked, malformed
//! input is rejected with a typed error, and no allocation happens for
//! fixed-width prefixes. Encoders are pure functions: identical inputs
//! always produce identical wire bytes (pinned by tests).
//!
//! Spec basis: TUIC protocol v5 wire-format specification (protocol version
//! `0x05`). Address `TYPE` bytes are TUIC's own (`0x00` FQDN, `0x01` IPv4,
//! `0x02` IPv6, `0xff` None) — deliberately *not* the SOCKS values.

use crate::engine::metadata::Addr;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Protocol version byte — TUIC v5.
pub const VERSION: u8 = 0x05;
/// Authenticate command (UUID + exporter TOKEN, one per connection).
pub const CMD_AUTHENTICATE: u8 = 0x00;
/// Connect command (TCP relay, one bidirectional stream per relay).
pub const CMD_CONNECT: u8 = 0x01;
/// Packet command (UDP relay fragment).
pub const CMD_PACKET: u8 = 0x02;
/// Dissociate command (release a UDP relay session).
pub const CMD_DISSOCIATE: u8 = 0x03;
/// Heartbeat command (keep-alive).
pub const CMD_HEARTBEAT: u8 = 0x04;

/// Address TYPE: none — non-first fragments only; no address bytes follow.
pub const ATYP_NONE: u8 = 0xff;
/// Address TYPE: fully-qualified domain name (next byte is its length).
pub const ATYP_DOMAIN: u8 = 0x00;
/// Address TYPE: IPv4 (4 bytes follow).
pub const ATYP_IPV4: u8 = 0x01;
/// Address TYPE: IPv6 (16 bytes follow).
pub const ATYP_IPV6: u8 = 0x02;

/// Fixed prefix of a Packet command: VER, TYPE, ASSOC_ID, PKT_ID,
/// FRAG_TOTAL, FRAG_ID, SIZE.
pub const PACKET_FIXED_LEN: usize = 10;

/// Hard ceiling on a single UDP payload this client will fragment: 255
/// fragments at the fallback datagram size.
pub const MAX_UDP_PAYLOAD: usize = 255 * DATAGRAM_SAFE_FRAGMENT;

/// Conservative per-fragment payload budget used for the ceiling above.
const DATAGRAM_SAFE_FRAGMENT: usize = 1200;

/// Typed decode/encode failure for the TUIC v5 wire format.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TuicWireError {
    /// Input ended before a field could be read.
    #[error("truncated input: needed {needed} bytes, only {have} available")]
    Truncated {
        /// Bytes the next field requires.
        needed: usize,
        /// Bytes actually remaining.
        have: usize,
    },
    /// An address TYPE byte outside the spec's set (e.g. the SOCKS domain
    /// byte 0x03 — a value the TUIC spec never assigns).
    #[error("unknown address TYPE byte 0x{0:02x}")]
    UnknownAddressType(u8),
    /// Domain length outside `1..=255`.
    #[error("domain length {0} outside 1..=255")]
    DomainLength(usize),
    /// Domain bytes are not valid UTF-8.
    #[error("domain name is not valid UTF-8")]
    DomainNotUtf8,
    /// Payload exceeds the 16-bit SIZE field.
    #[error("payload of {0} bytes exceeds the 16-bit SIZE field")]
    PayloadTooLarge(usize),
    /// A version byte other than 0x05.
    #[error("unexpected protocol version byte 0x{0:02x} (expected 0x05)")]
    Version(u8),
    /// A command TYPE this decoder does not accept.
    #[error("unexpected command TYPE byte 0x{0:02x}")]
    UnexpectedCommand(u8),
    /// Bytes remain after the declared payload — strict framing violation.
    #[error("{0} trailing bytes after packet payload")]
    TrailingBytes(usize),
    /// FRAG_TOTAL of zero (a packet that claims no fragments).
    #[error("FRAG_TOTAL must be at least 1")]
    ZeroFragments,
    /// FRAG_ID beyond FRAG_TOTAL-1.
    #[error("FRAG_ID {frag_id} out of range for FRAG_TOTAL {frag_total}")]
    FragmentIndexOutOfBounds {
        /// Declared fragment index.
        frag_id: u8,
        /// Declared total fragment count.
        frag_total: u8,
    },
    /// The payload cannot fit into 255 fragments at the given datagram size.
    #[error("payload cannot fit in 255 fragments of {0} bytes")]
    TooManyFragments(usize),
}

/// A TUIC wire address: host + port exactly as they travel on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireAddress {
    /// Host (IP or FQDN).
    pub host: Addr,
    /// Port.
    pub port: u16,
}

/// A decoded Packet command borrowed from its datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketCommand<'a> {
    /// UDP relay association identifier.
    pub assoc_id: u16,
    /// Reassembly group identifier.
    pub pkt_id: u16,
    /// Total fragments in the reassembly group.
    pub frag_total: u8,
    /// Zero-based index of this fragment.
    pub frag_id: u8,
    /// Responder/target address; `None` on non-first fragments.
    pub address: Option<WireAddress>,
    /// Fragment payload (LENGTH bytes).
    pub payload: &'a [u8],
}

/// Appends `TYPE + ADDR + PORT` for the given host/port to `out`.
///
/// # Errors
/// [`TuicWireError::DomainLength`] when the FQDN is empty or longer than
/// 255 bytes.
pub fn encode_address(host: &Addr, port: u16, out: &mut Vec<u8>) -> Result<(), TuicWireError> {
    match host {
        Addr::Ip(IpAddr::V4(ip)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Addr::Ip(IpAddr::V6(ip)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Addr::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return Err(TuicWireError::DomainLength(bytes.len()));
            }
            out.push(ATYP_DOMAIN);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

/// Wire length in bytes of a full address block for the given host.
pub fn encoded_address_len(host: &Addr) -> usize {
    match host {
        Addr::Ip(IpAddr::V4(_)) => 1 + 4,
        Addr::Ip(IpAddr::V6(_)) => 1 + 16,
        Addr::Domain(domain) => 1 + 1 + domain.len(),
    }
}

/// Decodes one address block from the front of `buf`.
///
/// Returns the address and the number of bytes consumed.
///
/// # Errors
/// [`TuicWireError`] on truncation, unknown TYPE bytes (including the SOCKS
/// values this protocol does not use), non-UTF-8 domains, or empty domains.
pub fn decode_address(buf: &[u8]) -> Result<(WireAddress, usize), TuicWireError> {
    let mut cursor = Cursor::new(buf);
    let ty = cursor.u8()?;
    let host = match ty {
        ATYP_IPV4 => {
            let octets = cursor.take(4)?;
            let mut raw = [0u8; 4];
            raw.copy_from_slice(octets);
            Addr::Ip(IpAddr::V4(Ipv4Addr::from(raw)))
        }
        ATYP_IPV6 => {
            let octets = cursor.take(16)?;
            let mut raw = [0u8; 16];
            raw.copy_from_slice(octets);
            Addr::Ip(IpAddr::V6(Ipv6Addr::from(raw)))
        }
        ATYP_DOMAIN => {
            let len = cursor.u8()? as usize;
            let bytes = cursor.take(len)?;
            let domain = std::str::from_utf8(bytes).map_err(|_| TuicWireError::DomainNotUtf8)?;
            if domain.is_empty() {
                return Err(TuicWireError::DomainLength(0));
            }
            Addr::Domain(domain.to_owned())
        }
        other => return Err(TuicWireError::UnknownAddressType(other)),
    };
    let port = cursor.u16()?;
    Ok((WireAddress { host, port }, cursor.pos))
}

/// Encodes a Connect command header: `VER | TYPE | ADDR | PORT`.
///
/// # Errors
/// [`TuicWireError::DomainLength`] for invalid FQDNs.
pub fn encode_connect(host: &Addr, port: u16) -> Result<Vec<u8>, TuicWireError> {
    let mut out = Vec::with_capacity(2 + encoded_address_len(host) + 2);
    out.push(VERSION);
    out.push(CMD_CONNECT);
    encode_address(host, port, &mut out)?;
    Ok(out)
}

/// Encodes the Authenticate command: `VER | TYPE | UUID(16) | TOKEN(32)`.
pub fn encode_authenticate(uuid: &[u8; 16], token: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 16 + 32);
    out.push(VERSION);
    out.push(CMD_AUTHENTICATE);
    out.extend_from_slice(uuid);
    out.extend_from_slice(token);
    out
}

/// Encodes the Dissociate command: `VER | TYPE | ASSOC_ID`.
pub fn encode_dissociate(assoc_id: u16) -> [u8; 4] {
    [VERSION, CMD_DISSOCIATE, assoc_id.to_be_bytes()[0], assoc_id.to_be_bytes()[1]]
}

/// Encodes the Heartbeat command: `VER | TYPE`.
pub fn encode_heartbeat() -> [u8; 2] {
    [VERSION, CMD_HEARTBEAT]
}

/// Encodes one Packet command datagram (header + one fragment payload).
///
/// # Errors
/// [`TuicWireError::PayloadTooLarge`] when the fragment exceeds the 16-bit
/// SIZE field, or [`TuicWireError::DomainLength`] for invalid FQDNs.
pub fn encode_packet(
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    address: Option<&WireAddress>,
    payload: &[u8],
) -> Result<Vec<u8>, TuicWireError> {
    let size =
        u16::try_from(payload.len()).map_err(|_| TuicWireError::PayloadTooLarge(payload.len()))?;
    let mut out = Vec::with_capacity(PACKET_FIXED_LEN + 1 + 255 + 2 + payload.len());
    out.push(VERSION);
    out.push(CMD_PACKET);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out.extend_from_slice(&pkt_id.to_be_bytes());
    out.push(frag_total);
    out.push(frag_id);
    out.extend_from_slice(&size.to_be_bytes());
    match address {
        Some(address) => encode_address(&address.host, address.port, &mut out)?,
        None => out.push(ATYP_NONE),
    }
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decodes one Packet command datagram with strict framing: the declared
/// SIZE must exactly match the remaining bytes.
///
/// # Errors
/// [`TuicWireError`] for truncation, wrong version/command, unknown address
/// TYPE, SIZE disagreement, trailing bytes, or invalid fragment indices.
pub fn decode_packet(buf: &[u8]) -> Result<PacketCommand<'_>, TuicWireError> {
    let mut cursor = Cursor::new(buf);
    let ver = cursor.u8()?;
    if ver != VERSION {
        return Err(TuicWireError::Version(ver));
    }
    let ty = cursor.u8()?;
    if ty != CMD_PACKET {
        return Err(TuicWireError::UnexpectedCommand(ty));
    }
    let assoc_id = cursor.u16()?;
    let pkt_id = cursor.u16()?;
    let frag_total = cursor.u8()?;
    let frag_id = cursor.u8()?;
    let size = cursor.u16()? as usize;

    let address = if cursor.peek()? == ATYP_NONE {
        cursor.u8()?;
        None
    } else {
        let (address, consumed) = decode_address(&buf[cursor.pos..])?;
        cursor.pos += consumed;
        Some(address)
    };

    let payload = cursor.take(size)?;
    if cursor.pos != buf.len() {
        return Err(TuicWireError::TrailingBytes(buf.len() - cursor.pos));
    }
    if frag_total == 0 {
        return Err(TuicWireError::ZeroFragments);
    }
    if frag_id >= frag_total {
        return Err(TuicWireError::FragmentIndexOutOfBounds { frag_id, frag_total });
    }

    Ok(PacketCommand { assoc_id, pkt_id, frag_total, frag_id, address, payload })
}

/// Encodes a complete (possibly fragmented) UDP payload into per-fragment
/// datagrams that each fit within `max_datagram_len`.
///
/// An empty payload produces a single zero-length fragment (a packet with
/// `SIZE = 0`), so empty datagrams are still relayed.
///
/// # Errors
/// [`TuicWireError::PayloadTooLarge`] beyond [`MAX_UDP_PAYLOAD`],
/// [`TuicWireError::TooManyFragments`] when the datagram budget cannot fit
/// the address header, or [`TuicWireError::DomainLength`] for invalid FQDNs.
pub fn encode_fragments(
    assoc_id: u16,
    pkt_id: u16,
    host: &Addr,
    port: u16,
    payload: &[u8],
    max_datagram_len: usize,
) -> Result<Vec<Vec<u8>>, TuicWireError> {
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(TuicWireError::PayloadTooLarge(payload.len()));
    }
    // Every fragment reserves the worst-case header (first fragment carries
    // the full address; later ones a single None byte) so a uniform chunk
    // size always fits.
    let headroom = PACKET_FIXED_LEN + encoded_address_len(host) + 2;
    if max_datagram_len <= headroom {
        return Err(TuicWireError::TooManyFragments(headroom));
    }
    let fragment_len = max_datagram_len - headroom;
    let frag_total = u8::try_from(payload.len().div_ceil(fragment_len).max(1))
        .map_err(|_| TuicWireError::PayloadTooLarge(payload.len()))?;

    let mut out = Vec::with_capacity(frag_total as usize);
    if payload.is_empty() {
        out.push(encode_packet(
            assoc_id,
            pkt_id,
            1,
            0,
            Some(&WireAddress { host: host.clone(), port }),
            &[],
        )?);
        return Ok(out);
    }
    for (frag_id, chunk) in payload.chunks(fragment_len).enumerate() {
        let address =
            if frag_id == 0 { Some(WireAddress { host: host.clone(), port }) } else { None };
        out.push(encode_packet(
            assoc_id,
            pkt_id,
            frag_total,
            frag_id as u8,
            address.as_ref(),
            chunk,
        )?);
    }
    Ok(out)
}

/// Bounds-checked read cursor over a datagram.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// Outcome of feeding one Packet command into a reassembly group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reassemble {
    /// Fragment stored; the group is not yet complete.
    Pending,
    /// The group is complete — final payload with the first fragment's
    /// address (`None` only for groups that never carried one).
    Complete {
        /// Destination/responder address from the first fragment.
        address: Option<WireAddress>,
        /// Reassembled payload in fragment order.
        payload: Vec<u8>,
    },
    /// The group violates invariants (size or consistency) and was dropped.
    Rejected,
}

/// Bounded reassembly of fragmented Packet commands.
///
/// Shared by the server's UDP pump and the client's datagram reader: TUIC
/// splits UDP payloads across Packet commands keyed by
/// `(ASSOC_ID, PKT_ID)`. Memory is bounded by `cap` concurrent groups
/// (oldest evicted); a group whose accumulated size exceeds
/// [`MAX_UDP_PAYLOAD`] is rejected outright (protocol-rules §13).
pub struct FragmentReassembler {
    cap: usize,
    partials: HashMap<(u16, u16), Partial>,
    order: VecDeque<(u16, u16)>,
}

struct Partial {
    frag_total: u8,
    received: u8,
    chunks: Vec<Option<Vec<u8>>>,
    first_address: Option<WireAddress>,
    total_len: usize,
}

impl FragmentReassembler {
    /// Creates a reassembler holding at most `cap` concurrent groups.
    pub fn new(cap: usize) -> Self {
        Self { cap, partials: HashMap::new(), order: VecDeque::new() }
    }

    /// Feeds one decoded Packet command. Duplicate fragments are ignored
    /// (idempotent); a fragment count inconsistent with the group's first
    /// fragment rejects the whole group.
    pub fn accept(&mut self, cmd: &PacketCommand<'_>) -> Reassemble {
        let key = (cmd.assoc_id, cmd.pkt_id);
        if !self.partials.contains_key(&key) {
            while self.partials.len() >= self.cap {
                let Some(oldest) = self.order.pop_front() else { break };
                self.partials.remove(&oldest);
            }
            self.order.push_back(key);
            self.partials.insert(
                key,
                Partial {
                    frag_total: cmd.frag_total,
                    received: 0,
                    chunks: vec![None; cmd.frag_total as usize],
                    first_address: None,
                    total_len: 0,
                },
            );
        }
        let Some(partial) = self.partials.get_mut(&key) else {
            return Reassemble::Rejected;
        };
        if partial.frag_total != cmd.frag_total {
            self.partials.remove(&key);
            return Reassemble::Rejected;
        }
        let frag_id = cmd.frag_id as usize;
        if frag_id >= partial.chunks.len() {
            return Reassemble::Rejected;
        }
        if partial.chunks[frag_id].is_some() {
            return Reassemble::Pending; // duplicate — idempotent
        }
        partial.total_len += cmd.payload.len();
        if partial.total_len > MAX_UDP_PAYLOAD {
            self.partials.remove(&key);
            return Reassemble::Rejected;
        }
        if frag_id == 0 {
            partial.first_address = cmd.address.clone();
        }
        partial.chunks[frag_id] = Some(cmd.payload.to_vec());
        partial.received += 1;
        if partial.received < partial.frag_total {
            return Reassemble::Pending;
        }
        let Some(partial) = self.partials.remove(&key) else {
            // Unreachable by the bookkeeping above; graceful instead of a panic.
            return Reassemble::Rejected;
        };
        let mut payload = Vec::with_capacity(partial.total_len);
        for chunk in &partial.chunks {
            payload.extend_from_slice(chunk.as_deref().unwrap_or(&[]));
        }
        Reassemble::Complete { address: partial.first_address, payload }
    }
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, needed: usize) -> Result<&'a [u8], TuicWireError> {
        let have = self.buf.len() - self.pos;
        if have < needed {
            return Err(TuicWireError::Truncated { needed, have });
        }
        let slice = &self.buf[self.pos..self.pos + needed];
        self.pos += needed;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, TuicWireError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TuicWireError> {
        let raw = self.take(2)?;
        Ok(u16::from_be_bytes([raw[0], raw[1]]))
    }

    fn peek(&self) -> Result<u8, TuicWireError> {
        if self.pos >= self.buf.len() {
            return Err(TuicWireError::Truncated { needed: 1, have: 0 });
        }
        Ok(self.buf[self.pos])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::metadata::Endpoint;
    use proptest::prelude::*;

    fn domain(host: &str, port: u16) -> WireAddress {
        WireAddress { host: Addr::Domain(host.to_owned()), port }
    }

    #[test]
    fn connect_header_shape_domain() {
        let header =
            encode_connect(&Addr::Domain("example.net".into()), 443).expect("valid domain");
        assert_eq!(header, {
            let mut expected = vec![0x05, 0x01, 0x00, 11];
            expected.extend_from_slice(b"example.net");
            expected.extend_from_slice(&443u16.to_be_bytes());
            expected
        });
    }

    #[test]
    fn connect_header_shape_ipv6() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let header = encode_connect(&Addr::Ip(IpAddr::V6(ip)), 0x0102).expect("valid ip");
        assert_eq!(header[0], 0x05);
        assert_eq!(header[1], 0x01);
        assert_eq!(header[2], ATYP_IPV6);
        assert_eq!(&header[3..19], &ip.octets());
        assert_eq!(&header[19..21], &[0x01, 0x02]);
    }

    #[test]
    fn authenticate_shape() {
        let uuid = [0x42u8; 16];
        let token = [0x7fu8; 32];
        let bytes = encode_authenticate(&uuid, &token);
        assert_eq!(bytes.len(), 50);
        assert_eq!(&bytes[..2], &[0x05, 0x00]);
        assert_eq!(&bytes[2..18], &uuid);
        assert_eq!(&bytes[18..], &token);
    }

    #[test]
    fn dissociate_and_heartbeat_shapes() {
        assert_eq!(encode_dissociate(0xBEEF), [0x05, 0x03, 0xBE, 0xEF]);
        assert_eq!(encode_heartbeat(), [0x05, 0x04]);
    }

    #[test]
    fn address_roundtrip_all_types() {
        for host in [
            Addr::Domain("shadowmesh.example".into()),
            Addr::Ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            Addr::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ] {
            let mut buf = Vec::new();
            encode_address(&host, 0xABCD, &mut buf).expect("encode");
            let (decoded, consumed) = decode_address(&buf).expect("decode");
            assert_eq!(decoded, WireAddress { host: host.clone(), port: 0xABCD });
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn decode_rejects_socks_domain_type() {
        // 0x03 is a valid SOCKS ATYP but not a valid TUIC one.
        let buf = [0x03, 3, b'a', b'b', b'c', 0x00, 0x50];
        assert_eq!(decode_address(&buf), Err(TuicWireError::UnknownAddressType(0x03)));
    }

    #[test]
    fn decode_rejects_empty_domain() {
        let buf = [ATYP_DOMAIN, 0, 0x00, 0x50];
        assert_eq!(decode_address(&buf), Err(TuicWireError::DomainLength(0)));
    }

    #[test]
    fn encode_rejects_oversized_domain() {
        let mut buf = Vec::new();
        let err = encode_address(&Addr::Domain("a".repeat(256)), 1, &mut buf);
        assert!(matches!(err, Err(TuicWireError::DomainLength(256))));
    }

    #[test]
    fn packet_roundtrip_with_address() {
        let datagram =
            encode_packet(0x1234, 0x0007, 1, 0, Some(&domain("dns.example", 53)), b"payload")
                .expect("encode");
        let cmd = decode_packet(&datagram).expect("decode");
        assert_eq!(cmd.assoc_id, 0x1234);
        assert_eq!(cmd.pkt_id, 0x0007);
        assert_eq!(cmd.frag_total, 1);
        assert_eq!(cmd.frag_id, 0);
        assert_eq!(cmd.address, Some(domain("dns.example", 53)));
        assert_eq!(cmd.payload, b"payload");
    }

    #[test]
    fn packet_roundtrip_none_address() {
        let datagram = encode_packet(1, 2, 3, 2, None, b"tail").expect("encode");
        let cmd = decode_packet(&datagram).expect("decode");
        assert_eq!(cmd.address, None);
        assert_eq!(cmd.payload, b"tail");
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut datagram = encode_packet(1, 1, 1, 0, None, b"x").expect("encode");
        datagram[0] = 0x04;
        assert!(matches!(decode_packet(&datagram), Err(TuicWireError::Version(0x04))));
    }

    #[test]
    fn decode_rejects_size_mismatch() {
        let mut datagram = encode_packet(1, 1, 1, 0, None, b"abcd").expect("encode");
        // SIZE spans bytes 8-9; bump it from 4 to 5 while only 4 payload
        // bytes follow — strict framing must reject the truncation.
        datagram[9] = 0x05;
        assert_eq!(decode_packet(&datagram), Err(TuicWireError::Truncated { needed: 5, have: 4 }));
    }

    #[test]
    fn decode_rejects_fragment_index_out_of_range() {
        let datagram = encode_packet(1, 1, 2, 2, None, b"x").expect("encode");
        assert!(matches!(
            decode_packet(&datagram),
            Err(TuicWireError::FragmentIndexOutOfBounds { frag_id: 2, frag_total: 2 })
        ));
    }

    #[test]
    fn decode_rejects_zero_fragments() {
        let mut datagram = encode_packet(1, 1, 1, 0, None, b"x").expect("encode");
        datagram[6] = 0; // FRAG_TOTAL = 0
        assert_eq!(decode_packet(&datagram), Err(TuicWireError::ZeroFragments));
    }

    #[test]
    fn fragments_reassemble_in_order() {
        let payload: Vec<u8> = (0..2500u32).map(|i| (i % 251) as u8).collect();
        let host = Addr::Domain("frag.example".into());
        let datagrams =
            encode_fragments(9, 4, &host, 8443, &payload, 700).expect("fragmentation plan");
        assert!(datagrams.len() >= 2, "payload must split");

        let mut reassembled = Vec::new();
        for (idx, datagram) in datagrams.iter().enumerate() {
            let cmd = decode_packet(datagram).expect("fragment decodes");
            assert_eq!(cmd.assoc_id, 9);
            assert_eq!(cmd.pkt_id, 4);
            assert_eq!(cmd.frag_total as usize, datagrams.len());
            assert_eq!(cmd.frag_id as usize, idx);
            if idx == 0 {
                assert_eq!(cmd.address, Some(WireAddress { host: host.clone(), port: 8443 }));
            } else {
                assert_eq!(cmd.address, None, "non-first fragments carry no address");
            }
            reassembled.extend_from_slice(cmd.payload);
        }
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn empty_payload_yields_single_zero_fragment() {
        let datagrams =
            encode_fragments(1, 1, &Addr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)), 53, &[], 1200)
                .expect("encode");
        assert_eq!(datagrams.len(), 1);
        let cmd = decode_packet(&datagrams[0]).expect("decode");
        assert_eq!(cmd.frag_total, 1);
        assert_eq!(cmd.frag_id, 0);
        assert!(cmd.payload.is_empty());
    }

    #[test]
    fn endpoint_display_roundtrip_through_codec() {
        // The outbound passes engine Endpoints through the codec — pin that
        // seam for the domain path used by split-tunnel DNS.
        let endpoint = Endpoint::new_domain("relay.example".into(), 0xFFFF);
        let mut buf = Vec::new();
        encode_address(&endpoint.addr, endpoint.port, &mut buf).expect("encode");
        let (decoded, _) = decode_address(&buf).expect("decode");
        assert_eq!(decoded.host, endpoint.addr);
        assert_eq!(decoded.port, endpoint.port);
    }

    #[test]
    fn reassembler_completes_fragmented_group() {
        let payload: Vec<u8> = (0..2500u32).map(|i| (i % 13) as u8).collect();
        let datagrams =
            encode_fragments(3, 9, &Addr::Domain("re.example".into()), 8080, &payload, 700)
                .expect("fragmentation plan");
        let mut reassembler = FragmentReassembler::new(64);
        let mut outcome = Reassemble::Pending;
        for datagram in &datagrams {
            let cmd = decode_packet(datagram).expect("fragment decodes");
            outcome = reassembler.accept(&cmd);
        }
        match outcome {
            Reassemble::Complete { address, payload: assembled } => {
                assert_eq!(
                    address,
                    Some(WireAddress { host: Addr::Domain("re.example".into()), port: 8080 })
                );
                assert_eq!(assembled, payload);
            }
            other => panic!("expected complete reassembly, got {other:?}"),
        }
    }

    #[test]
    fn reassembler_rejects_oversized_group() {
        let mut reassembler = FragmentReassembler::new(64);
        let chunk = [0xA5u8; 1400];
        let mut outcome = Reassemble::Pending;
        for frag_id in 0..255u8 {
            let datagram = encode_packet(1, 1, 255, frag_id, None, &chunk).expect("encode");
            let cmd = decode_packet(&datagram).expect("decode");
            outcome = reassembler.accept(&cmd);
            if outcome == Reassemble::Rejected {
                break;
            }
        }
        assert_eq!(outcome, Reassemble::Rejected, "group past MAX_UDP_PAYLOAD must be rejected");
    }

    #[test]
    fn reassembler_evicts_oldest_group_at_cap() {
        let mut reassembler = FragmentReassembler::new(2);
        let fragment = encode_packet(1, 1, 2, 0, None, b"first").expect("encode");
        let cmd = decode_packet(&fragment).expect("decode");
        assert_eq!(reassembler.accept(&cmd), Reassemble::Pending);
        let other = encode_packet(2, 1, 2, 0, None, b"second").expect("encode");
        let cmd = decode_packet(&other).expect("decode");
        assert_eq!(reassembler.accept(&cmd), Reassemble::Pending);
        // Third group evicts the first — its tail fragment no longer completes.
        let third = encode_packet(3, 1, 2, 0, None, b"third").expect("encode");
        let cmd = decode_packet(&third).expect("decode");
        assert_eq!(reassembler.accept(&cmd), Reassemble::Pending);
        let tail = encode_packet(1, 1, 2, 1, None, b"first-tail").expect("encode");
        let cmd = decode_packet(&tail).expect("decode");
        assert_eq!(
            reassembler.accept(&cmd),
            Reassemble::Pending,
            "evicted group must not complete"
        );
    }

    proptest::proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn address_roundtrip_property(
            host in host_strategy(),
            port in any::<u16>(),
        ) {
            let mut buf = Vec::new();
            encode_address(&host, port, &mut buf).expect("encode");
            let (decoded, consumed) = decode_address(&buf).expect("decode");
            prop_assert_eq!(decoded, WireAddress { host, port });
            prop_assert_eq!(consumed, buf.len());
        }

        #[test]
        fn packet_roundtrip_property(
            assoc_id in any::<u16>(),
            pkt_id in any::<u16>(),
            frag_total in 1u8..=255,
            frag_id_seed in any::<u8>(),
            address in proptest::option::of(
                (host_strategy(), any::<u16>())
                    .prop_map(|(host, port)| WireAddress { host, port }),
            ),
            payload in proptest::collection::vec(any::<u8>(), 0..=300),
        ) {
            let frag_id = frag_id_seed % frag_total;
            let datagram = encode_packet(assoc_id, pkt_id, frag_total, frag_id, address.as_ref(), &payload)
                .expect("encode");
            let cmd = decode_packet(&datagram).expect("decode");
            prop_assert_eq!(cmd.assoc_id, assoc_id);
            prop_assert_eq!(cmd.pkt_id, pkt_id);
            prop_assert_eq!(cmd.frag_total, frag_total);
            prop_assert_eq!(cmd.frag_id, frag_id);
            prop_assert_eq!(cmd.address, address);
            prop_assert_eq!(cmd.payload, payload.as_slice());
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..=400)) {
            // Both decoders must reject malformed input without panicking or
            // reading out of bounds.
            let _ = decode_packet(&data);
            let _ = decode_address(&data);
        }

        #[test]
        fn fragments_reassemble_property(
            payload in proptest::collection::vec(any::<u8>(), 0..=1500),
            max_datagram_len in 600usize..=1500,
            assoc_id in any::<u16>(),
            pkt_id in any::<u16>(),
        ) {
            let host = Addr::Domain("prop.example".into());
            let port = 0xBEEF;
            let datagrams = encode_fragments(assoc_id, pkt_id, &host, port, &payload, max_datagram_len)
                .expect("fragmentation plan");
            let mut by_id = datagrams
                .iter()
                .map(|d| decode_packet(d).expect("fragment decodes"))
                .map(|c| (c.frag_id, c))
                .collect::<Vec<_>>();
            by_id.sort_by_key(|(id, _)| *id);
            let mut reassembled = Vec::new();
            for (idx, (_, cmd)) in by_id.iter().enumerate() {
                prop_assert_eq!(cmd.assoc_id, assoc_id);
                prop_assert_eq!(cmd.pkt_id, pkt_id);
                prop_assert_eq!(cmd.frag_total as usize, datagrams.len());
                prop_assert_eq!(idx, cmd.frag_id as usize);
                if idx == 0 {
                    prop_assert_eq!(cmd.address.clone(), Some(WireAddress { host: host.clone(), port }));
                } else {
                    prop_assert!(cmd.address.is_none());
                }
                reassembled.extend_from_slice(cmd.payload);
            }
            prop_assert_eq!(reassembled, payload);
        }
    }

    fn host_strategy() -> impl proptest::strategy::Strategy<Value = Addr> {
        proptest::prelude::prop_oneof![
            proptest::prelude::any::<Ipv4Addr>().prop_map(|ip| Addr::Ip(IpAddr::V4(ip))),
            proptest::prelude::any::<Ipv6Addr>().prop_map(|ip| Addr::Ip(IpAddr::V6(ip))),
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..16)
                .prop_map(|chars| Addr::Domain(chars.into_iter().collect())),
        ]
    }
}
