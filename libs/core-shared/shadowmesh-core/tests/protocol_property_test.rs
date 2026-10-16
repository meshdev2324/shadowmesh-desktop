//! Property-based tests for ShadowMesh custom protocol suites.
//!
//! Implementation Source:
//! - Specifications: VLESS / VMess / Trojan / Shadowsocks AEAD (SIP007) public specs
//! - RFC 5869 (HKDF), RFC 8439 (ChaCha20-Poly1305)
//! - Relevant sections: handshake header parsing, AEAD chunk framing, KDF
//! - Security considerations: parsers must be total on arbitrary bytes (no panic),
//!   round-trips must preserve data exactly, framing must reject oversized chunks.
//!
//! Independent implementation for ShadowMesh Core.

use base64::Engine;
use proptest::prelude::*;

use shadowmesh_core::engine::metadata::{Addr, Endpoint};
use shadowmesh_core::protocol::binary::{decode_node_list, encode_node_list, VPNNodeBorrowed};
use shadowmesh_core::protocol::shadowsocks::{ShadowsocksCipher, ShadowsocksMethod, TAG_SIZE};
use shadowmesh_core::transport::hysteria::{BrutalConfig, BrutalController, HysteriaObfuscator};
use shadowmesh_core::transport::inbound::shadowsocks::parse_ss_address;
use shadowmesh_core::transport::inbound::trojan::parse_trojan_handshake;
use shadowmesh_core::transport::inbound::vmess::{parse_vless_handshake, parse_vmess_header};
use shadowmesh_core::transport::outbound::vmess::VmessStream;
use shadowmesh_core::VPNNode;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// Arbitrary endpoint address generator: IPv4, IPv6, or printable ASCII domain.
fn arb_addr() -> impl Strategy<Value = Addr> {
    prop_oneof![
        (any::<u32>()).prop_map(|a| {
            Addr::Ip(IpAddr::V4(Ipv4Addr::new(
                (a >> 24) as u8,
                (a >> 16) as u8,
                (a >> 8) as u8,
                a as u8,
            )))
        }),
        any::<[u8; 16]>().prop_map(|o| Addr::Ip(IpAddr::V6(Ipv6Addr::from(o)))),
        "[a-zA-Z0-9.-]{1,60}".prop_map(Addr::Domain),
    ]
}

fn arb_endpoint() -> impl Strategy<Value = Endpoint> {
    (arb_addr(), any::<u16>()).prop_map(|(addr, port)| Endpoint { addr, port })
}

fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..2048)
}

fn arb_uuid() -> impl Strategy<Value = uuid::Uuid> {
    any::<[u8; 16]>().prop_map(uuid::Uuid::from_bytes)
}

/// Every method the protocol module models, in the order of SIP022's list.
///
/// `arb_ss_method` deliberately covers only the two SIP007 AEAD-2017 methods,
/// because `encrypt_udp`/`decrypt_udp` refuse the 2022 edition. Assertions
/// about **method parameters** must range over this list instead: a generator
/// that only yields `Aes256Gcm` and `ChaCha20Poly1305` makes
/// `key_len() == 32` true by construction, because both of those return 32.
const ALL_SS_METHODS: [ShadowsocksMethod; 5] = [
    ShadowsocksMethod::Aes256Gcm,
    ShadowsocksMethod::ChaCha20Poly1305,
    ShadowsocksMethod::Aes128Gcm2022,
    ShadowsocksMethod::Aes256Gcm2022,
    ShadowsocksMethod::ChaCha20Poly13052022,
];

/// The key length each method's specification mandates. If `key_len()` is
/// edited, this table stops matching and the property fails.
const SPEC_KEY_LEN: [(ShadowsocksMethod, usize); 5] = [
    (ShadowsocksMethod::Aes256Gcm, 32),
    (ShadowsocksMethod::ChaCha20Poly1305, 32),
    // SIP022 section 4: `2022-blake3-aes-128-gcm` is the one method with a
    // 16-byte key. It is the case a constant-32 assertion could never see.
    (ShadowsocksMethod::Aes128Gcm2022, 16),
    (ShadowsocksMethod::Aes256Gcm2022, 32),
    (ShadowsocksMethod::ChaCha20Poly13052022, 32),
];

/// A strategy over **all five** methods. Use this for anything asserting a
/// per-method parameter; use [`arb_ss_method`] only for the SIP007 paths.
fn arb_all_ss_method() -> impl Strategy<Value = ShadowsocksMethod> {
    proptest::sample::select(ALL_SS_METHODS.to_vec())
}

/// The SIP007 AEAD-2017 methods — the only ones `encrypt_udp`/`decrypt_udp`
/// accept. Both have a 32-byte key, so **no key-length assertion may use
/// this generator**: it would be constant by construction.
fn arb_ss_method() -> impl Strategy<Value = ShadowsocksMethod> {
    prop_oneof![Just(ShadowsocksMethod::Aes256Gcm), Just(ShadowsocksMethod::ChaCha20Poly1305),]
}

/// Serializes an `Endpoint` as the SOCKS-style `ATYP || addr || port` trailer
/// used by Trojan and Shadowsocks.
fn encode_addr_then_port(ep: &Endpoint) -> Vec<u8> {
    let mut out = encode_atyp_addr(&ep.addr);
    out.extend_from_slice(&ep.port.to_be_bytes());
    out
}

/// Serializes only `ATYP || addr` (no port) — the VLESS/VMess layout pairs this
/// with the port placed *before* it.
fn encode_atyp_addr(addr: &Addr) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 255);
    match addr {
        Addr::Ip(IpAddr::V4(ip)) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        Addr::Ip(IpAddr::V6(ip)) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
        Addr::Domain(d) => {
            out.push(0x03);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
    }
    out
}

/// Serializes an `Endpoint` in the VLESS/VMess wire order: `port || ATYP || addr`.
fn encode_port_then_addr(ep: &Endpoint) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 1 + 255);
    out.extend_from_slice(&ep.port.to_be_bytes());
    out.extend_from_slice(&encode_atyp_addr(&ep.addr));
    out
}

// ---------------------------------------------------------------------------
// Shared address parser (Shadowsocks) — parse/serialize round-trip
// ---------------------------------------------------------------------------

proptest! {
    /// For every endpoint, wire-encoding then parsing must yield the identical
    /// endpoint, and the parser must consume exactly the bytes it produced.
    #[test]
    fn prop_ss_address_roundtrip(ep in arb_endpoint()) {
        let wire = encode_addr_then_port(&ep);
        let (rest, parsed) = parse_ss_address(&wire)
            .map_err(|_| TestCaseError::fail("valid wire input rejected"))?;
        prop_assert!(rest.is_empty(), "parser left {}/{} bytes unconsumed", rest.len(), wire.len());
        prop_assert_eq!(parsed, ep);
    }

    /// Prefixing a valid address with a valid address must still parse the
    /// first address and leave the remainder untouched (streaming invariant).
    #[test]
    fn prop_ss_address_streaming(ep in arb_endpoint(), tail in arb_payload()) {
        let mut wire = encode_addr_then_port(&ep);
        wire.extend_from_slice(&tail);
        let (rest, parsed) = parse_ss_address(&wire)
            .map_err(|_| TestCaseError::fail("valid wire input rejected"))?;
        prop_assert_eq!(parsed, ep);
        prop_assert_eq!(rest, tail.as_slice());
    }

    /// Truncating a valid encoding at any byte length must never panic; it may
    /// only fail cleanly (too short) — a totality property for the parser.
    #[test]
    fn prop_ss_address_truncated_never_panics(ep in arb_endpoint()) {
        let wire = encode_addr_then_port(&ep);
        for cut in 0..wire.len() {
            let _ = parse_ss_address(&wire[..cut]);
        }
    }
}

// ---------------------------------------------------------------------------
// VLESS handshake parser
// ---------------------------------------------------------------------------

proptest! {
    /// A well-formed VLESS header must round-trip: version 0, UUID, addons,
    /// command, endpoint — with any trailing payload preserved verbatim.
    #[test]
    fn prop_vless_handshake_roundtrip(
        uuid in arb_uuid(),
        cmd in any::<u8>(),
        ep in arb_endpoint(),
        addons in proptest::collection::vec(any::<u8>(), 0..255),
        payload in arb_payload(),
    ) {
        let mut wire = Vec::with_capacity(32 + addons.len() + payload.len());
        wire.push(0x00); // version
        wire.extend_from_slice(uuid.as_bytes());
        wire.push(addons.len() as u8);
        wire.extend_from_slice(&addons);
        wire.push(cmd);
        wire.extend_from_slice(&encode_port_then_addr(&ep));
        wire.extend_from_slice(&payload);

        let (rest, req) = parse_vless_handshake(&wire)
            .map_err(|_| TestCaseError::fail("valid VLESS wire rejected"))?;
        prop_assert_eq!(req.uuid, uuid);
        prop_assert_eq!(req.cmd, cmd);
        prop_assert_eq!(req.destination, ep);
        prop_assert_eq!(rest, payload.as_slice());
    }

    /// Any non-zero version byte must be rejected without panicking.
    #[test]
    fn prop_vless_rejects_bad_version(
        ver in 1u8..=255,
        uuid in arb_uuid(),
        ep in arb_endpoint(),
    ) {
        let mut wire = vec![ver];
        wire.extend_from_slice(uuid.as_bytes());
        wire.push(0x00);
        wire.push(0x01);
        wire.extend_from_slice(&encode_port_then_addr(&ep));
        prop_assert!(parse_vless_handshake(&wire).is_err());
    }

    /// Arbitrary truncations of a valid header must never panic.
    #[test]
    fn prop_vless_truncated_never_panics(
        uuid in arb_uuid(),
        ep in arb_endpoint(),
    ) {
        let mut wire = vec![0x00];
        wire.extend_from_slice(uuid.as_bytes());
        wire.push(0x00);
        wire.push(0x01);
        wire.extend_from_slice(&encode_port_then_addr(&ep));
        for cut in 0..wire.len() {
            let _ = parse_vless_handshake(&wire[..cut]);
        }
    }
}

// ---------------------------------------------------------------------------
// VMess request header parser
// ---------------------------------------------------------------------------

proptest! {
    /// A well-formed VMess request header must round-trip with padding and
    /// security nibbles decoded from the packed P/S byte, and trailing payload
    /// preserved.
    #[test]
    fn prop_vmess_header_roundtrip(
        request_iv in any::<[u8; 16]>(),
        request_key in any::<[u8; 16]>(),
        padding_len in 0u8..16,
        security_type in 0u8..16,
        cmd in any::<u8>(),
        ep in arb_endpoint(),
        payload in arb_payload(),
    ) {
        let mut wire = Vec::with_capacity(64 + payload.len());
        wire.push(0x01); // version
        wire.extend_from_slice(&request_iv);
        wire.extend_from_slice(&request_key);
        wire.push(0x00); // response header hash
        wire.push(0x01); // option
        wire.push((padding_len << 4) | security_type);
        wire.push(0x00); // reserved
        wire.push(cmd);
        wire.extend_from_slice(&encode_port_then_addr(&ep));
        wire.extend_from_slice(&payload);

        let (rest, hdr) = parse_vmess_header(&wire)
            .map_err(|_| TestCaseError::fail("valid VMess header rejected"))?;
        prop_assert_eq!(hdr.version, 0x01);
        prop_assert_eq!(hdr.request_iv, request_iv);
        prop_assert_eq!(hdr.request_key, request_key);
        prop_assert_eq!(hdr.padding_len, padding_len);
        prop_assert_eq!(hdr.security_type, security_type);
        prop_assert_eq!(hdr.cmd, cmd);
        prop_assert_eq!(hdr.port, ep.port);
        prop_assert_eq!(hdr.destination, ep);
        prop_assert_eq!(rest, payload.as_slice());
    }

    /// Arbitrary truncations must never panic.
    #[test]
    fn prop_vmess_header_truncated_never_panics(ep in arb_endpoint()) {
        let mut wire = vec![0x01];
        wire.extend_from_slice(&[0u8; 16]);
        wire.extend_from_slice(&[0u8; 16]);
        wire.extend_from_slice(&[0x00, 0x01, 0x33, 0x00, 0x01]);
        wire.extend_from_slice(&encode_port_then_addr(&ep));
        for cut in 0..wire.len() {
            let _ = parse_vmess_header(&wire[..cut]);
        }
    }
}

// ---------------------------------------------------------------------------
// Trojan handshake parser
// ---------------------------------------------------------------------------

proptest! {
    /// A well-formed Trojan header (56-hex-char hash, CRLF, cmd, endpoint,
    /// CRLF) must round-trip with payload preserved.
    #[test]
    fn prop_trojan_handshake_roundtrip(
        hash in "[0-9a-f]{56}",
        cmd in any::<u8>(),
        ep in arb_endpoint(),
        payload in arb_payload(),
    ) {
        let mut wire = Vec::with_capacity(64 + payload.len());
        wire.extend_from_slice(hash.as_bytes());
        wire.extend_from_slice(b"\r\n");
        wire.push(cmd);
        wire.extend_from_slice(&encode_addr_then_port(&ep));
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(&payload);

        let (rest, req) = parse_trojan_handshake(&wire)
            .map_err(|_| TestCaseError::fail("valid Trojan wire rejected"))?;
        prop_assert_eq!(req.password_hash, hash);
        prop_assert_eq!(req.cmd, cmd);
        prop_assert_eq!(req.destination, ep);
        prop_assert_eq!(rest, payload.as_slice());
    }

    /// Arbitrary truncations must never panic.
    #[test]
    fn prop_trojan_truncated_never_panics(hash in "[0-9a-f]{56}", ep in arb_endpoint()) {
        let mut wire: Vec<u8> = hash.as_bytes().to_vec();
        wire.extend_from_slice(b"\r\n");
        wire.push(0x01);
        wire.extend_from_slice(&encode_addr_then_port(&ep));
        wire.extend_from_slice(b"\r\n");
        for cut in 0..wire.len() {
            let _ = parse_trojan_handshake(&wire[..cut]);
        }
    }
}

// ---------------------------------------------------------------------------
// Shadowsocks AEAD (SIP007) — KDF + UDP packet encryption
// ---------------------------------------------------------------------------

proptest! {
    /// HKDF-SHA1 subkey derivation must be deterministic for a fixed
    /// (password, salt) pair and must depend on every salt bit.
    ///
    /// This is the SIP007 path only. The key length is asserted here against
    /// the per-method table in `prop_ss_key_and_salt_len_match_the_spec`, not
    /// as a literal `32`: the generator only ever yields two methods and both
    /// return 32, so `key_len() == 32` is true by construction and would pass
    /// whatever `key_len()` returned.
    #[test]
    fn prop_ss_kdf_deterministic(
        method in arb_ss_method(),
        password in "[a-zA-Z0-9_-]{1,32}",
        salt in any::<[u8; 32]>(),
    ) {
        let a = ShadowsocksCipher::new(method, &password, &salt)
            .map_err(|e| TestCaseError::fail(format!("KDF failed: {e}")))?;
        let b = ShadowsocksCipher::new(method, &password, &salt)
            .map_err(|e| TestCaseError::fail(format!("KDF failed: {e}")))?;

        // Determinism: same inputs → identical subkey digest.
        prop_assert_eq!(a.subkey_digest(), b.subkey_digest());

        // Salt sensitivity: flipping one salt bit must change the subkey.
        let mut salt2 = salt;
        salt2[0] ^= 1;
        let c = ShadowsocksCipher::new(method, &password, &salt2)
            .map_err(|e| TestCaseError::fail(format!("KDF failed: {e}")))?;
        prop_assert_ne!(a.subkey_digest(), c.subkey_digest());
    }

    /// Every method's `key_len()` must equal the length its specification
    /// mandates, and `salt_len()` must follow from it.
    ///
    /// This is the assertion that *can* fail where `key_len() == 32` could not.
    /// `ShadowsocksMethod::Aes128Gcm2022` is the discriminator: SIP022 gives it
    /// a 16-byte key, so a generator that covers it turns a tautology into a
    /// real check. If `key_len()` were edited — say `Aes128Gcm2022` widened to
    /// 32 to match its siblings — this fails immediately.
    #[test]
    fn prop_ss_key_and_salt_len_match_the_spec(method in arb_all_ss_method()) {
        let expected = SPEC_KEY_LEN
            .iter()
            .find(|(m, _)| *m == method)
            .map(|(_, len)| *len)
            .unwrap_or_else(|| panic!("{} is missing from SPEC_KEY_LEN", method.wire_name()));

        prop_assert_eq!(
            method.key_len(),
            expected,
            "{} must have a {}-byte key",
            method.wire_name(),
            expected
        );

        // SIP022 section 2.2: "the salt has the same length as the pre-shared
        // key". SIP007 fixes the salt at 32 bytes regardless of key length.
        let want_salt = if method.is_2022() { method.key_len() } else { 32 };
        prop_assert_eq!(
            method.salt_len(),
            want_salt,
            "{} has the wrong salt length",
            method.wire_name()
        );

        // The table itself must stay non-degenerate: if every entry became 32
        // the generator would once again be unable to fail anything.
        prop_assert!(
            SPEC_KEY_LEN.iter().any(|(_, len)| *len != 32),
            "SPEC_KEY_LEN has lost its non-32 entry, so this property is constant again"
        );
    }

    /// The 2022-edition KDF must also be deterministic and salt-sensitive, and
    /// it must *refuse* a salt of the wrong length rather than deriving a
    /// subkey no conforming peer could reproduce.
    #[test]
    fn prop_ss2022_kdf_is_deterministic_and_salt_sensitive(method in arb_all_ss_method().prop_filter("2022 edition only", |m| m.is_2022())) {
        let key_len = method.key_len();
        let salt_len = method.salt_len();
        // The 2022 constructor takes the pre-shared key base64-encoded.
        let psk = base64::engine::general_purpose::STANDARD.encode(vec![0xABu8; key_len]);
        let salt: Vec<u8> = (0..salt_len).map(|i| i as u8).collect();

        let a = ShadowsocksCipher::new(method, &psk, &salt)
            .map_err(|e| TestCaseError::fail(format!("2022 KDF failed: {e}")))?;
        let b = ShadowsocksCipher::new(method, &psk, &salt)
            .map_err(|e| TestCaseError::fail(format!("2022 KDF failed: {e}")))?;
        prop_assert_eq!(a.subkey_digest(), b.subkey_digest(), "2022 KDF is not deterministic");

        let mut salt2 = salt.clone();
        salt2[0] ^= 1;
        let c = ShadowsocksCipher::new(method, &psk, &salt2)
            .map_err(|e| TestCaseError::fail(format!("2022 KDF failed: {e}")))?;
        prop_assert_ne!(a.subkey_digest(), c.subkey_digest(), "2022 KDF ignores a salt bit");

        // A salt of the wrong length must fail closed. This is the branch that
        // the previous `salt in any::<[u8; 32]>()` generator could not reach for
        // Aes128Gcm2022 at all, because its correct salt is 16 bytes.
        let wrong: Vec<u8> = (0..salt_len + 1).map(|i| i as u8).collect();
        prop_assert!(
            ShadowsocksCipher::new(method, &psk, &wrong).is_err(),
            "{} accepted a {}-byte salt",
            method.wire_name(),
            wrong.len()
        );
    }

    /// UDP encrypt/decrypt round-trip must be lossless for arbitrary payloads
    /// across both AEAD methods, and ciphertext must differ from plaintext.
    #[test]
    fn prop_ss_udp_roundtrip(
        method in arb_ss_method(),
        password in "[a-zA-Z0-9_-]{1,32}",
        payload in arb_payload(),
    ) {
        let ct = ShadowsocksCipher::encrypt_udp(method, &password, &payload)
            .map_err(|e| TestCaseError::fail(format!("encrypt failed: {e}")))?;
        let pt = ShadowsocksCipher::decrypt_udp(method, &password, &ct)
            .map_err(|e| TestCaseError::fail(format!("decrypt failed: {e}")))?;

        prop_assert_eq!(pt, payload.clone());
        prop_assert!(ct.len() >= method.salt_len() + payload.len() + TAG_SIZE);
        if !payload.is_empty() {
            prop_assert_ne!(&ct[method.salt_len()..][..payload.len().min(ct.len() - method.salt_len())], payload.as_slice());
        }

        // Tampering with any single ciphertext byte must fail authentication.
        // Sample at most 32 positions per case: full-byte exhaustive tampering
        // is covered by the shadowsocks_udp_packet fuzz target.
        let positions: Vec<usize> = if ct.len() <= 32 {
            (0..ct.len()).collect()
        } else {
            (0..32).map(|i| i * ct.len() / 32).collect()
        };
        for idx in positions {
            let mut tampered = ct.clone();
            tampered[idx] ^= 0x01;
            prop_assert!(
                ShadowsocksCipher::decrypt_udp(method, &password, &tampered).is_err(),
                "tampered byte {idx} accepted"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// VMess AEAD chunk stream (VmessStream) — framing round-trip
// ---------------------------------------------------------------------------

proptest! {
    /// Data written through VmessStream must be read back byte-identical
    /// through a duplex, for arbitrary payloads (multi-chunk included).
    /// Reader runs concurrently with the writer — payloads near the duplex
    /// capacity would otherwise deadlock a strictly sequential test.
    #[test]
    fn prop_vmess_stream_roundtrip(
        key in any::<[u8; 16]>(),
        iv in any::<[u8; 16]>(),
        payload in proptest::collection::vec(any::<u8>(), 0..16384),
    ) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| TestCaseError::fail(format!("runtime build failed: {e}")))?
            .block_on(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                let (client_io, server_io) = tokio::io::duplex(8192);
                let mut a = VmessStream::new(client_io, key, iv).unwrap();
                let mut b = VmessStream::new(server_io, key, iv).unwrap();

                // Writer on a spawned task so >8 KiB payloads can be pumped
                // while the reader drains the duplex concurrently.
                let payload_out = payload.clone();
                let writer = tokio::task::spawn(async move {
                    a.write_all(&payload_out).await
                        .map_err(|e| TestCaseError::fail(format!("write failed: {e}")))?;
                    a.flush().await
                        .map_err(|e| TestCaseError::fail(format!("flush failed: {e}")))?;
                    Ok::<(), TestCaseError>(())
                });

                let mut received = vec![0u8; payload.len()];
                if !payload.is_empty() {
                    b.read_exact(&mut received).await
                        .map_err(|e| TestCaseError::fail(format!("read failed: {e}")))?;
                }
                writer
                    .await
                    .map_err(|e| TestCaseError::fail(format!("writer join failed: {e}")))??;
                prop_assert_eq!(received, payload.clone());

                // Reverse direction on a fresh duplex pair (the first pair's
                // writer halves were consumed by the tasks above).
                let (client_io2, server_io2) = tokio::io::duplex(8192);
                let mut c = VmessStream::new(client_io2, key, iv).unwrap();
                let mut d = VmessStream::new(server_io2, key, iv).unwrap();

                let payload_back = payload.clone();
                let writer = tokio::task::spawn(async move {
                    d.write_all(&payload_back).await
                        .map_err(|e| TestCaseError::fail(format!("reverse write failed: {e}")))?;
                    d.flush().await
                        .map_err(|e| TestCaseError::fail(format!("reverse flush failed: {e}")))?;
                    Ok::<(), TestCaseError>(())
                });

                let mut echoed = vec![0u8; payload.len()];
                if !payload.is_empty() {
                    c.read_exact(&mut echoed).await
                        .map_err(|e| TestCaseError::fail(format!("reverse read failed: {e}")))?;
                }
                writer
                    .await
                    .map_err(|e| TestCaseError::fail(format!("writer join failed: {e}")))??;
                prop_assert_eq!(echoed, payload);

                Ok(())
            })?;
    }
}

// ---------------------------------------------------------------------------
// Hysteria — XOR obfuscation and Brutal pacing invariants
// ---------------------------------------------------------------------------

proptest! {
    /// XOR obfuscation must be an involution for arbitrary keys and data.
    #[test]
    fn prop_hysteria_obfuscation_involution(
        key in "[a-zA-Z0-9_-]{1,64}",
        data in arb_payload(),
    ) {
        let obf = HysteriaObfuscator::new(&key);
        let mut buf = data.clone();
        obf.obfuscate_in_place(&mut buf);
        if !data.is_empty() {
            prop_assert_ne!(buf.clone(), data.clone(), "obfuscation must change data");
        }
        obf.deobfuscate_in_place(&mut buf);
        prop_assert_eq!(buf, data);
    }

    /// Brutal pacing must never demand a wait longer than the time to
    /// transmit the same bytes at the configured rate.
    #[test]
    fn prop_brutal_pacing_bounded(
        bps in 1_000_000u64..=100_000_000,
        bytes in 1u64..=100_000,
    ) {
        let mut ctrl = BrutalController::new(BrutalConfig { up_bps: bps });
        let now = std::time::Instant::now();
        let wait = ctrl.on_transmit(now, bytes);
        let max_wait = std::time::Duration::from_secs_f64(bytes as f64 / bps as f64);
        prop_assert!(wait <= max_wait, "wait {wait:?} exceeded transmit time {max_wait:?}");
        prop_assert!(wait > std::time::Duration::ZERO, "first transmit must be paced");
    }
}

// ---------------------------------------------------------------------------
// Binary node-list codec — fuzz-resistant decoding
// ---------------------------------------------------------------------------

proptest! {
    /// Arbitrary corrupted encodings must be rejected (or tolerated) without
    /// panicking; a valid round-trip must still succeed afterwards.
    #[test]
    fn prop_binary_corrupt_never_panics(
        seed in any::<u64>(),
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = seed;
        let _ = decode_node_list(&data);
        let _ = decode_node_list(&[b'S', b'M', b'B', 0x01]);
        // Valid round-trip after adversarial inputs.
        let node = VPNNode {
            id: "node-1".into(),
            name: "Test Node".into(),
            region: "eu".into(),
            country: "DE".into(),
            endpoint: "10.0.0.1:51820".into(),
            public_key: "pk".into(),
            load: 10,
            latency: 20,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        };
        let encoded = encode_node_list(&[VPNNodeBorrowed::from(&node)])
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        let decoded = decode_node_list(&encoded)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(decoded.len(), 1);
        let restored = decoded[0].to_owned();
        prop_assert_eq!(restored.id, node.id);
        prop_assert_eq!(restored.endpoint, node.endpoint);
        prop_assert_eq!(restored.load, node.load);
        prop_assert_eq!(restored.is_online, node.is_online);
    }
}
