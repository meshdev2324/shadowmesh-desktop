//! Browser-shaped ClientHello profiles.
//!
//! # What is wrong today
//!
//! `reality_tls.rs` hand-builds a ClientHello with a deliberately minimal
//! extension set. That is a *stronger* fingerprint than a stock library's, not a
//! weaker one: a real browser ClientHello carries a long, version-specific list
//! of extensions in a specific order, several of them GREASE-padded, and a
//! cipher list ordered by the browser's own preference. A minimal hello with
//! three or four extensions is something no browser emits, which is a cheap
//! classification for DPI.
//!
//! This corrects an earlier claim in this project that the client "sends
//! rustls' own distinctive ClientHello". It does not. It sends a hand-rolled
//! minimal one, and the remedy is the same in kind: make the hello look like
//! what a browser actually sends.
//!
//! # What this module is and is not
//!
//! This is **profile-driven ClientHello shaping**, not uTLS. uTLS is a Rust
//! library that intercepts a TLS stack's ClientHello and rewrites it. That
//! requires owning the handshake, which is a much larger change. What is built
//! here is the data: per-browser extension sets, their order, GREASE values, and
//! cipher preferences, plus the machinery to emit them.
//!
//! It is honest about the limit: shaped-but-not-uTLS. A determined adversary
//! comparing byte-level layout against a known browser build can still tell. The
//! realistic gain is that a hello carrying Chrome's actual extension list and
//! ordering stops being trivially classifiable, which is what cheap DPI does.
//!
//! # GREASE
//!
//! Chrome deliberately pads its ClientHello with meaningless values whose
//! high and low bytes are equal (0x0a0a, 0x1a1a, ... 0xfafa). Browsers have done
//! this since version 25 specifically to stop extension-list fingerprinting.
//! Omitting GREASE is one of the most recognisable signs of a hand-rolled hello,
//! so it is modelled explicitly and randomly, exactly as a browser does.
//!
//! # Clean-room
//!
//! Extension identifiers and orderings are public protocol facts, taken from the
//! IETF TLS registry and observed browser behaviour. No third-party uTLS source
//! is consulted or ingested.

/// A GREASE value, as defined by RFC 8701. The high and low bytes are equal and
/// the value is `0x?A?A` for a hex digit A.
pub const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// True when `value` is a GREASE placeholder.
pub fn is_grease(value: u16) -> bool {
    GREASE_VALUES.contains(&value)
}

/// A random GREASE value. A browser picks one per position, not one per hello,
/// which is what defeats a static signature.
pub fn random_grease(rng: &mut impl FnMut() -> u8) -> u16 {
    GREASE_VALUES[(rng() as usize) % GREASE_VALUES.len()]
}

/// Which browser to imitate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProfile {
    /// Chrome and other Chromium derivatives, recent versions.
    Chrome,
    /// Firefox.
    Firefox,
}

impl BrowserProfile {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "chrome" | "chromium" | "edge" => Some(Self::Chrome),
            "firefox" => Some(Self::Firefox),
            _ => None,
        }
    }

    /// Non-GREASE extensions, in the order the browser sends them.
    ///
    /// Order is not cosmetic. A browser's extension order is stable per version
    /// and is itself a fingerprint; presenting the right set in the wrong order
    /// is nearly as suspicious as presenting the wrong set.
    pub fn extension_order(self) -> &'static [u16] {
        match self {
            // server_name, extended_master_secret, renegotiation_info,
            // supported_groups, ec_point_formats, session_ticket,
            // ALPN, status_request, signature_algorithms, supported_versions,
            // key_share, psk_key_exchange_modes, session_ticket,
            // compress_certificate, application_settings, ALPS,
            // padding, and delegated_credentials.
            Self::Chrome => &[
                0x0000, // server_name
                0x0017, // extended_master_secret
                0xff01, // renegotiation_info
                0x000a, // supported_groups
                0x000b, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // ALPN
                0x0005, // status_request
                0x000d, // signature_algorithms
                0x002b, // supported_versions
                0x0033, // key_share
                0x002d, // psk_key_exchange_modes
                0x001b, // compress_certificate
                0x446f, // application_settings (ALPS)
                0x0029, // pre_shared_key
                0x0015, // padding
                0x0030, // delegated_credentials
            ],
            Self::Firefox => &[
                0x0000, // server_name
                0x0017, // extended_master_secret
                0x000a, // supported_groups
                0x000b, // ec_point_formats
                0x000d, // signature_algorithms
                0x002b, // supported_versions
                0x0033, // key_share
                0x0010, // ALPN
                0x0023, // session_ticket
                0x0005, // status_request
                0x000f, // heartbeat
            ],
        }
    }

    /// Cipher suites, in the browser's preference order.
    pub fn ciphers(self) -> &'static [u16] {
        match self {
            Self::Chrome => &[
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            ],
            Self::Firefox => {
                &[0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030]
            }
        }
    }

    /// Supported groups, in preference order.
    pub fn groups(self) -> &'static [u16] {
        match self {
            Self::Chrome => &[0x001d, 0x0017, 0x0018], // x25519, secp256r1, secp384r1
            Self::Firefox => &[0x001d, 0x0017, 0x0018],
        }
    }

    /// ALPN protocols a browser offers.
    pub fn alpn(self) -> &'static [&'static [u8]] {
        match self {
            Self::Chrome => &[b"h2", b"http/1.1"],
            Self::Firefox => &[b"h2", b"http/1.1"],
        }
    }
}

/// The shaping decision for one ClientHello.
#[derive(Debug, Clone)]
pub struct HelloShape {
    pub profile: BrowserProfile,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
}

impl HelloShape {
    /// Build a shape for `profile`, inserting GREASE at the positions a browser
    /// uses it.
    ///
    /// Chrome places GREASE at the first and last extension positions and around
    /// the version list. Emulating that is what stops a static signature.
    pub fn build(profile: BrowserProfile, rng: &mut impl FnMut() -> u8) -> Self {
        // GREASE values are distinct within one ClientHello. A repeated padding
        // value is not something a browser emits, and a constant RNG makes a
        // collision certain rather than rare - a test caught exactly that.
        fn pick(rng: &mut impl FnMut() -> u8, used: &mut Vec<u16>) -> u16 {
            // Each retry advances the index as well as re-rolling, so a
            // pathological generator that always returns the same byte still
            // yields distinct values. Re-rolling alone would loop through all
            // sixteen candidates, find them all used, and then fall back to the
            // duplicate it was avoiding.
            for attempt in 0..GREASE_VALUES.len() {
                let roll = rng() as usize;
                let candidate = GREASE_VALUES[(roll + attempt) % GREASE_VALUES.len()];
                if !used.contains(&candidate) {
                    used.push(candidate);
                    return candidate;
                }
            }
            // Unreachable for two positions; kept total rather than panicking.
            let fallback = GREASE_VALUES[0];
            used.push(fallback);
            fallback
        }

        let mut used: Vec<u16> = Vec::new();
        let mut extensions = Vec::with_capacity(profile.extension_order().len() + 2);
        extensions.push(pick(rng, &mut used));
        for ext in profile.extension_order() {
            if !extensions.contains(ext) {
                extensions.push(*ext);
            }
        }
        extensions.push(pick(rng, &mut used));

        Self { profile, ciphers: profile.ciphers().to_vec(), extensions }
    }

    /// The cipher list, GREASE-padded as Chrome does.
    pub fn cipher_bytes(&self, rng: &mut impl FnMut() -> u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.ciphers.len() * 2 + 4);
        out.extend_from_slice(&((self.ciphers.len() * 2 + 2) as u16).to_be_bytes());
        out.extend_from_slice(&random_grease(rng).to_be_bytes());
        for c in &self.ciphers {
            out.extend_from_slice(&c.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_is_resolvable() {
        assert_eq!(BrowserProfile::from_name("chrome"), Some(BrowserProfile::Chrome));
        assert_eq!(BrowserProfile::from_name("Chrome"), Some(BrowserProfile::Chrome));
        assert_eq!(BrowserProfile::from_name("  FIREFOX "), Some(BrowserProfile::Firefox));
        assert_eq!(BrowserProfile::from_name("safari"), None);
    }

    /// RFC 8701: high and low bytes are equal.
    #[test]
    fn grease_values_are_well_formed() {
        for v in GREASE_VALUES {
            assert_eq!(v >> 8, v & 0xFF, "{v:#06x} is not a GREASE value");
            assert!(is_grease(v));
        }
    }

    #[test]
    fn non_grease_values_are_rejected() {
        for v in [0x0000u16, 0x0017, 0x1301, 0x0a0b, 0xaaaa + 1] {
            assert!(!is_grease(v), "{v:#06x} misidentified as GREASE");
        }
    }

    #[test]
    fn random_grease_stays_in_range() {
        let mut i = 0u32;
        let mut rng = || {
            i = i.wrapping_add(1);
            (i * 37 % 251) as u8
        };
        for _ in 0..500 {
            assert!(is_grease(random_grease(&mut rng)));
        }
    }

    /// A hello with no GREASE is one of the most recognisable signs of a
    /// hand-rolled ClientHello.
    #[test]
    fn every_shape_carries_grease() {
        for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
            let mut rng = || 3u8;
            let shape = HelloShape::build(profile, &mut rng);
            assert!(
                shape.extensions.iter().any(|e| is_grease(*e)),
                "{profile:?} produced a hello with no GREASE"
            );
        }
    }

    #[test]
    fn server_name_is_always_present() {
        // Without server_name the TLS handshake cannot proceed, and its absence
        // is itself a fingerprint.
        for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
            assert!(profile.extension_order().contains(&0x0000));
        }
    }

    #[test]
    fn key_share_and_alpn_are_always_present() {
        for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
            assert!(profile.extension_order().contains(&0x0033), "{profile:?} missing key_share");
            assert!(profile.extension_order().contains(&0x0010), "{profile:?} missing ALPN");
        }
    }

    /// A duplicate extension is a protocol violation and a fingerprint in itself.
    /// This also covers the GREASE padding, which must be distinct within one
    /// hello. A constant RNG makes collisions certain, which is why the test
    /// uses one deliberately.
    #[test]
    fn shapes_contain_no_duplicate_extensions() {
        for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
            let mut rng = || 1u8;
            let shape = HelloShape::build(profile, &mut rng);
            let mut seen = std::collections::HashSet::new();
            for ext in &shape.extensions {
                assert!(seen.insert(*ext), "{profile:?} repeated extension {ext:#06x}");
            }
        }
    }

    #[test]
    fn extension_order_is_preserved_from_the_profile() {
        let mut rng = || 2u8;
        let shape = HelloShape::build(BrowserProfile::Chrome, &mut rng);
        let expected: Vec<u16> = BrowserProfile::Chrome
            .extension_order()
            .iter()
            .copied()
            .filter(|e| !is_grease(*e))
            .collect();
        let actual: Vec<u16> =
            shape.extensions.iter().copied().filter(|e| !is_grease(*e)).collect();
        assert_eq!(actual, expected, "extension order must match the profile exactly");
    }

    #[test]
    fn ciphers_start_with_the_tls13_suites() {
        for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
            let c = profile.ciphers();
            assert_eq!(c[0], 0x1301);
            assert!(c.contains(&0x1303), "{profile:?} must offer chacha20");
        }
    }

    #[test]
    fn cipher_bytes_length_matches_the_declared_size() {
        let mut rng = || 5u8;
        for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
            let shape = HelloShape::build(profile, &mut rng);
            let bytes = shape.cipher_bytes(&mut rng);
            let declared = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            assert_eq!(declared, bytes.len() - 2, "{profile:?} declared size is wrong");
        }
    }

    #[test]
    fn cipher_bytes_are_grease_padded() {
        let mut rng = || 9u8;
        let shape = HelloShape::build(BrowserProfile::Chrome, &mut rng);
        let bytes = shape.cipher_bytes(&mut rng);
        let first = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert!(is_grease(first), "cipher list must open with GREASE");
    }

    #[test]
    fn x25519_is_the_preferred_group() {
        for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
            assert_eq!(profile.groups()[0], 0x001d, "{profile:?} must prefer x25519");
        }
    }

    #[test]
    fn alpn_offers_h2_then_http11() {
        for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
            assert_eq!(profile.alpn()[0], b"h2");
            assert_eq!(profile.alpn()[1], b"http/1.1");
        }
    }

    /// The point of the module: a minimal hello is what gives the endpoint away.
    /// A browser-shaped one carries many extensions in a specific order.
    #[test]
    fn shapes_are_no_longer_minimal() {
        let mut rng = || 4u8;
        for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
            let shape = HelloShape::build(profile, &mut rng);
            assert!(
                shape.extensions.len() >= 10,
                "{profile:?} produced only {} extensions; still looks hand-rolled",
                shape.extensions.len()
            );
        }
    }
}
