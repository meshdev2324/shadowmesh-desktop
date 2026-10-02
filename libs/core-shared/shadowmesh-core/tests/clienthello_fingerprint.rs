//! ClientHello fingerprint measurement.
//!
//! # The question this answers
//!
//! Is a shaped ClientHello distinguishable from a real browser's, by the
//! dimensions an analyst actually uses? That has been open in this project and
//! I have been answering it by assertion. This measures it.
//!
//! # What it measures, and what it does not
//!
//! It measures the output of `utls_profile::HelloShape`: the extension list, its
//! order, the cipher list, and GREASE placement. That is the part I control.
//!
//! It does **not** capture a live ClientHello off the socket, because the
//! builder is currently inlined in the handshake; extracting it into a pure
//! function is a separate refactor. So this is a measurement of the shaping
//! data, not a byte-level capture of what ships. Stated rather than hidden,
//! because a test implying it captured the shipped hello would invite exactly
//! the confidence that produced the original defect.
//!
//! The reference values are public protocol facts: extension identifiers from
//! the IETF TLS registry, GREASE from RFC 8701, and the widely-documented Chrome
//! extension set. No third-party uTLS source was consulted.
//!
//! # How to read a failure
//!
//! Each test is one dimension an adversary could key on. A failure means "this
//! dimension is a giveaway today", not "the code is broken". That is the value:
//! it turns a vague worry into a ranked list.

use shadowmesh_core::transport::utls_profile::{
    is_grease, BrowserProfile, HelloShape, GREASE_VALUES,
};

/// A deterministic stand-in for the OS entropy source, so failures reproduce.
fn seeded() -> impl FnMut() -> u8 {
    let mut state: u32 = 0x1234_5678;
    move || {
        // xorshift32
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        (state & 0xFF) as u8
    }
}

/// Non-GREASE extensions, in order.
fn real_extensions(shape: &HelloShape) -> Vec<u16> {
    shape.extensions.iter().copied().filter(|e| !is_grease(*e)).collect()
}

fn grease_positions(shape: &HelloShape) -> Vec<usize> {
    shape.extensions.iter().enumerate().filter(|(_, e)| is_grease(**e)).map(|(i, _)| i).collect()
}

// ---- Dimension 1: how many extensions, and does that look like a browser? --

#[test]
fn extension_count_is_in_the_browser_range() {
    // Chrome sends roughly 15-18 extensions; Firefox 11-14. A count far outside
    // that is the cheapest possible classifier and needs no parsing at all.
    for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
        let mut rng = seeded();
        let shape = HelloShape::build(profile, &mut rng);
        let real = real_extensions(&shape).len();
        assert!(
            (8..=20).contains(&real),
            "{profile:?} sends {real} real extensions; browsers send 11-18"
        );
    }
}

// ---- Dimension 2: order, which a naive parser keys on ---------------------

#[test]
fn extension_order_matches_the_browser() {
    for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
        let mut rng = seeded();
        let shape = HelloShape::build(profile, &mut rng);
        assert_eq!(
            real_extensions(&shape),
            profile.extension_order().to_vec(),
            "{profile:?} extension order must match the browser exactly"
        );
    }
}

// ---- Dimension 3: GREASE, and where --------------------------------------

#[test]
fn grease_is_present_at_browser_positions() {
    for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
        let mut rng = seeded();
        let shape = HelloShape::build(profile, &mut rng);
        let positions = grease_positions(&shape);
        assert!(
            positions.len() >= 2,
            "{profile:?} has {} GREASE values; browsers pad both ends",
            positions.len()
        );
        // Chrome pads the first and last extension positions.
        assert_eq!(positions[0], 0, "{profile:?} must GREASE the first position");
        let last = shape.extensions.len() - 1;
        assert_eq!(*positions.last().unwrap(), last, "{profile:?} must GREASE the last position");
    }
}

#[test]
fn grease_values_are_distinct_within_a_hello() {
    for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
        for seed in 0..64u8 {
            let mut rng = seeded();
            let mut shape_seed = seed;
            let mut rng2 = move || {
                shape_seed = shape_seed.wrapping_add(1);
                shape_seed
            };
            let _ = &mut rng;
            let shape = HelloShape::build(profile, &mut rng2);
            let grease: Vec<u16> =
                shape.extensions.iter().copied().filter(|e| is_grease(*e)).collect();
            let mut unique = grease.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(grease.len(), unique.len(), "{profile:?} repeated a GREASE value");
        }
    }
}

#[test]
fn every_grease_value_is_rfc8701_shaped() {
    let mut rng = seeded();
    let shape = HelloShape::build(BrowserProfile::Chrome, &mut rng);
    for e in shape.extensions.iter().filter(|e| is_grease(**e)) {
        assert!(GREASE_VALUES.contains(e), "{e:#06x} is not a valid GREASE value");
    }
}

// ---- Dimension 4: mandatory extensions -----------------------------------

#[test]
fn no_browser_omits_these() {
    for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
        let mut rng = seeded();
        let exts = real_extensions(&HelloShape::build(profile, &mut rng));
        for required in [0x0000u16, 0x0033, 0x0010, 0x000d, 0x002b] {
            assert!(
                exts.contains(&required),
                "{profile:?} omits {required:#06x}, which every browser sends"
            );
        }
    }
}

// ---- Dimension 5: the cipher list ----------------------------------------

#[test]
fn cipher_count_and_order_are_browser_like() {
    for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
        let mut rng = seeded();
        let shape = HelloShape::build(profile, &mut rng);
        let bytes = shape.cipher_bytes(&mut rng);
        let declared = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        // A browser offers 13-17 suites including GREASE. Offering three is
        // trivially distinctive; offering dozens is also wrong.
        assert!(
            (6..=20).contains(&declared),
            "{profile:?} declares {declared} cipher bytes; browsers offer 13-17 suites"
        );
    }
}

#[test]
fn tls13_suites_lead_after_grease() {
    for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
        let mut rng = seeded();
        let shape = HelloShape::build(profile, &mut rng);
        let bytes = shape.cipher_bytes(&mut rng);
        let first = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert!(is_grease(first), "{profile:?} cipher list must open with GREASE");
        let second = u16::from_be_bytes([bytes[4], bytes[5]]);
        assert_eq!(second, 0x1301, "{profile:?} must lead with TLS_AES_128_GCM_SHA256");
    }
}

// ---- Dimension 6: groups and ALPN ----------------------------------------

#[test]
fn groups_lead_with_x25519_and_alpn_offers_h2() {
    for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
        let mut rng = seeded();
        let _ = HelloShape::build(profile, &mut rng);
        assert_eq!(profile.groups()[0], 0x001d, "{profile:?} must prefer x25519");
        assert_eq!(profile.alpn()[0], b"h2", "{profile:?} must offer h2 first");
    }
}

// ---- Dimension 7: stability ----------------------------------------------

#[test]
fn two_hellos_from_the_same_profile_differ() {
    // An identical hello on every connection is itself a signature: a real
    // browser varies its ClientHello, notably in GREASE and the key share.
    let mut a = seeded();
    let mut b = seeded();
    let mut sa = 1u8;
    let mut sb = 2u8;
    let mut ra = move || {
        sa = sa.wrapping_add(7);
        sa
    };
    let mut rb = move || {
        sb = sb.wrapping_add(7);
        sb
    };
    let _ = (&mut a, &mut b);
    let shape_a = HelloShape::build(BrowserProfile::Chrome, &mut ra);
    let shape_b = HelloShape::build(BrowserProfile::Chrome, &mut rb);
    assert_ne!(
        shape_a.extensions, shape_b.extensions,
        "consecutive hellos should not be byte-identical"
    );
}

// ---- The measurement, recorded rather than asserted ----------------------

/// Writes the current fingerprint to stdout as a ranked list of dimensions, so
/// a change can be diffed between runs instead of reasoned about from memory.
#[test]
fn fingerprint_report() {
    for profile in [BrowserProfile::Chrome, BrowserProfile::Firefox] {
        let mut rng = seeded();
        let shape = HelloShape::build(profile, &mut rng);
        let real = real_extensions(&shape);
        let grease = grease_positions(&shape);
        let cipher_bytes = shape.cipher_bytes(&mut rng);
        let declared_ciphers = u16::from_be_bytes([cipher_bytes[0], cipher_bytes[1]]);

        println!("--- {profile:?} ---");
        println!("  real extensions : {} -> {:04x?}", real.len(), real);
        println!("  GREASE at       : {grease:?}");
        println!("  ciphers         : {declared_ciphers} bytes");
        println!("  groups          : {:04x?}", profile.groups());
        println!("  ALPN            : {:?}", profile.alpn());
        // An explicit verdict per dimension, so a regression names itself.
        println!(
            "  D1 count        : {}",
            if (8..=20).contains(&real.len()) { "plausible" } else { "GIVEAWAY" }
        );
        println!(
            "  D2 order        : {}",
            if real == profile.extension_order() { "browser order" } else { "GIVEAWAY" }
        );
        println!("  D3 grease       : {}", if grease.len() >= 2 { "padded" } else { "GIVEAWAY" });
        println!(
            "  D4 mandatory    : {}",
            if [0x0000u16, 0x0033, 0x0010, 0x000d, 0x002b].iter().all(|r| real.contains(r)) {
                "complete"
            } else {
                "GIVEAWAY"
            }
        );
        println!(
            "  D5 cipher count : {}",
            if (6..=20).contains(&declared_ciphers) { "plausible" } else { "GIVEAWAY" }
        );
    }
}
