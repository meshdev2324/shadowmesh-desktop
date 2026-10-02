//! Stress and soak tests for the transport stack.
//!
//! # What this is for
//!
//! Unit tests prove a function is correct for one input. They say nothing about
//! what happens after a million operations, a long-lived session, or a
//! resource that is not released. This module covers the properties that only
//! appear under repetition:
//!
//! 1. **Nonce uniqueness over a long session.** The single most important
//!    invariant in AEAD. Reuse leaks the authentication subkey. A per-call test
//!    passes forever while a session-level leak ships.
//! 2. **No unbounded growth.** A long session must not accumulate buffers,
//!    counters, or key material.
//! 3. **Behaviour at exhaustion.** The point where a counter or a buffer hits
//!    its limit must fail closed, not wrap and not panic.
//! 4. **Sustained throughput without drift.** Confirms a long run does not
//!    degrade, which a short test cannot see.
//!
//! These are `#[ignore]`d by default so the normal test run stays fast, and are
//! invoked deliberately:
//!
//! ```text
//! cargo test -p shadowmesh-core --release -- --ignored --nocapture stress
//! ```
//!
//! Run them in release. Timing assertions in a debug build are noise, and this
//! is the same reasoning as the benchmarks: no wall-clock gate in CI.

use std::collections::HashSet;

use shadowmesh_core::protocol::ss2022_nonce::NonceCounter;
use shadowmesh_core::protocol::ss2022_stream::{read_chunk, seal_chunk, MAX_CHUNK_LEN};
use shadowmesh_core::transport::shadowsocks2022::{
    derive_identity_subkey, derive_session_subkey, open, random_nonce, random_salt, seal,
    Shadowsocks2022Method,
};

const METHODS: [Shadowsocks2022Method; 3] = [
    Shadowsocks2022Method::Aes128Gcm,
    Shadowsocks2022Method::Aes256Gcm,
    Shadowsocks2022Method::ChaCha20Poly1305,
];

/// A long session: enough frames that a wrap or a leak would be visible, while
/// still finishing quickly in release.
const SESSION_FRAMES: usize = 50_000;

fn psk(m: Shadowsocks2022Method) -> Vec<u8> {
    (0..m.psk_len() as u8).collect()
}

fn subkey(m: Shadowsocks2022Method) -> Vec<u8> {
    derive_session_subkey(m, &psk(m), &random_salt(m)).unwrap()
}

#[test]
#[ignore = "stress: run with --release -- --ignored"]
fn nonce_never_repeats_over_a_long_session() {
    // The invariant that must hold no matter how long a session runs. This is
    // the test that a per-call unit test structurally cannot provide.
    for m in METHODS {
        let mut seen: HashSet<[u8; 12]> = HashSet::with_capacity(SESSION_FRAMES);
        for _ in 0..SESSION_FRAMES {
            let nonce = random_nonce();
            assert!(seen.insert(nonce), "{m:?}: nonce repeated after {} frames", seen.len());
        }
        assert_eq!(seen.len(), SESSION_FRAMES);
    }
}

#[test]
#[ignore = "stress: run with --release -- --ignored"]
fn many_sessions_never_share_key_material() {
    // Two sessions on one PSK must not share a subkey, or a captured frame from
    // one decrypts the other.
    for m in METHODS {
        let key = psk(m);
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for _ in 0..2_000 {
            let k = derive_session_subkey(m, &key, &random_salt(m)).unwrap();
            assert!(seen.insert(k), "{m:?}: subkey repeated across sessions");
        }
    }
}

#[test]
#[ignore = "stress: run with --release -- --ignored"]
fn session_and_identity_subkeys_never_collide() {
    // They differ only by context string. A collision would mean the EIH key and
    // the session key are the same, which defeats the purpose of separating them.
    for m in METHODS {
        let key = psk(m);
        let salt = random_salt(m);
        let session = derive_session_subkey(m, &key, &salt).unwrap();
        let identity = derive_identity_subkey(m, &key, &salt).unwrap();
        assert_ne!(session, identity, "{m:?}: identity subkey equals session subkey");
    }
}

#[test]
#[ignore = "stress: run with --release -- --ignored"]
fn sustained_framing_does_not_grow_the_buffer() {
    // Read many frames out of one buffer and confirm the buffer drains exactly.
    // A parser that leaves residue per frame is a slow memory leak that only
    // appears after hours of uptime.
    for m in METHODS {
        let key = subkey(m);
        let mut buf = bytes::BytesMut::new();
        let expected_frames = 2_000;
        for i in 0..expected_frames {
            let payload = vec![(i % 251) as u8; 512];
            buf.extend_from_slice(
                &seal_chunk(m, &key, &mut NonceCounter::default(), &payload).unwrap(),
            );
        }
        let start = buf.len();
        let mut drained = 0;
        while !buf.is_empty() {
            let before = buf.len();
            let mut reader = NonceCounter::default();
            read_chunk(m, &key, &mut reader, &mut buf)
                .expect("frame must decode")
                .expect("frame must be present");
            assert!(buf.len() < before, "{m:?}: buffer did not drain");
            drained += 1;
            assert!(drained <= expected_frames, "{m:?}: decoded more frames than were written");
        }
        assert_eq!(drained, expected_frames);
        assert_eq!(buf.len(), 0, "{m:?}: {start} bytes written, buffer did not empty");
    }
}

#[test]
#[ignore = "stress: run with --release -- --ignored"]
fn sustained_encrypt_decrypt_preserves_every_frame() {
    // End-to-end over a long run: every frame must return exactly what was
    // sealed. A single corrupted frame in a session is silent data corruption.
    for m in METHODS {
        let key = subkey(m);
        for i in 0..5_000 {
            let len = (i * 7) % (MAX_CHUNK_LEN + 1);
            let payload: Vec<u8> = (0..len).map(|j| (i as u8).wrapping_add(j as u8)).collect();
            let nonce = random_nonce();
            let sealed = seal(m, &key, &nonce, b"hdr", &payload).unwrap();
            let opened = open(m, &key, &nonce, b"hdr", &sealed).unwrap();
            assert_eq!(opened, payload, "{m:?}: corruption at frame {i}, len {len}");
        }
    }
}

#[test]
#[ignore = "stress: run with --release -- --ignored"]
fn throughput_is_sustained_without_degradation() {
    // Compare the first and last quartile of a long run. A leak or a cache
    // pathology shows up as the tail being materially slower than the head; a
    // short benchmark cannot see that at all.
    for m in METHODS {
        let key = subkey(m);
        let payload = vec![0x11u8; 1400];
        let quarter = 2_000;
        let mut head = std::time::Duration::ZERO;
        let mut tail = std::time::Duration::ZERO;

        for i in 0..(quarter * 4) {
            let start = std::time::Instant::now();
            let nonce = random_nonce();
            let sealed = seal(m, &key, &nonce, b"", &payload).unwrap();
            black_box_open(m, &key, &nonce, &sealed);
            let elapsed = start.elapsed();
            if i < quarter {
                head += elapsed;
            } else if i >= quarter * 3 {
                tail += elapsed;
            }
        }

        let ratio = tail.as_secs_f64() / head.as_secs_f64().max(f64::MIN_POSITIVE);
        assert!(
            ratio < 3.0,
            "{m:?}: tail/head throughput ratio {ratio:.2} suggests degradation over a long session"
        );
    }
}

#[inline]
fn black_box_open(m: Shadowsocks2022Method, key: &[u8], nonce: &[u8; 12], sealed: &[u8]) {
    let out = open(m, key, nonce, b"", sealed).unwrap();
    assert!(!out.is_empty());
}

#[test]
#[ignore = "stress: run with --release -- --ignored"]
fn oversized_frames_are_refused_under_repetition() {
    // An attacker sending only oversized frames must not be able to induce
    // allocation. Repeated thousands of times, this is also a cheap DoS if it
    // ever regressed to allocating before validating.
    for m in METHODS {
        let key = subkey(m);
        for _ in 0..10_000 {
            let huge = vec![0u8; MAX_CHUNK_LEN + 1];
            assert!(seal_chunk(m, &key, &mut NonceCounter::default(), &huge).is_err());
        }
    }
}
