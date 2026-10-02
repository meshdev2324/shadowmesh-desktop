#![no_main]
//! Fuzz target: Shadowsocks UDP packet encryption (SIP007 single-packet mode).
//!
//! Invariants: arbitrary ciphertext input must never panic (length checks and
//! AEAD failures must surface as errors), and corrupting one byte of a valid
//! packet must always fail authentication.

use libfuzzer_sys::fuzz_target;
use shadowmesh_core::protocol::shadowsocks::{ShadowsocksCipher, ShadowsocksMethod};

fuzz_target!(|data: &[u8]| {
    let payload = if data.len() > 2048 { &data[..2048] } else { data };

    for method in [ShadowsocksMethod::Aes256Gcm, ShadowsocksMethod::ChaCha20Poly1305] {
        // 1. Arbitrary ciphertext bytes: must never panic, only error.
        let _ = ShadowsocksCipher::decrypt_udp(method, "fuzz-password", data);

        // 2. Round-trip + tamper detection.
        if let Ok(ct) = ShadowsocksCipher::encrypt_udp(method, "fuzz-password", payload) {
            if let Ok(pt) = ShadowsocksCipher::decrypt_udp(method, "fuzz-password", &ct) {
                assert_eq!(pt, payload);
            }
            // Tamper one byte of the body (skip the salt) — must fail.
            if ct.len() > method.salt_len() {
                let mut tampered = ct;
                let idx = tampered.len() - 1;
                tampered[idx] ^= 0xFF;
                assert!(ShadowsocksCipher::decrypt_udp(method, "fuzz-password", &tampered).is_err());
            }
        }
    }
});
