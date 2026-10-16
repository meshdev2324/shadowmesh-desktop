#![no_main]
//! Fuzz target: Hysteria XOR obfuscation (involution property).
//!
//! Invariant: obfuscate ∘ deobfuscate = identity for arbitrary key material
//! and data; obfuscation must always change non-empty data.

use libfuzzer_sys::fuzz_target;
use shadowmesh_core::transport::hysteria::HysteriaObfuscator;

fuzz_target!(|input: (Vec<u8>, String)| {
    let (data, key) = input;
    if key.is_empty() {
        return; // constructor requires non-empty keys to be meaningful
    }
    let obf = HysteriaObfuscator::new(&key);

    let mut buf = data.clone();
    obf.obfuscate_in_place(&mut buf);
    if !data.is_empty() {
        assert_ne!(buf, data, "obfuscation must change non-empty data");
    }
    obf.deobfuscate_in_place(&mut buf);
    assert_eq!(buf, data, "obfuscation must be an involution");
});
