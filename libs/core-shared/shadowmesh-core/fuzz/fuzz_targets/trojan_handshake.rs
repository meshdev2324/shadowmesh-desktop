#![no_main]
use libfuzzer_sys::fuzz_target;
use shadowmesh_core::transport::inbound::trojan::parse_trojan_handshake;

fuzz_target!(|data: &[u8]| {
    let _ = parse_trojan_handshake(data);
});
