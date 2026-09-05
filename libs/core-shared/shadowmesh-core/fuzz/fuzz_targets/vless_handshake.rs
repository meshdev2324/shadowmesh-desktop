#![no_main]
use libfuzzer_sys::fuzz_target;
use shadowmesh_core::transport::inbound::vmess::parse_vless_handshake;

fuzz_target!(|data: &[u8]| {
    let _ = parse_vless_handshake(data);
});
