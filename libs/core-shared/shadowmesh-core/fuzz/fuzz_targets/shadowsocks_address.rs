#![no_main]
use libfuzzer_sys::fuzz_target;
use shadowmesh_core::transport::inbound::shadowsocks::parse_ss_address;

fuzz_target!(|data: &[u8]| {
    let _ = parse_ss_address(data);
});
