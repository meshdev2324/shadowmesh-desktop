#![no_main]
use libfuzzer_sys::fuzz_target;
use shadowmesh_core::transport::inbound::vmess::parse_vmess_header;

fuzz_target!(|data: &[u8]| {
    let _ = parse_vmess_header(data);
});
