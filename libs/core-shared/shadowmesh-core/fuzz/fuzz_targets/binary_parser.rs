#![no_main]
use libfuzzer_sys::fuzz_target;
use shadowmesh_core::protocol::binary::decode_node_list;

fuzz_target!(|data: &[u8]| {
    // We expect decode_node_list to never panic, even with malformed input.
    let _ = decode_node_list(data);
});
