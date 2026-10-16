#![no_main]
use libfuzzer_sys::fuzz_target;
use shadowmesh_core::transport::outbound::tuic::wire;

fuzz_target!(|data: &[u8]| {
    // Both TUIC v5 decoders must reject malformed input without panicking,
    // reading out of bounds, or accepting non-strict framing. decode_packet
    // enforces SIZE == payload length internally, so any accepted command
    // satisfies that invariant by construction.
    if let Ok(cmd) = wire::decode_packet(data) {
        assert!(cmd.frag_total >= 1);
        assert!(cmd.frag_id < cmd.frag_total);
    }
    let _ = wire::decode_address(data);
});
