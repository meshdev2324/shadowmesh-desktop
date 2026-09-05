#![no_main]
use libfuzzer_sys::fuzz_target;
use shadowmesh_core::fragment::{fragment_data, reassemble_fragments, FragmentationConfig};
use bytes::Bytes;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() { return; }

    let config = FragmentationConfig::quantum();
    let fragments = fragment_data(Bytes::copy_from_slice(data), &config);
    let reassembled = reassemble_fragments(fragments);

    assert_eq!(reassembled.as_ref(), data);
});
