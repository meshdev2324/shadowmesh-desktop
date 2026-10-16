use bytes::Bytes;
use shadowmesh_core::fragment::{fragment_data, FragmentationConfig};

#[test]
fn audit_packet_signature_randomization() {
    // Principal Requirement: Packet signatures must be non-deterministic to evade DPI.
    let payload = Bytes::from(vec![0u8; 1000]);
    let config = FragmentationConfig::adaptive_handshake();

    // 1. Fragment the same data twice
    let frags_1 = fragment_data(payload.clone(), &config);
    let frags_2 = fragment_data(payload.clone(), &config);

    // 2. Extract sizes
    let sizes_1: Vec<usize> = frags_1.iter().map(|f| f.len()).collect();
    let sizes_2: Vec<usize> = frags_2.iter().map(|f| f.len()).collect();

    println!("Sequence 1: {:?}", sizes_1);
    println!("Sequence 2: {:?}", sizes_2);

    // 3. Verify they are different (statistically highly likely)
    assert_ne!(sizes_1, sizes_2, "Repeated fragmentation should produce different chunk sequences to disrupt DPI fingerprinting");
}

#[test]
fn audit_quantum_mtu_compliance() {
    // Verify Protocol Compliance: MTU 576
    let payload = Bytes::from(vec![0u8; 5000]);
    let config = FragmentationConfig::quantum();

    let frags = fragment_data(payload, &config);

    for (i, frag) in frags.iter().enumerate() {
        assert!(frag.len() <= 576, "Fragment {} exceeds QUANTUM_MTU (576): {}", i, frag.len());
    }
}
