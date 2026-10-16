use bytes::Bytes;
use shadowmesh_core::fragment::{fragment_data, FragmentationConfig, QUANTUM_MTU};
use shadowmesh_core::shadow_router::{preferred_mode_for_region, score_node};
use shadowmesh_core::vpn_manager::TrafficMode;
use shadowmesh_core::VPNNode;

// 🌀 custom Protocol & DPI Evasion Tests

// 1. MTU Fragmentation Validation
// Automated tests that verify packets leaving the TUN interface are exactly 576 bytes or less.

#[test]
fn test_quantum_tunneling_enforces_mtu_limit() {
    let large_payload = vec![0u8; 2000]; // Larger than standard Ethernet (1500) and Quantum (576)
    let config = FragmentationConfig::quantum();

    let fragments = fragment_data(Bytes::from(large_payload.clone()), &config);

    assert!(fragments.len() > 1, "Payload should be split into multiple fragments");

    for (i, frag) in fragments.iter().enumerate() {
        assert!(
            frag.len() <= QUANTUM_MTU as usize,
            "Fragment #{} size {} exceeds Quantum MTU limit of {}",
            i,
            frag.len(),
            QUANTUM_MTU
        );
    }

    let reassembled = fragments.concat();
    assert_eq!(reassembled.len(), large_payload.len(), "Data loss during fragmentation");
    assert_eq!(reassembled, large_payload.as_slice(), "Data corruption during fragmentation");
}

// 2. Simulated DPI "Middlebox" Detection
// Verify that standard WireGuard signatures are broken when fragmented.

#[test]
fn test_dpi_middlebox_signature_bypass() {
    // Simulated WireGuard Type 1 Handshake Initiation packet (usually ~148 bytes)
    // For this test, we use a recognizable "signature" string.
    let wg_signature = b"WireGuard_Handshake_Initiation_v1_Signature_Header";
    let payload = [wg_signature.as_slice(), &vec![0u8; 500]].concat(); // Total ~550 bytes

    // Config: force small fragments (e.g. 32 bytes) to ensure the signature is split.
    let config = FragmentationConfig::new(10, 32, 0);
    let fragments = fragment_data(Bytes::from(payload), &config);

    // A simple signature-based DPI would look for the whole wg_signature in a single packet.
    let mut signature_detected = false;
    for frag in &fragments {
        if frag.windows(wg_signature.len()).any(|window| window == wg_signature) {
            signature_detected = true;
            break;
        }
    }

    assert!(!signature_detected, "DPI engine detected WireGuard signature in a single fragment! Fragmentation failed to obfuscate.");
}

// 3. Shadow-Routing Simulation
// Scenario-based tests to verify the router correctly falls back based on region or efficiency.

#[test]
fn test_shadow_routing_region_fallback() {
    // Scenario: User is in China (CN)
    let mode = preferred_mode_for_region("CN");
    assert_eq!(
        mode,
        TrafficMode::Fragmented,
        "High-risk region CN must default to Fragmented mode"
    );

    // Scenario: User is in United States (US)
    let mode = preferred_mode_for_region("US");
    assert_eq!(mode, TrafficMode::Normal, "Low-risk region US should default to Normal mode");
}

#[test]
fn test_shadow_routing_efficiency_penalty() {
    let node = VPNNode {
        id: "node-low-latency".into(),
        name: "Fast Node".into(),
        region: "US".into(),
        country: "US".into(),
        endpoint: "1.1.1.1:51820".into(),
        public_key: "pub".into(),
        load: 10,
        latency: 20, // Excellent latency
        is_sovereign: false,
        is_online: true,
        shard_id: None,
    };

    // Case A: High fragmentation success (80%)
    let score_good = score_node(&node, 0.8, 0.0, 0.5).score;

    // Case B: Low fragmentation success (20%) - sign of DPI interference
    let score_bad = score_node(&node, 0.2, 0.0, 0.5).score;

    assert!(score_bad > score_good, "Low fragmentation efficiency (DPI interference) must penalize the node score significantly");
}
