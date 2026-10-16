use shadowmesh_core::{score_node, VPNNode};

fn make_node(id: &str, latency: u32, load: u32) -> VPNNode {
    VPNNode {
        id: id.to_string(),
        name: id.to_string(),
        region: "US".to_string(),
        country: "US".to_string(),
        endpoint: "1.2.3.4:51820".to_string(),
        public_key: "key".to_string(),
        load,
        latency,
        is_sovereign: false,
        is_online: true,
        shard_id: None,
    }
}

#[test]
fn audit_stability_over_speed() {
    // Principal Requirement: Stability is the primary Pillar.
    // Node A: Very fast (20ms) but unstable (50% frag success)
    let node_a = make_node("fast-unstable", 20, 10);
    // Node B: Slower (80ms) but very stable (98% frag success)
    let node_b = make_node("slow-stable", 80, 10);

    let score_a = score_node(&node_a, 0.5, 0.0, 0.5).score;
    let score_b = score_node(&node_b, 0.98, 0.0, 0.5).score;

    println!("Score A (Fast/Unstable): {}", score_a);
    println!("Score B (Slow/Stable): {}", score_b);

    // B should have a lower (better) score than A because stability (frag efficiency)
    // has a higher weight (400) than latency (300).
    assert!(score_b < score_a, "Stable node should be preferred over fast but unstable node");
}

#[test]
fn audit_ip_reputation_impact() {
    // Node A: Standard latency (50ms), Clean IP (0.0 reputation score)
    let node_a = make_node("clean", 50, 10);
    // Node B: Same latency (50ms), Risky IP (0.6 reputation score)
    let node_b = make_node("risky", 50, 10);

    let score_a = score_node(&node_a, 0.9, 0.0, 0.5).score;
    let score_b = score_node(&node_b, 0.9, 0.6, 0.5).score;

    assert!(score_a < score_b, "Clean IP should have a better score than risky IP");
}

#[test]
fn audit_load_balancing_pivot() {
    // Node A: Good latency (40ms), but heavily loaded (90%)
    let node_a = make_node("loaded", 40, 90);
    // Node B: Slightly worse latency (60ms), but idle (10%)
    let node_b = make_node("idle", 60, 10);

    let score_a = score_node(&node_a, 0.9, 0.0, 0.5).score;
    let score_b = score_node(&node_b, 0.9, 0.0, 0.5).score;

    // Load influences transit_score and also contributes directly via some internal blending.
    // Let's see if B wins.
    println!("Score A (Loaded): {}", score_a);
    println!("Score B (Idle): {}", score_b);

    // In score_node:
    // load_norm = load * 10 = 900 for A, 100 for B.
    // transit_norm = (diversity * 500) + (load_norm / 2) = (0.5 * 500) + 450 = 700 for A.
    // transit_norm = (0.5 * 500) + 50 = 300 for B.
    // A score = (133 * 300 + 100 * 400 + 0 * 100 + 700 * 200) / 1000 = (39900 + 40000 + 0 + 140000) / 1000 = 219
    // B score = (200 * 300 + 100 * 400 + 0 * 100 + 300 * 200) / 1000 = (60000 + 40000 + 0 + 60000) / 1000 = 160
    assert!(
        score_b < score_a,
        "Idle node should be preferred over heavily loaded node despite better latency"
    );
}

#[test]
fn audit_extreme_latency_penalty() {
    // Node A: Very slow (500ms), but perfect stability
    let node_a = make_node("snail", 500, 10);
    // Node B: Moderate speed (150ms), moderate stability (70%)
    let node_b = make_node("moderate", 150, 10);

    let score_a = score_node(&node_a, 1.0, 0.0, 0.5).score;
    let score_b = score_node(&node_b, 0.7, 0.0, 0.5).score;

    println!("Score A (Snail/Stable): {}", score_a);
    println!("Score B (Moderate/Unstable): {}", score_b);

    // Snail should be penalized heavily by the latency cap (300ms max norm).
    assert!(
        score_b < score_a,
        "Moderate speed/stability should win over extreme latency even if stable"
    );
}
