use crate::vpn_manager::TrafficMode;
use crate::VPNNode;

/// Shadow-Routing scoring weights per PROTOCOLS.md §3 (Fixed-point, scale of 1000).
const WEIGHT_LATENCY: u32 = 300;
const WEIGHT_FRAGMENTATION_EFFICIENCY: u32 = 400;
const WEIGHT_IP_REPUTATION: u32 = 100;
const WEIGHT_TRANSIT_DIVERSITY: u32 = 200;

/// Composite score and metrics for a VPN node as calculated by the Shadow-Routing algorithm.
pub struct NodeScore {
    /// The node being scored.
    pub node: VPNNode,
    /// Final blended score (lower is better, 0-1000).
    pub score: u32,
    /// Normalized latency component of the score.
    pub latency_score: u32,
    /// Normalized fragmentation efficiency component of the score.
    pub fragmentation_score: u32,
    /// Normalized IP reputation component of the score.
    pub reputation_score: u32,
    /// Normalized transit path diversity component of the score.
    pub transit_score: u32,
}

/// Score a single node based on the Shadow-Routing algorithm using integer math.
///
/// - `frag_success_ratio`: fraction of fragmented handshakes that succeeded (0.0–1.0).
/// - `reputation_score`: external IP reputation (0.0 = clean, 1.0 = fully blocked).
/// - `transit_diversity`: transit path diversity score (0.0 = bottleneck backbone, 1.0 = diverse paths).
pub fn score_node(
    node: &VPNNode,
    frag_success_ratio: f64,
    reputation_score: f64,
    transit_diversity: f64,
) -> NodeScore {
    // Normalize latency: 0 ms → 0, ≥300 ms → 1000
    let latency_norm = ((node.latency * 1000) / 300).min(1000);

    // Fragmentation efficiency: high success is good (invert: 1 - ratio)
    let frag_norm = ((1.0 - frag_success_ratio.clamp(0.0, 1.0)) * 1000.0) as u32;

    // Load contribution (0-100 → 0-1000)
    let load_norm = (node.load * 10).min(1000);

    // Blended transit diversity with server load
    let transit_norm = ((transit_diversity * 500.0) as u32 + (load_norm / 2)).min(1000);

    let reputation_norm = (reputation_score.clamp(0.0, 1.0) * 1000.0) as u32;

    let score = (latency_norm * WEIGHT_LATENCY
        + frag_norm * WEIGHT_FRAGMENTATION_EFFICIENCY
        + reputation_norm * WEIGHT_IP_REPUTATION
        + transit_norm * WEIGHT_TRANSIT_DIVERSITY)
        / 1000;

    NodeScore {
        node: node.clone(),
        score,
        latency_score: latency_norm,
        fragmentation_score: frag_norm,
        reputation_score: reputation_norm,
        transit_score: transit_norm,
    }
}

/// Select the best node from a list using the Shadow-Routing algorithm.
///
/// If no live fragmentation telemetry is available, it defaults to a combination
/// of latency and load with conservative assumptions for reputation and diversity.
pub fn shadow_route_best_node(nodes: &[VPNNode]) -> Option<&VPNNode> {
    let filtered_nodes: Vec<&VPNNode> = nodes.iter().filter(|n| n.is_online).collect();
    if filtered_nodes.is_empty() {
        return None;
    }

    // In absence of live fragmentation telemetry, weight purely by latency
    // and load (conservative defaults: perfect reputation, moderate transit diversity).
    filtered_nodes.into_iter().min_by(|a, b| {
        let score_a = score_node(a, 0.8, 0.0, 0.5).score;
        let score_b = score_node(b, 0.8, 0.0, 0.5).score;
        score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
    })
}

/// Determine the preferred `TrafficMode` for a given ISO 3166-1 alpha-2 region code.
///
/// Nodes in high-risk DPI regions (e.g., CN, IR, RU) default to `Fragmented` mode immediately.
pub fn preferred_mode_for_region(region_code: &str) -> TrafficMode {
    match region_code.to_uppercase().as_str() {
        // v4.5: Expanded high-risk DPI regions synchronized with server-rust RoutingEngine
        "CN" | "IR" | "RU" | "PK" | "EG" | "TH" | "TM" | "BY" | "AE" | "SA" | "MM" | "KP" => {
            TrafficMode::Fragmented
        }
        _ => TrafficMode::Normal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VPNNode;
    use proptest::prelude::*;

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
    fn test_scoring_weights_sum_to_one() {
        let total = WEIGHT_LATENCY
            + WEIGHT_FRAGMENTATION_EFFICIENCY
            + WEIGHT_IP_REPUTATION
            + WEIGHT_TRANSIT_DIVERSITY;
        assert_eq!(total, 1000, "Weights must sum to 1000, got {}", total);
    }

    #[test]
    fn test_best_node_selected_by_latency_when_equal_load() {
        let nodes = vec![make_node("fast", 20, 30), make_node("slow", 200, 30)];
        let best = shadow_route_best_node(&nodes).expect("Shadow pick a node");
        assert_eq!(best.id, "fast", "Lower latency node should win");
    }

    #[test]
    fn test_fragmentation_efficiency_dominates() {
        // Node A: perfect latency, terrible frag efficiency
        let node_a = make_node("a", 10, 20);
        // Node B: worse latency, excellent frag efficiency
        let node_b = make_node("b", 120, 20);

        let score_a = score_node(&node_a, 0.0, 0.0, 0.5).score; // frag_success=0 → bad
        let score_b = score_node(&node_b, 1.0, 0.0, 0.5).score; // frag_success=1 → great

        // Frag weight (0.40) should make B win despite higher latency
        assert!(score_b < score_a, "High frag efficiency should overcome latency penalty");
    }

    #[test]
    fn test_region_dpi_preference() {
        assert_eq!(preferred_mode_for_region("CN"), TrafficMode::Fragmented);
        assert_eq!(preferred_mode_for_region("IR"), TrafficMode::Fragmented);
        assert_eq!(preferred_mode_for_region("US"), TrafficMode::Normal);
        assert_eq!(preferred_mode_for_region("DE"), TrafficMode::Normal);
    }

    #[test]
    fn test_empty_nodes_returns_none() {
        assert!(shadow_route_best_node(&[]).is_none());
    }

    proptest! {
        #[test]
        fn test_score_node_robustness(
            latency in 0..5000u32,
            load in 0..200u32,
            frag_success in -1.0..2.0f64,
            reputation in -1.0..2.0f64,
            transit in -1.0..2.0f64,
        ) {
            let node = VPNNode {
                id: "test".into(),
                name: "test".into(),
                region: "US".into(),
                country: "US".into(),
                endpoint: "1.1.1.1:443".into(),
                public_key: "pub".into(),
                load,
                latency,
                is_sovereign: false, is_online: true, shard_id: None,
            };

            let score = score_node(&node, frag_success, reputation, transit);

            // Verify score is within valid range [0, 1000]
            prop_assert!(score.score <= 1000, "Score should not exceed 1000, got {}", score.score);
            prop_assert!(score.latency_score <= 1000);
            prop_assert!(score.fragmentation_score <= 1000);
            prop_assert!(score.reputation_score <= 1000);
            prop_assert!(score.transit_score <= 1000);
        }
    }
}
