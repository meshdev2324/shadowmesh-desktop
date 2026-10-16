use base64::prelude::*;
use base64::Engine;
use mockito::Server;
use shadowmesh_core::network::discovery::ResilientDiscoveryEngine;
use tokio::time::Instant;

#[tokio::test]
async fn test_discovery_resilience_under_load() {
    println!("🌌 [Stress Test] Starting Discovery Resilience Audit...");

    let mut server = Server::new_async().await;
    let url = server.url();

    // 1. Mock API: Constant Failure (500)
    let _m1 = server.mock("GET", "/api/v1/nodes").with_status(500).create_async().await;

    // 2. Mock Worker: Constant Success (returns empty base64 manifest)
    let manifest = shadowmesh_core::GlobalManifest {
        nodes: Vec::new(),
        anycast_vips: Vec::new(),
        version: "v1.0.0".into(),
    };
    let encoded = BASE64_STANDARD.encode(serde_json::to_string(&manifest).unwrap());
    let _m2 = server
        .mock("GET", "/worker/nodes")
        .with_status(200)
        .with_body(encoded)
        .create_async()
        .await;

    let engine = ResilientDiscoveryEngine::new(
        url.clone(),
        format!("{}/worker/nodes", url),
        "nodes.test".into(),
    );

    println!("⚡ Executing rapid discovery requests...");
    let start = Instant::now();

    for _ in 0..10 {
        let res = engine.fetch_nodes_resilient().await;
        assert!(res.is_ok(), "Should have recovered via Worker fallback");
    }

    let duration = start.elapsed();
    println!("🏁 [Stress Test] Completed in {:?}. Resilience logic stable.", duration);
}
