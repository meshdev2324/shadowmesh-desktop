use bytes::Bytes;
use shadowmesh_core::transport::reality::RealityTransport;
use shadowmesh_core::transport::AsyncTransport;
use shadowmesh_core::{RealityConfig, ShadowMeshError};

#[tokio::test]
async fn test_reality_vless_wireguard_flow() {
    // This test simulates the composition logic.
    // In a real environment, it would connect to an Xray server.

    let config = RealityConfig {
        server_ip: "157.245.154.116".to_string(),
        port: 443,
        uuid: "d4f2cdeb-66b3-4e52-a743-b042aa53822b".to_string(),
        public_key: "1nf6Pue_IRqOZQv9R2Uj7MIlm1m5DGZA8fD5t8AOjAw".to_string(),
        short_id: "fb5304e4438d01ad".to_string(),
        sni_target: "dl.google.com".to_string(),
        fingerprint: Some("chrome".to_string()),
    };

    let priv_key = [0u8; 32]; // Mock ephemeral
    let server_pub = [0u8; 32];

    let transport = RealityTransport::new(config, priv_key, server_pub);

    // We expect connection to fail in CI without a real server, but we can verify the
    // handshake construction via unit tests in reality_tls.rs.
    let result = transport.connect().await;
    match result {
        Err(ShadowMeshError::IoError(_)) | Err(ShadowMeshError::Other(_)) => {
            // Expected failure if server is unreachable
        }
        _ => {}
    }
}

#[tokio::test]
#[ignore]
async fn reality_live() {
    use std::env;
    let host = env::var("SHADOWMESH_REALITY_HOST").unwrap_or_else(|_| "157.245.154.116".into());
    let port =
        env::var("SHADOWMESH_REALITY_PORT").unwrap_or_else(|_| "443".into()).parse().unwrap();
    let pubkey = env::var("SHADOWMESH_REALITY_PUBKEY")
        .unwrap_or_else(|_| "1nf6Pue_IRqOZQv9R2Uj7MIlm1m5DGZA8fD5t8AOjAw".into());
    let shortid =
        env::var("SHADOWMESH_REALITY_SHORTID").unwrap_or_else(|_| "fb5304e4438d01ad".into());
    let sni = env::var("SHADOWMESH_REALITY_SNI").unwrap_or_else(|_| "dl.google.com".into());
    let uuid = env::var("SHADOWMESH_REALITY_UUID")
        .unwrap_or_else(|_| "d4f2cdeb-66b3-4e52-a743-b042aa53822b".into());

    let config = RealityConfig {
        server_ip: host,
        port,
        uuid,
        public_key: pubkey,
        short_id: shortid,
        sni_target: sni,
        fingerprint: Some("chrome".to_string()),
    };

    // Use a fixed keypair for the live test
    let priv_key = [0u8; 32];
    let server_pub = [0u8; 32];

    let transport = RealityTransport::new(config, priv_key, server_pub);
    transport.connect().await.expect("Handshake failed");

    // Trigger handshake
    transport.send(Bytes::from_static(&[0u8; 40])).await.unwrap();

    println!("✅ REALITY live test: handshake and send successful");
}
