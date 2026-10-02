use mockito::Server;
use shadowmesh_core::ApiClient;
use shadowmesh_daemon::{CoreApiWrapper, ShadowApi};
use std::sync::Arc;

#[tokio::test]
async fn test_daemon_core_integration_health() {
    let mut server = Server::new_async().await;
    let url = server.url();

    // Mock API health endpoint
    let _m = server
        .mock("GET", "/api/health")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status": "ok", "version": "1.0", "uptime_seconds": 12345}"#)
        .create_async()
        .await;

    let core_client = Arc::new(ApiClient::new(url).expect("Failed to create ApiClient"));
    let bridge = CoreApiWrapper::new(core_client);

    let health = bridge.check_health().await.expect("Failed to check health via bridge");
    assert_eq!(health.status, "ok");
    assert_eq!(health.version, "1.0");
}

#[tokio::test]
async fn test_daemon_core_integration_nodes() {
    let mut server = Server::new_async().await;
    let url = server.url();

    // Mock nodes endpoint
    let _m = server.mock("GET", "/api/v1/nodes")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"[{"id": "node-1", "name": "Berlin", "region": "Europe", "country": "DE", "endpoint": "1.2.3.4:51820", "public_key": "pub", "load": 5, "latency": 10, "is_online": true}]"#)
        .create_async().await;

    let core_client = Arc::new(ApiClient::new(url).expect("Failed to create ApiClient"));
    let bridge = CoreApiWrapper::new(core_client);

    let nodes = bridge.get_nodes().await.expect("Failed to fetch nodes via bridge");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "Berlin");
}
