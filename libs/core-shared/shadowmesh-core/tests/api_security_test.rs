use mockito::Server;
use shadowmesh_core::ApiClient;

#[tokio::test]
async fn test_api_client_mandatory_headers() {
    let mut server = Server::new_async().await;
    let url = server.url();
    let client = ApiClient::new(url).unwrap();

    client.set_device_id("test-device-id-1234567890".to_string());
    client.set_auth_token(Some("test-token".to_string()));

    let mock = server
        .mock("GET", "/api/v1/nodes")
        .match_header("Authorization", "Bearer test-token")
        .match_header("X-Shadow-Device-ID", "test-device-id-1234567890")
        .with_status(200)
        .with_body("[]")
        .create_async()
        .await;

    let _ = client.get_nodes_async().await;
    mock.assert_async().await;
}

#[tokio::test]
async fn test_report_compromised_payload() {
    let mut server = Server::new_async().await;
    let url = server.url();
    let client = ApiClient::new(url).unwrap();

    let device_id = "test-device-id-1234567890";
    let reason = "test-reason";

    let mock = server
        .mock("POST", "/api/v1/auth/report-compromised")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "device_id": device_id,
            "reason": reason
        })))
        .with_status(200)
        .create_async()
        .await;

    let _ = client.report_compromised_async(device_id.to_string(), reason.to_string()).await;
    mock.assert_async().await;
}
