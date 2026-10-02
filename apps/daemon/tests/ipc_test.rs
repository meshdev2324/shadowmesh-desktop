use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;

#[cfg(unix)]
const SOCKET_PATH: &str = "/tmp/shadowmesh.sock";

#[tokio::test]
async fn test_daemon_version() {
    #[cfg(unix)]
    {
        if !std::path::Path::new(SOCKET_PATH).exists() {
            println!("Skipping test: Daemon socket not found. Ensure daemon is running.");
            return;
        }

        let mut stream =
            UnixStream::connect(SOCKET_PATH).await.expect("Failed to connect to daemon");

        let cmd = json!({
            "action": "version",
            "args": [],
            "token": "test-token"
        });

        let cmd_bytes = serde_json::to_vec(&cmd).unwrap();
        stream.write_all(&cmd_bytes).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).await.unwrap();

        let response: serde_json::Value = serde_json::from_slice(&response_bytes).unwrap();
        assert!(response["success"].as_bool().unwrap());
        assert_eq!(response["data"]["version"], "1.0.0-PRO");
    }
}

#[tokio::test]
async fn test_daemon_status() {
    #[cfg(unix)]
    {
        if !std::path::Path::new(SOCKET_PATH).exists() {
            return;
        }

        let mut stream =
            UnixStream::connect(SOCKET_PATH).await.expect("Failed to connect to daemon");

        let cmd = json!({
            "action": "status",
            "args": [],
            "token": "test-token"
        });

        let cmd_bytes = serde_json::to_vec(&cmd).unwrap();
        stream.write_all(&cmd_bytes).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes).await.unwrap();

        let response: serde_json::Value = serde_json::from_slice(&response_bytes).unwrap();
        assert!(response["success"].as_bool().unwrap());
        assert!(response["data"].get("connected").is_some());
    }
}
