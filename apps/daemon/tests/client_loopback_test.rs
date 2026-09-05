//! RFC-016 §6.1 — IPC client loopback tests.
//!
//! Drives the REAL daemon IPC stack (`handle_ipc_io` + `process_command`)
//! against the new `DaemonClient` over a real Unix socket pair, proving
//! framing, token transport, and round-trip behavior end to end.

use shadowmesh_daemon::client::{DaemonClient, socket_path_from};
use shadowmesh_daemon::ipc::handle_ipc_io;
use shadowmesh_daemon::types::VpnAction;
use shadowmesh_daemon::{
    Daemon, FileSystem, SecureStorage, ShadowApi, SystemCommandRunner, VpnTunnel,
};
use std::sync::Arc;

// ---- mocks (same shapes as the daemon's own mock suite) --------------------

struct MockCommandRunner;
#[async_trait::async_trait]
impl SystemCommandRunner for MockCommandRunner {
    async fn run_command(&self, _cmd: &str, _args: &[&str]) -> anyhow::Result<String> {
        Ok("mock".into())
    }
    async fn spawn_tunnel(
        &self,
        _cmd: &str,
        _args: &[&str],
        _name: String,
    ) -> anyhow::Result<Box<dyn VpnTunnel>> {
        struct NoTunnel;
        #[async_trait::async_trait]
        impl VpnTunnel for NoTunnel {
            fn pid(&self) -> Option<u32> {
                None
            }
            fn try_wait(&mut self) -> anyhow::Result<Option<std::process::ExitStatus>> {
                Ok(None)
            }
            async fn shutdown(&mut self) -> anyhow::Result<()> {
                Ok(())
            }
        }
        Ok(Box::new(NoTunnel))
    }
}

struct MockFs;
#[async_trait::async_trait]
impl FileSystem for MockFs {
    async fn read_to_string(&self, _path: &str) -> anyhow::Result<String> {
        Ok(String::new())
    }
    async fn read(&self, _path: &str) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
    async fn write(&self, _path: &str, _contents: String) -> anyhow::Result<()> {
        Ok(())
    }
    async fn create_dir_all(&self, _path: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn remove_file(&self, _path: &str) -> anyhow::Result<()> {
        Ok(())
    }
    fn metadata_permissions_mode(&self, _path: &str) -> anyhow::Result<u32> {
        Ok(0o600)
    }
    fn set_permissions_mode(&self, _path: &str, _mode: u32) -> anyhow::Result<()> {
        Ok(())
    }
}

struct MockStorage;
impl SecureStorage for MockStorage {
    fn get_password(&self, _service: &str, _user: &str) -> anyhow::Result<String> {
        Ok(String::new())
    }
    fn set_password(&self, _service: &str, _user: &str, _password: &str) -> anyhow::Result<()> {
        Ok(())
    }
    fn delete_password(&self, _service: &str, _user: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

struct MockApi;
#[async_trait::async_trait]
impl ShadowApi for MockApi {
    async fn request_activation_challenge(
        &self,
        _device_id: String,
    ) -> Result<shadowmesh_core::ActivationChallenge, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::ActivationChallenge { challenge: "".into(), difficulty: 0 })
    }
    async fn activate(
        &self,
        _req: shadowmesh_core::ActivationRequest,
    ) -> Result<shadowmesh_core::ActivationResponse, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::ActivationResponse {
            message: "OK".into(),
            token: Some("t".into()),
            plan: Some("Pro".into()),
            expires_at: None,
            remaining_days: 365,
            subscription_notice: "".into(),
            devices_remaining: 4,
            vpn_config: None,
            is_canary: Some(false),
            server_location: None,
        })
    }
    async fn get_nodes(
        &self,
    ) -> Result<Vec<shadowmesh_core::VPNNode>, shadowmesh_core::ShadowMeshError> {
        Ok(vec![])
    }
    async fn get_config(
        &self,
        _node_id: String,
        _priv_key: String,
        _mode: Option<String>,
    ) -> Result<shadowmesh_core::VPNConfig, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::VPNConfig::test_fixture())
    }
    async fn heartbeat(
        &self,
        _req: shadowmesh_core::HeartbeatRequest,
    ) -> Result<shadowmesh_core::HeartbeatResponse, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::HeartbeatResponse {
            message: "ok".into(),
            device_id: "test-device".into(),
            session_active: true,
            subscription_notice: String::new(),
            next_heartbeat: "3600".into(),
        })
    }
    async fn get_identity_info(
        &self,
    ) -> Result<shadowmesh_core::IdentityInfo, shadowmesh_core::ShadowMeshError> {
        Err(shadowmesh_core::ShadowMeshError::Other("n/a".into()))
    }
    async fn qr_generate(
        &self,
        _device_id: String,
        _device_name: String,
        _os_name: String,
        _os_version: String,
        _arch: String,
    ) -> Result<String, shadowmesh_core::ShadowMeshError> {
        Err(shadowmesh_core::ShadowMeshError::Other("n/a".into()))
    }
    async fn qr_status(&self, _token: String) -> Result<String, shadowmesh_core::ShadowMeshError> {
        Err(shadowmesh_core::ShadowMeshError::Other("n/a".into()))
    }
    async fn check_health(
        &self,
    ) -> Result<shadowmesh_core::HealthStatus, shadowmesh_core::ShadowMeshError> {
        Err(shadowmesh_core::ShadowMeshError::Other("n/a".into()))
    }
    async fn report_compromised(
        &self,
        _device_id: String,
        _reason: String,
    ) -> Result<(), shadowmesh_core::ShadowMeshError> {
        Ok(())
    }
    async fn ping_gateway(&self) -> Result<bool, shadowmesh_core::ShadowMeshError> {
        Ok(true)
    }
    fn set_auth_token(&self, _token: Option<String>) {}
    fn set_pow_solution(&self, _solution: String, _original_challenge: String) {}
    fn set_device_id(&self, _device_id: String) {}
    fn get_core_client(&self) -> Arc<shadowmesh_core::ApiClient> {
        unimplemented!("not exercised by IPC loopback tests")
    }
}

fn mock_daemon() -> Arc<Daemon> {
    Arc::new(
        Daemon::new(
            Arc::new(MockApi),
            Arc::new(MockFs),
            Arc::new(MockStorage),
            Arc::new(MockCommandRunner),
        )
        .expect("daemon composes"),
    )
}

// ---- tests ------------------------------------------------------------------

#[tokio::test]
async fn ping_and_disconnect_roundtrip_through_real_ipc_stack() {
    let _ = tracing_subscriber::fmt::try_init();
    let daemon = mock_daemon();

    let (client_sock, daemon_sock) = tokio::net::UnixStream::pair().expect("socketpair");
    let (r, w) = tokio::io::split(daemon_sock);
    tokio::spawn(handle_ipc_io(r, w, daemon));

    let mut client = DaemonClient::from_stream(client_sock);

    let pong = client.handshake().await.expect("ping roundtrip");
    assert!(pong.success);
    assert_eq!(pong.message, "pong");

    let disc = client.request(VpnAction::Disconnect).await.expect("disconnect roundtrip");
    assert!(disc.success, "disconnect with no active tunnel must succeed");
}

#[tokio::test]
async fn status_response_carries_tunnel_truth() {
    let daemon = mock_daemon();
    let (client_sock, daemon_sock) = tokio::net::UnixStream::pair().expect("socketpair");
    let (r, w) = tokio::io::split(daemon_sock);
    tokio::spawn(handle_ipc_io(r, w, daemon));

    let mut client = DaemonClient::from_stream(client_sock);
    let resp = client.request(VpnAction::Status).await.expect("status");
    assert!(resp.success);

    let data = match resp.data.expect("status payload") {
        shadowmesh_daemon::types::VpnResponseData::Status(v) => v,
        other => panic!("expected Status payload, got {other:?}"),
    };
    // RFC-016 G3: the tunnel truth block must always be present.
    assert!(data.get("tunnel").is_some(), "status must carry the tunnel block");
    assert_eq!(data["tunnel"]["active"], serde_json::json!(false));
}

#[tokio::test]
async fn unresponsive_daemon_times_out_instead_of_hanging() {
    let (client_sock, daemon_sock) = tokio::net::UnixStream::pair().expect("socketpair");
    // The "daemon" reads nothing and answers nothing.
    tokio::spawn(async move {
        let mut dead = daemon_sock;
        let mut sink = [0u8; 512];
        use tokio::io::AsyncReadExt;
        loop {
            if dead.read(&mut sink).await.unwrap_or(0) == 0 {
                break;
            }
        }
    });

    let mut client = DaemonClient::from_stream(client_sock);
    let started = std::time::Instant::now();
    let result =
        client.request_with_timeout(VpnAction::Ping, std::time::Duration::from_millis(150)).await;
    assert!(result.is_err(), "unresponsive daemon must time out");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "timeout must actually bound the wait"
    );
}

#[test]
fn socket_path_resolution_prefers_env_then_home() {
    // Env override wins.
    assert_eq!(
        socket_path_from("/home/x", Some("/custom/sock")),
        std::path::PathBuf::from("/custom/sock")
    );
    // Empty override falls through to HOME.
    assert_eq!(
        socket_path_from("/home/x", Some("")),
        std::path::PathBuf::from("/home/x/.shadowmesh.sock")
    );
    // Default: $HOME/.shadowmesh.sock
    assert_eq!(
        socket_path_from("/home/y", None),
        std::path::PathBuf::from("/home/y/.shadowmesh.sock")
    );
}
