use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use shadowmesh_daemon::ipc_codec::IpcCodec;
use shadowmesh_daemon::{
    ShadowApi, SystemCommandRunner, VpnAction, VpnCommand, VpnResponse, VpnTunnel,
    create_test_daemon, handle_ipc_io,
};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

struct MockRunner;
#[async_trait]
impl SystemCommandRunner for MockRunner {
    async fn run_command(&self, _: &str, _: &[&str]) -> anyhow::Result<String> {
        Ok("ok".into())
    }
    async fn spawn_tunnel(
        &self,
        _: &str,
        _: &[&str],
        _: String,
    ) -> anyhow::Result<Box<dyn VpnTunnel>> {
        struct T;
        #[async_trait]
        impl VpnTunnel for T {
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
        Ok(Box::new(T))
    }
}

struct MockApi;
#[async_trait]
impl ShadowApi for MockApi {
    async fn request_activation_challenge(
        &self,
        _: String,
    ) -> Result<shadowmesh_core::ActivationChallenge, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::ActivationChallenge { challenge: "".into(), difficulty: 0 })
    }
    async fn activate(
        &self,
        _: shadowmesh_core::ActivationRequest,
    ) -> Result<shadowmesh_core::ActivationResponse, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::ActivationResponse {
            message: "".into(),
            token: None,
            plan: None,
            expires_at: None,
            remaining_days: 0,
            subscription_notice: "".into(),
            devices_remaining: 0,
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
        _: String,
        _: String,
        _: Option<String>,
    ) -> Result<shadowmesh_core::VPNConfig, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::VPNConfig::test_fixture())
    }
    async fn heartbeat(
        &self,
        _: shadowmesh_core::HeartbeatRequest,
    ) -> Result<shadowmesh_core::HeartbeatResponse, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::HeartbeatResponse {
            message: "".into(),
            device_id: "".into(),
            session_active: true,
            subscription_notice: "".into(),
            next_heartbeat: "".into(),
        })
    }
    async fn get_identity_info(
        &self,
    ) -> Result<shadowmesh_core::IdentityInfo, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::IdentityInfo {
            id: 0,
            public_key: "".into(),
            is_admin: false,
            mfa_enabled: false,
            created_at: "".into(),
        })
    }
    async fn qr_generate(
        &self,
        _: String,
        _: String,
        _: String,
        _: String,
        _: String,
    ) -> Result<String, shadowmesh_core::ShadowMeshError> {
        Ok("".into())
    }
    async fn qr_status(&self, _: String) -> Result<String, shadowmesh_core::ShadowMeshError> {
        Ok("".into())
    }
    async fn check_health(
        &self,
    ) -> Result<shadowmesh_core::HealthStatus, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::HealthStatus {
            status: "".into(),
            version: "".into(),
            uptime_seconds: 0,
        })
    }
    async fn report_compromised(
        &self,
        _: String,
        _: String,
    ) -> Result<(), shadowmesh_core::ShadowMeshError> {
        Ok(())
    }
    async fn ping_gateway(&self) -> Result<bool, shadowmesh_core::ShadowMeshError> {
        Ok(true)
    }
    fn set_auth_token(&self, _: Option<String>) {}
    fn set_pow_solution(&self, _: String, _: String) {}
    fn set_device_id(&self, _: String) {}
    fn get_core_client(&self) -> Arc<shadowmesh_core::ApiClient> {
        Arc::new(shadowmesh_core::ApiClient::new("http://localhost".into()).unwrap())
    }
}

async fn setup_robustness_server(socket_path: &str) -> tokio::task::JoinHandle<()> {
    if Path::new(socket_path).exists() {
        let _ = std::fs::remove_file(socket_path);
    }
    let daemon = create_test_daemon(Arc::new(MockApi), Arc::new(MockRunner));
    let listener = UnixListener::bind(socket_path).unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let d = Arc::clone(&daemon);
            tokio::spawn(async move {
                let (reader, writer) = tokio::io::split(stream);
                let _ = handle_ipc_io(reader, writer, d).await;
            });
        }
    })
}

#[tokio::test]
async fn test_ipc_large_payload_rejection() {
    let socket_path = "/tmp/shadowmesh_large.sock";
    let server = setup_robustness_server(socket_path).await;

    let mut stream = UnixStream::connect(socket_path).await.unwrap();

    let mut header = BytesMut::with_capacity(4);
    header.put_u32(10 * 1024 * 1024);
    stream.write_all(&header).await.unwrap();

    let mut buf = [0u8; 1];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "Daemon should have closed the connection");

    server.abort();
    let _ = std::fs::remove_file(socket_path);
}

#[tokio::test]
async fn test_ipc_malformed_json_recovery() {
    let socket_path = "/tmp/shadowmesh_malformed.sock";
    let server = setup_robustness_server(socket_path).await;

    let mut stream = UnixStream::connect(socket_path).await.unwrap();

    let garbage = b"{ garbage: true ]";
    let mut buf = BytesMut::new();
    buf.put_u32(garbage.len() as u32);
    buf.put_slice(garbage);
    stream.write_all(&buf).await.unwrap();

    let mut read_buf = BytesMut::new();
    loop {
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        read_buf.extend_from_slice(&chunk[..n]);
        if let Some(frame) = IpcCodec::decode(&mut read_buf).unwrap() {
            let resp: VpnResponse = serde_json::from_slice(&frame).unwrap();
            assert!(!resp.success);
            assert!(resp.message.contains("Malformed JSON"));
            break;
        }
    }

    let req = VpnCommand { action: VpnAction::Ping, token: "test".into() };
    let req_bytes = serde_json::to_vec(&req).unwrap();
    buf.clear();
    IpcCodec::encode(&req_bytes, &mut buf).unwrap();
    stream.write_all(&buf).await.unwrap();

    read_buf.clear();
    loop {
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        read_buf.extend_from_slice(&chunk[..n]);
        if let Some(frame) = IpcCodec::decode(&mut read_buf).unwrap() {
            let resp: VpnResponse = serde_json::from_slice(&frame).unwrap();
            assert!(resp.success);
            assert_eq!(resp.message, "pong");
            break;
        }
    }

    server.abort();
    let _ = std::fs::remove_file(socket_path);
}

#[tokio::test]
async fn test_metrics_server_encoding() {
    let port = 9091;
    shadowmesh_daemon::metrics::register_metrics();

    let server = tokio::spawn(async move {
        let _ = shadowmesh_daemon::metrics::start_metrics_server(port).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let resp = client.get(format!("http://127.0.0.1:{}/metrics", port)).send().await.unwrap();

    assert!(resp.status().is_success());
    let body = resp.text().await.unwrap();
    assert!(body.contains("vpn_bytes_sent_total"));

    server.abort();
}
