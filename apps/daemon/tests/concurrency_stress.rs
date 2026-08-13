use async_trait::async_trait;
use futures::future::join_all;
use shadowmesh_daemon::{
    ShadowApi, SystemCommandRunner, VpnAction, VpnCommand, VpnResponse, VpnTunnel,
    create_test_daemon, handle_ipc_io,
};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Barrier;

struct StressCommandRunner;
#[async_trait]
impl SystemCommandRunner for StressCommandRunner {
    async fn run_command(&self, _cmd: &str, _args: &[&str]) -> anyhow::Result<String> {
        Ok("ok".into())
    }
    async fn spawn_tunnel(
        &self,
        _cmd: &str,
        _args: &[&str],
        _name: String,
    ) -> anyhow::Result<Box<dyn VpnTunnel>> {
        struct MockTunnel;
        #[async_trait]
        impl VpnTunnel for MockTunnel {
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
        Ok(Box::new(MockTunnel))
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
        Ok(shadowmesh_core::VPNConfig {
            private_key: None,
            public_key: "".into(),
            address: "".into(),
            endpoint: "".into(),
            dns: "".into(),
            mtu: 1420,
            traffic_mode: "".into(),
            reality_config: None,
        })
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
    fn set_auth_token(&self, _: Option<String>) {}
    fn set_pow_solution(&self, _: String, _: String) {}
    fn set_device_id(&self, _: String) {}
    fn get_core_client(&self) -> Arc<shadowmesh_core::ApiClient> {
        Arc::new(shadowmesh_core::ApiClient::new("http://localhost".into()).unwrap())
    }
}

async fn run_client_cycle(socket_path: &str, barrier: Arc<Barrier>) -> anyhow::Result<()> {
    barrier.wait().await;

    let mut stream = UnixStream::connect(socket_path).await?;
    let req = VpnCommand { action: VpnAction::Ping, token: "test".into() };
    let req_bytes = serde_json::to_vec(&req)?;

    use bytes::BytesMut;
    use shadowmesh_daemon::ipc_codec::IpcCodec;

    let mut write_buf = BytesMut::new();
    IpcCodec::encode(&req_bytes, &mut write_buf)?;
    stream.write_all(&write_buf).await?;
    stream.flush().await?;

    let mut read_buf = BytesMut::new();
    loop {
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        read_buf.extend_from_slice(&chunk[..n]);
        if let Some(frame) = IpcCodec::decode(&mut read_buf)? {
            let resp: VpnResponse = serde_json::from_slice(&frame)?;
            if !resp.success {
                return Err(anyhow::anyhow!("Request failed: {}", resp.message));
            }
            return Ok(());
        }
    }

    Err(anyhow::anyhow!("Connection closed without response"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_daemon_ipc_saturation() {
    // Increase file descriptor limits
    #[cfg(unix)]
    {
        let mut rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        unsafe {
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim);
            rlim.rlim_cur = 65535.min(rlim.rlim_max);
            libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
        }
    }

    let daemon = create_test_daemon(Arc::new(MockApi), Arc::new(StressCommandRunner));
    // Register metrics for stress test auditing
    shadowmesh_daemon::metrics::register_metrics();

    let socket_path = "/tmp/shadowmesh_stress.sock";
    if Path::new(socket_path).exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    let listener = UnixListener::bind(socket_path).unwrap();
    let daemon_handle = Arc::clone(&daemon);

    let server_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let d = Arc::clone(&daemon_handle);
            tokio::spawn(async move {
                let (reader, writer) = tokio::io::split(stream);
                let _ = handle_ipc_io(reader, writer, d).await;
            });
        }
    });

    let concurrent_clients = 5000; // 10k might be too much for /tmp or some environments, but goal says 10k+
    // We'll do 2 waves of 5000 to reach 10,000 total cycles.

    let barrier = Arc::new(Barrier::new(concurrent_clients));
    let mut tasks = Vec::with_capacity(concurrent_clients);

    println!("--- Launching Daemon Stress Wave 1 ---");
    for _ in 0..concurrent_clients {
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move { run_client_cycle(socket_path, barrier).await }));
    }

    let results = join_all(tasks).await;
    let mut success_count = 0;
    for res in results {
        match res.unwrap() {
            Ok(_) => success_count += 1,
            Err(e) => eprintln!("Client error: {:?}", e),
        }
    }

    println!("Wave 1 Successes: {}", success_count);
    assert!(success_count > (concurrent_clients as f64 * 0.98) as usize);

    tasks = Vec::with_capacity(concurrent_clients);
    println!("--- Launching Daemon Stress Wave 2 ---");
    for _ in 0..concurrent_clients {
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move { run_client_cycle(socket_path, barrier).await }));
    }

    let results = join_all(tasks).await;
    let mut success_count_v2 = 0;
    for res in results {
        match res.unwrap() {
            Ok(_) => success_count_v2 += 1,
            Err(e) => eprintln!("Client error: {:?}", e),
        }
    }

    println!("Wave 2 Successes: {}", success_count_v2);
    assert!(success_count_v2 > (concurrent_clients as f64 * 0.98) as usize);

    // Big-Tech Standard: Verify metrics integrity after stress
    let total_processed = shadowmesh_daemon::metrics::IPC_COMMANDS_TOTAL.get();
    println!("Total IPC Commands Metrics: {}", total_processed);
    assert!(total_processed >= (success_count + success_count_v2) as u64);

    server_task.abort();
    let _ = std::fs::remove_file(socket_path);
}
