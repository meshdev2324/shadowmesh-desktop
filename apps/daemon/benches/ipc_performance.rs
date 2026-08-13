use async_trait::async_trait;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use shadowmesh_daemon::{
    ShadowApi, SystemCommandRunner, VpnAction, VpnCommand, VpnResponse, VpnTunnel,
    create_test_daemon, handle_ipc_io,
};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

struct BenchCommandRunner;
#[async_trait]
impl SystemCommandRunner for BenchCommandRunner {
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
    fn get_core_client(&self) -> std::sync::Arc<shadowmesh_core::ApiClient> {
        std::sync::Arc::new(shadowmesh_core::ApiClient::new("http://localhost".into()).unwrap())
    }
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
}

async fn client_send_framed<W>(writer: &mut W, payload: &[u8]) -> tokio::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn client_recv_framed<R>(reader: &mut R) -> tokio::io::Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    let len = reader.read_u32().await? as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

fn bench_ipc_transport_overhead(c: &mut Criterion) {
    let daemon = create_test_daemon(Arc::new(MockApi), Arc::new(BenchCommandRunner));
    let rt = tokio::runtime::Runtime::new().unwrap();

    let socket_path = "/tmp/shadowmesh_bench_framed.sock";

    let mut group = c.benchmark_group("ipc_transport_v4");
    group.sample_size(10);

    group.bench_function("ipc_uds_roundtrip_latency_framed", |b| {
        b.iter_custom(|iters| {
            let daemon = Arc::clone(&daemon);

            rt.block_on(async {
                if Path::new(socket_path).exists() {
                    let _ = std::fs::remove_file(socket_path);
                }
                let listener = UnixListener::bind(socket_path).unwrap();

                let daemon_clone = Arc::clone(&daemon);
                let _server_task = tokio::spawn(async move {
                    while let Ok((stream, _)) = listener.accept().await {
                        let daemon_inner = Arc::clone(&daemon_clone);
                        tokio::spawn(async move {
                            let (reader, writer) = tokio::io::split(stream);
                            let _ = handle_ipc_io(reader, writer, daemon_inner).await;
                        });
                    }
                });

                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let mut stream = tokio::net::UnixStream::connect(socket_path).await.unwrap();
                    let req = VpnCommand { action: VpnAction::Ping, token: "test".into() };
                    let req_bytes = serde_json::to_vec(&req).unwrap();

                    client_send_framed(&mut stream, &req_bytes).await.unwrap();
                    let resp_bytes = client_recv_framed(&mut stream).await.unwrap();
                    let resp: VpnResponse = serde_json::from_slice(&resp_bytes).unwrap();
                    assert!(resp.success);
                }
                start.elapsed()
            })
        });
    });

    if Path::new(socket_path).exists() {
        let _ = std::fs::remove_file(socket_path);
    }
    group.finish();
}

fn bench_ipc_payload_scaling_framed(c: &mut Criterion) {
    let daemon = create_test_daemon(Arc::new(MockApi), Arc::new(BenchCommandRunner));
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("ipc_payload_size_v4");
    group.sample_size(10);

    for size in [0, 1024, 4096, 16384].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let daemon = Arc::clone(&daemon);
                rt.block_on(async {
                    let (client, server) = tokio::io::duplex(65536);
                    let (mut client_reader, mut client_writer) = tokio::io::split(client);
                    let (server_reader, server_writer) = tokio::io::split(server);

                    let handler = tokio::spawn(async move {
                        let _ = handle_ipc_io(server_reader, server_writer, daemon).await;
                    });

                    let req = VpnCommand {
                        action: VpnAction::Activate { code: "A".repeat(size).into() },
                        token: "test".into(),
                    };
                    let req_bytes = serde_json::to_vec(&req).unwrap();

                    client_send_framed(&mut client_writer, &req_bytes).await.unwrap();
                    let resp_bytes = client_recv_framed(&mut client_reader).await.unwrap();
                    let _resp: VpnResponse = serde_json::from_slice(&resp_bytes).unwrap();

                    // Close connection
                    drop(client_writer);
                    handler.await.unwrap();
                });
            });
        });
    }
    group.finish();
}

fn bench_persistent_connection(c: &mut Criterion) {
    let daemon = create_test_daemon(Arc::new(MockApi), Arc::new(BenchCommandRunner));
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("ipc_persistent_v4");
    group.sample_size(10);

    group.bench_function("persistent_ping_latency", |b| {
        b.iter_custom(|iters| {
            let daemon = Arc::clone(&daemon);
            rt.block_on(async {
                let (client, server) = tokio::io::duplex(65536);
                let (mut client_reader, mut client_writer) = tokio::io::split(client);
                let (server_reader, server_writer) = tokio::io::split(server);

                let _handler = tokio::spawn(async move {
                    let _ = handle_ipc_io(server_reader, server_writer, daemon).await;
                });

                let req = VpnCommand { action: VpnAction::Ping, token: "test".into() };
                let req_bytes = serde_json::to_vec(&req).unwrap();

                let start = std::time::Instant::now();
                for _ in 0..iters {
                    client_send_framed(&mut client_writer, &req_bytes).await.unwrap();
                    let resp_bytes = client_recv_framed(&mut client_reader).await.unwrap();
                    let _resp: VpnResponse = serde_json::from_slice(&resp_bytes).unwrap();
                }
                start.elapsed()
            })
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ipc_transport_overhead,
    bench_ipc_payload_scaling_framed,
    bench_persistent_connection
);
criterion_main!(benches);
