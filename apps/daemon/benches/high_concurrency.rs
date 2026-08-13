use async_trait::async_trait;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use futures::future::join_all;
use shadowmesh_daemon::{
    ShadowApi, SystemCommandRunner, VpnAction, VpnCommand, VpnResponse, VpnTunnel,
    create_test_daemon, handle_ipc_io,
};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

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

async fn run_client_request(socket_path: &str) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(socket_path).await?;
    let req = VpnCommand { action: VpnAction::Ping, token: "test".into() };
    let req_bytes = serde_json::to_vec(&req)?;
    stream.write_all(&req_bytes).await?;
    stream.shutdown().await?;

    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).await?;
    let resp: VpnResponse = serde_json::from_slice(&resp_bytes)?;
    if !resp.success {
        return Err(anyhow::anyhow!("Request failed"));
    }
    Ok(())
}

fn bench_high_concurrency(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let daemon = create_test_daemon(Arc::new(MockApi), Arc::new(BenchCommandRunner));
    let socket_path = "/tmp/shadowmesh_concurrency.sock";

    let mut group = c.benchmark_group("high_concurrency");
    group.sample_size(10);

    for concurrent_count in [1, 10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrent_count),
            concurrent_count,
            |b, &count| {
                b.iter_custom(|iters| {
                    let daemon = Arc::clone(&daemon);

                    rt.block_on(async {
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

                        let mut all_latencies = Vec::with_capacity((iters as usize) * count);
                        let start = std::time::Instant::now();
                        for _ in 0..iters {
                            let mut clients = Vec::with_capacity(count);
                            for _ in 0..count {
                                clients.push(tokio::spawn(async move {
                                    let start_req = std::time::Instant::now();
                                    run_client_request(socket_path).await?;
                                    Ok::<std::time::Duration, anyhow::Error>(start_req.elapsed())
                                }));
                            }

                            let results = join_all(clients).await;
                            for res in results {
                                let lat = res
                                    .unwrap()
                                    .expect("Client request failed during concurrency bench");
                                all_latencies.push(lat);
                            }
                        }
                        let duration = start.elapsed();

                        if iters > 0 {
                            all_latencies.sort();
                            let len = all_latencies.len();
                            println!("\n--- Concurrency Profile ({} clients) ---", count);
                            println!("p55:  {:?}", all_latencies[(len * 55) / 100]);
                            println!("p95:  {:?}", all_latencies[(len * 95) / 100]);
                            println!("p99:  {:?}", all_latencies[(len * 99) / 100]);
                            if len >= 1000 {
                                println!("p99.9: {:?}", all_latencies[(len * 999) / 1000]);
                            }
                            println!("---------------------------------------\n");
                        }

                        // Cleanup
                        drop(server_task);
                        if Path::new(socket_path).exists() {
                            let _ = std::fs::remove_file(socket_path);
                        }

                        duration
                    })
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_high_concurrency);
criterion_main!(benches);
