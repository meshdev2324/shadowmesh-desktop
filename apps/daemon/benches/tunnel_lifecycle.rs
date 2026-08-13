use async_trait::async_trait;
use criterion::{Criterion, criterion_group, criterion_main};
use shadowmesh_daemon::{ShadowApi, SystemCommandRunner, VpnTunnel, create_test_daemon};
use std::sync::Arc;

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

struct VirtualCommandRunner;
#[async_trait]
impl SystemCommandRunner for VirtualCommandRunner {
    async fn run_command(&self, _cmd: &str, _args: &[&str]) -> anyhow::Result<String> {
        Ok("ok".into())
    }
    async fn spawn_tunnel(
        &self,
        _cmd: &str,
        _args: &[&str],
        _name: String,
    ) -> anyhow::Result<Box<dyn VpnTunnel>> {
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
            dns: "1.1.1.1, 8.8.8.8".into(),
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

fn bench_tunnel_lifecycle_logic(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let api = Arc::new(MockApi);
    let runner = Arc::new(VirtualCommandRunner);
    let daemon = create_test_daemon(api, runner);

    let mut group = c.benchmark_group("tunnel_lifecycle");
    group.sample_size(10);

    group.bench_function("connect_disconnect_cycle_optimized", |b| {
        b.iter(|| {
            let daemon = Arc::clone(&daemon);
            rt.block_on(async {
                let _ = daemon.handle_connect("test-node".into(), None).await;
                let _ = daemon.handle_disconnect().await;
            });
        });
    });
    group.finish();
}

criterion_group!(benches, bench_tunnel_lifecycle_logic);
criterion_main!(benches);
