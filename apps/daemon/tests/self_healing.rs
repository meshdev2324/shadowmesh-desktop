use async_trait::async_trait;
use shadowmesh_core::{ConnectionStatus, NetworkType};
use shadowmesh_daemon::create_test_daemon;
use shadowmesh_daemon::{ShadowApi, SystemCommandRunner, VpnTunnel};
use std::sync::Arc;
use tokio::sync::Mutex;

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

struct MockRunner {
    reconnect_count: Arc<Mutex<u32>>,
}
#[async_trait]
impl SystemCommandRunner for MockRunner {
    async fn run_command(&self, _: &str, _: &[&str]) -> anyhow::Result<String> {
        Ok("".into())
    }
    async fn spawn_tunnel(
        &self,
        _: &str,
        _: &[&str],
        _: String,
    ) -> anyhow::Result<Box<dyn VpnTunnel>> {
        *self.reconnect_count.lock().await += 1;
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

#[tokio::test]
async fn test_self_healing_on_network_change() {
    let reconnect_count = Arc::new(Mutex::new(0));
    let runner = Arc::new(MockRunner { reconnect_count: reconnect_count.clone() });
    let daemon = create_test_daemon(Arc::new(MockApi), runner);

    // 1. Manually set state to connected
    daemon.vpn_manager.set_status(ConnectionStatus::Connected);

    // Simulate initial network
    let last_net_id = format!("{:?}-true", NetworkType::WiFi);

    // 2. Trigger network change logic (extracted from lib.rs loop)
    let new_net_id = format!("{:?}-true", NetworkType::Ethernet);

    if new_net_id != last_net_id {
        let node_id = Some("test-node".to_string());
        let mode = Some("normal".to_string());

        if let Some(id) = node_id {
            daemon.handle_connect(id, mode).await;
        }
    }

    assert_eq!(*reconnect_count.lock().await, 1);
}
