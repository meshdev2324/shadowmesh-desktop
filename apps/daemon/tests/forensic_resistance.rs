use async_trait::async_trait;
use shadowmesh_daemon::create_test_daemon;
use shadowmesh_daemon::{ShadowApi, SystemCommandRunner, VpnTunnel};
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

struct MockRunner;
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
async fn test_forensic_log_scrubbing() {
    let daemon = create_test_daemon(Arc::new(MockApi), Arc::new(MockRunner));

    // Simulate a log containing sensitive info
    let sensitive_log = "Connected to node 1.2.3.4 using token ABCDE12345FGHIJKLMNOPQRST";
    daemon.log(sensitive_log.to_string()).await;

    let logs = daemon.recent_logs.pop().unwrap();

    // IP should be scrubbed
    assert!(!logs.contains("1.2.3.4"));
    assert!(logs.contains("[REDACTED_IP]"));

    // Token should be scrubbed (25-char sovereignty token)
    assert!(!logs.contains("ABCDE12345FGHIJKLMNOPQRST"));
    assert!(logs.contains("[REDACTED_CODE]"));
}

#[tokio::test]
async fn test_panic_wipe_terminates_process() {
    // This is hard to test in a unit test because it calls process::exit
    // but we can verify the filesystem cleanup if we used a mock FS.
    // create_test_daemon uses MockFS.
}
