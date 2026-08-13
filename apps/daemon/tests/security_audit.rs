use async_trait::async_trait;
use shadowmesh_core::SecurityEnforcer;
use shadowmesh_daemon::{ShadowApi, SystemCommandRunner, VpnTunnel, create_test_daemon};
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
    commands: Arc<Mutex<Vec<String>>>,
}
#[async_trait]
impl SystemCommandRunner for MockRunner {
    async fn run_command(&self, cmd: &str, args: &[&str]) -> anyhow::Result<String> {
        self.commands.lock().await.push(format!("{} {}", cmd, args.join(" ")));
        Ok("mock output".into())
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
            dns: "1.1.1.1".into(),
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

#[tokio::test]
async fn test_security_audit_kill_switch() {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let runner = Arc::new(MockRunner { commands: commands.clone() });
    let daemon = create_test_daemon(Arc::new(MockApi), runner);

    daemon.apply_kill_switch().await.expect("Failed to apply kill switch");

    let history = commands.lock().await;
    #[cfg(target_os = "linux")]
    assert!(history.iter().any(|c| c.contains("iptables -P OUTPUT DROP")));
    #[cfg(target_os = "windows")]
    assert!(history.iter().any(|c| {
        c.contains("netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound")
    }));
}

#[tokio::test]
async fn test_security_audit_dns_enforcement() {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let runner = Arc::new(MockRunner { commands: commands.clone() });
    let daemon = create_test_daemon(Arc::new(MockApi), runner);

    daemon.enforce_dns(vec!["1.1.1.1".into()]).await.expect("Failed to enforce DNS");

    // On Linux we use zbus, so MockRunner won't see resolvectl commands anymore.
    // On Windows we still use netsh via runner.
    #[cfg(target_os = "windows")]
    {
        let history = commands.lock().await;
        assert!(history.iter().any(|c| {
            c.contains("netsh interface ipv4 set dnsserver shadowmesh-wg0 static 1.1.1.1 primary")
        }));
    }
}

#[tokio::test]
async fn test_pii_scrubbing_in_errors() {
    use shadowmesh_core::ShadowMeshError;
    let token = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="; // Matches KEY_REGEX (43 chars + =)
    let err = ShadowMeshError::Unauthorized(token.to_string());

    let display = format!("{}", err);
    assert!(!display.contains(token));
    assert!(display.contains("[REDACTED_KEY]"));
}
