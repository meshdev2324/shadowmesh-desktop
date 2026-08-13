use arc_swap::ArcSwap;
use async_trait::async_trait;
use crossbeam_queue::ArrayQueue;
use shadowmesh_daemon::network_config::DnsManager;
use shadowmesh_daemon::types::DaemonConfig;
use shadowmesh_daemon::{
    Daemon, FileSystem, SecureStorage, ShadowApi, SystemCommandRunner, VpnAction, VpnCommand,
    VpnTunnel, process_command,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// --- Mocks ---

struct MockApi {
    auth_token: Mutex<Option<String>>,
}
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
            message: "OK".into(),
            token: Some("test-token".into()),
            plan: Some("Pro".into()),
            expires_at: None,
            remaining_days: 365,
            subscription_notice: "".into(),
            devices_remaining: 5,
            vpn_config: None,
            server_location: None,
        })
    }
    async fn get_nodes(
        &self,
    ) -> Result<Vec<shadowmesh_core::VPNNode>, shadowmesh_core::ShadowMeshError> {
        Ok(vec![shadowmesh_core::VPNNode {
            id: "node-1".into(),
            name: "Test Node".into(),
            region: "North America".into(),
            country: "US".into(),
            endpoint: "1.1.1.1:51820".into(),
            public_key: "pub".into(),
            load: 10,
            latency: 50,
            is_online: true,
        }])
    }
    async fn get_config(
        &self,
        _: String,
        _: String,
        _: Option<String>,
    ) -> Result<shadowmesh_core::VPNConfig, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::VPNConfig {
            private_key: None,
            public_key: "pub".into(),
            address: "10.0.0.2".into(),
            endpoint: "1.1.1.1:51820".into(),
            dns: "1.1.1.1".into(),
            mtu: 1420,
            traffic_mode: "normal".into(),
            reality_config: None,
        })
    }
    async fn heartbeat(
        &self,
        _: shadowmesh_core::HeartbeatRequest,
    ) -> Result<shadowmesh_core::HeartbeatResponse, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::HeartbeatResponse {
            message: "OK".into(),
            device_id: "id".into(),
            session_active: true,
            subscription_notice: "".into(),
            next_heartbeat: "".into(),
        })
    }
    async fn get_identity_info(
        &self,
    ) -> Result<shadowmesh_core::IdentityInfo, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::IdentityInfo {
            id: 1,
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
        Ok("t".into())
    }
    async fn qr_status(&self, _: String) -> Result<String, shadowmesh_core::ShadowMeshError> {
        Ok("authorized".into())
    }
    async fn check_health(
        &self,
    ) -> Result<shadowmesh_core::HealthStatus, shadowmesh_core::ShadowMeshError> {
        Ok(shadowmesh_core::HealthStatus {
            status: "ok".into(),
            version: "1.0".into(),
            uptime_seconds: 100,
        })
    }
    async fn report_compromised(
        &self,
        _: String,
        _: String,
    ) -> Result<(), shadowmesh_core::ShadowMeshError> {
        Ok(())
    }
    fn set_auth_token(&self, t: Option<String>) {
        let mut guard = self.auth_token.try_lock().unwrap();
        *guard = t;
    }
    fn set_pow_solution(&self, _: String, _: String) {}
    fn set_device_id(&self, _: String) {}
    fn get_core_client(&self) -> Arc<shadowmesh_core::ApiClient> {
        Arc::new(shadowmesh_core::ApiClient::new("http://localhost".into()).unwrap())
    }
}

struct MockFS {
    files: Mutex<HashMap<String, String>>,
}
#[async_trait]
impl FileSystem for MockFS {
    async fn read_to_string(&self, path: &str) -> anyhow::Result<String> {
        self.files.lock().await.get(path).cloned().ok_or(anyhow::anyhow!("File not found"))
    }
    async fn read(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        self.read_to_string(path).await.map(|s| s.into_bytes())
    }
    async fn write(&self, path: &str, contents: String) -> anyhow::Result<()> {
        self.files.lock().await.insert(path.to_string(), contents);
        Ok(())
    }
    async fn create_dir_all(&self, _: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn remove_file(&self, path: &str) -> anyhow::Result<()> {
        self.files.lock().await.remove(path);
        Ok(())
    }
    fn metadata_permissions_mode(&self, _: &str) -> anyhow::Result<u32> {
        Ok(0o644)
    }
    fn set_permissions_mode(&self, _: &str, _: u32) -> anyhow::Result<()> {
        Ok(())
    }
}

struct MockStorage {
    data: Mutex<HashMap<String, String>>,
}
impl SecureStorage for MockStorage {
    fn get_password(&self, s: &str, u: &str) -> anyhow::Result<String> {
        self.data
            .try_lock()
            .unwrap()
            .get(&format!("{}:{}", s, u))
            .cloned()
            .ok_or(anyhow::anyhow!("Not found"))
    }
    fn set_password(&self, s: &str, u: &str, p: &str) -> anyhow::Result<()> {
        self.data.try_lock().unwrap().insert(format!("{}:{}", s, u), p.to_string());
        Ok(())
    }
    fn delete_password(&self, s: &str, u: &str) -> anyhow::Result<()> {
        self.data.try_lock().unwrap().remove(&format!("{}:{}", s, u));
        Ok(())
    }
}

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
        Ok("mock output".into())
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

struct MockDns;
#[async_trait]
impl DnsManager for MockDns {
    async fn set_dns(&self, _: &str, _: Vec<String>) -> anyhow::Result<()> {
        Ok(())
    }
    async fn reset_dns(&self, _: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

// --- Helper ---

async fn setup_test_daemon() -> Arc<Daemon> {
    let api = Arc::new(MockApi { auth_token: Mutex::new(None) });
    let fs = Arc::new(MockFS { files: Mutex::new(HashMap::new()) });
    let storage = Arc::new(MockStorage { data: Mutex::new(HashMap::new()) });
    let runner = Arc::new(MockRunner);
    let dns = Arc::new(MockDns);

    let device_id = "test-device".to_string();
    let settings = shadowmesh_core::UserSettings::default();
    let vpn_manager = Arc::new(shadowmesh_core::VPNManager::new(settings));
    let security_logger = shadowmesh_core::SecurityEventLogger::new(
        device_id.clone(),
        "1.0.0-TEST".into(),
        "/tmp".into(),
    )
    .unwrap()
    .into();
    let anti_tamper =
        Arc::new(shadowmesh_core::AntiTamperChecker::new(shadowmesh_core::AntiTamperConfig {
            expected_hashes: HashMap::new(),
        }));
    let kill_switch_manager = Arc::new(shadowmesh_core::KillSwitchManager::new());

    Arc::new(Daemon {
        vpn_manager,
        api_client: api,
        file_system: fs,
        secure_storage: storage,
        security_logger,
        anti_tamper,
        kill_switch_manager,
        command_runner: runner,
        dns_manager: dns,
        device_id,
        active_tunnel: Mutex::new(None),
        operational_state: tokio::sync::RwLock::new(
            shadowmesh_daemon::daemon::OperationalState::Active,
        ),
        recent_logs: ArrayQueue::new(200),
        config: ArcSwap::from_pointee(DaemonConfig::default()),
        config_path: "/tmp/test_config.json".into(),
        last_error: tokio::sync::RwLock::new(None),
        last_speed_result: tokio::sync::RwLock::new(None),
        stats: shadowmesh_daemon::daemon::AtomicStats {
            bytes_sent: std::sync::atomic::AtomicU64::new(0),
            bytes_received: std::sync::atomic::AtomicU64::new(0),
            last_update_ts: std::sync::atomic::AtomicU64::new(0),
        },
        has_config_dir_been_checked: std::sync::atomic::AtomicBool::new(true),
    })
}

// --- Tests ---

#[tokio::test]
async fn test_ipc_ping() {
    let daemon = setup_test_daemon().await;
    let cmd = VpnCommand { action: VpnAction::Ping, token: "".into() };
    let resp = process_command(cmd, daemon).await;
    assert!(resp.success);
    assert_eq!(resp.message, "pong");
}

#[tokio::test]
async fn test_ipc_activate() {
    let daemon = setup_test_daemon().await;
    let cmd = VpnCommand {
        action: VpnAction::Activate { code: "TEST-CODE-123".into() },
        token: "".into(),
    };
    let resp = process_command(cmd, daemon.clone()).await;
    assert!(resp.success);
    assert_eq!(resp.message, "Activated");

    let config = daemon.config.load();
    assert_eq!(config.activation_code, Some("TESTCODE123".into()));
    assert_eq!(config.auth_token, Some("test-token".into()));
}

#[tokio::test]
async fn test_ipc_connect_disconnect() {
    let daemon = setup_test_daemon().await;

    // Connect
    let cmd_connect = VpnCommand {
        action: VpnAction::Connect { node_id: "node-1".into(), mode: None },
        token: "".into(),
    };
    let resp_connect = process_command(cmd_connect, daemon.clone()).await;
    assert!(resp_connect.success);

    // Verify tunnel is active
    {
        let active = daemon.active_tunnel.lock().await;
        assert!(active.is_some());
    }

    // Disconnect
    let cmd_disconnect = VpnCommand { action: VpnAction::Disconnect, token: "".into() };
    let resp_disconnect = process_command(cmd_disconnect, daemon.clone()).await;
    assert!(resp_disconnect.success);
    assert_eq!(resp_disconnect.message, "Stopped");

    // Verify tunnel is cleared
    {
        let active = daemon.active_tunnel.lock().await;
        assert!(active.is_none());
    }
}

#[tokio::test]
async fn test_ipc_kill_switch() {
    let daemon = setup_test_daemon().await;
    let cmd = VpnCommand { action: VpnAction::SetKillSwitch { enabled: true }, token: "".into() };
    let resp = process_command(cmd, daemon.clone()).await;
    assert!(resp.success);

    let config = daemon.config.load();
    assert!(config.kill_switch);
}

#[tokio::test]
async fn test_lifecycle_stress() {
    let daemon = setup_test_daemon().await;
    for _ in 0..100 {
        daemon.handle_connect("node".into(), None).await;
        daemon.handle_disconnect().await;
    }
}

#[tokio::test]
async fn test_ipc_shutdown() {
    let daemon = setup_test_daemon().await;
    let cmd = VpnCommand { action: VpnAction::Shutdown, token: "".into() };
    let resp = process_command(cmd, daemon).await;
    assert!(resp.success);
    assert_eq!(resp.message, "Shutting down");
}
