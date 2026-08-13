use crate::api::ShadowApi;
use crate::network_config::DnsManager;
use crate::orchestration::{FileSystem, SecureStorage, SystemCommandRunner, VpnTunnel};
use crate::types::{CONFIG_DIR, CONFIG_FILE, DaemonConfig, SOCKET_PATH, VpnResponse};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use crossbeam_queue::ArrayQueue;
use shadowmesh_core::{
    ActivationRequest, AntiTamperChecker, AntiTamperConfig, KillSwitchManager, PoWChallenge,
    SecurityEnforcer, SecurityEventLogger, SecurityEventType, UserSettings, VPNManager,
    get_persistent_device_id, solve_pow,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

/// High-level lifecycle state of the Daemon.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OperationalState {
    Initializing,
    Active,
    ShuttingDown,
}

/// Managed handle for an active VPN tunnel process.
pub struct TunnelHandle {
    pub inner: Box<dyn VpnTunnel>,
    pub name: String,
    pub start_time: std::time::Instant,
}

impl TunnelHandle {
    pub fn new(inner: Box<dyn VpnTunnel>, name: String) -> Self {
        Self { inner, name, start_time: std::time::Instant::now() }
    }

    /// Attempts to gracefully terminate the tunnel process.
    pub async fn shutdown(mut self) {
        let pid = self.inner.pid();
        info!("🛑 Terminating tunnel process: {} (PID: {:?})", self.name, pid);
        let _ = self.inner.shutdown().await;
    }
}

/// Atomic statistics tracker for high-performance telemetry updates.
pub struct AtomicStats {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub last_update_ts: AtomicU64,
}

pub struct Daemon {
    pub vpn_manager: Arc<VPNManager>,
    pub api_client: Arc<dyn ShadowApi>,
    pub file_system: Arc<dyn FileSystem>,
    pub secure_storage: Arc<dyn SecureStorage>,
    pub security_logger: Arc<SecurityEventLogger>,
    pub anti_tamper: Arc<AntiTamperChecker>,
    pub kill_switch_manager: Arc<KillSwitchManager>,
    pub command_runner: Arc<dyn SystemCommandRunner>,
    pub dns_manager: Arc<dyn DnsManager>,
    pub device_id: String,

    /// Mutual exclusion for the active tunnel process to prevent race conditions.
    pub active_tunnel: Mutex<Option<TunnelHandle>>,

    /// Operational state using RwLock (infrequent updates).
    pub operational_state: RwLock<OperationalState>,

    /// O(1) lock-free ring-buffer for recent daemon log lines.
    /// Eliminates lock contention on the critical logging path.
    pub recent_logs: ArrayQueue<String>,

    /// Lock-free configuration state using ArcSwap.
    /// Provides wait-free reads for IPC status requests.
    pub config: ArcSwap<DaemonConfig>,
    pub config_path: String,

    pub last_error: RwLock<Option<String>>,
    pub last_speed_result: RwLock<Option<shadowmesh_core::SpeedTestResult>>,

    pub stats: AtomicStats,
    pub has_config_dir_been_checked: AtomicBool,
}

#[async_trait]
impl SecurityEnforcer for Daemon {
    async fn apply_kill_switch(&self) -> anyhow::Result<()> {
        info!("🛡️ Enabling System Kill Switch...");

        match std::env::consts::OS {
            "linux" => {
                // Flush and set default DROP policy safely
                self.command_runner.run_command("iptables", &["-F", "OUTPUT"]).await?;
                self.command_runner
                    .run_command("iptables", &["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
                    .await?;
                self.command_runner
                    .run_command(
                        "iptables",
                        &["-A", "OUTPUT", "-o", "shadowmesh-wg0", "-j", "ACCEPT"],
                    )
                    .await?;

                // Allow traffic to the API and VPN nodes (this should be more specific in prod)
                // For now, allow DNS to the VPN servers to avoid bootstrapping deadlocks
                self.command_runner
                    .run_command(
                        "iptables",
                        &["-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                    )
                    .await?;

                self.command_runner.run_command("iptables", &["-P", "OUTPUT", "DROP"]).await?;
            }
            "windows" => {
                self.command_runner
                    .run_command(
                        "netsh",
                        &[
                            "advfirewall",
                            "set",
                            "allprofiles",
                            "firewallpolicy",
                            "blockinbound,blockoutbound",
                        ],
                    )
                    .await?;
            }
            "macos" => {
                self.command_runner.run_command("pfctl", &["-e"]).await?;
            }
            _ => return Err(anyhow::anyhow!("Unsupported OS for kill switch")),
        };

        info!("✅ Kill Switch Active");
        Ok(())
    }

    async fn remove_kill_switch(&self) -> anyhow::Result<()> {
        info!("🔓 Disabling System Kill Switch...");
        match std::env::consts::OS {
            "linux" => {
                self.command_runner.run_command("iptables", &["-P", "OUTPUT", "ACCEPT"]).await?;
                self.command_runner.run_command("iptables", &["-F", "OUTPUT"]).await?;
            }
            "windows" => {
                self.command_runner
                    .run_command(
                        "netsh",
                        &[
                            "advfirewall",
                            "set",
                            "allprofiles",
                            "firewallpolicy",
                            "blockinbound,allowoutbound",
                        ],
                    )
                    .await?;
            }
            _ => {}
        };
        info!("✅ Kill Switch Inactive");
        Ok(())
    }

    async fn enforce_dns(&self, servers: Vec<String>) -> anyhow::Result<()> {
        self.dns_manager.set_dns("shadowmesh-wg0", servers).await
    }

    async fn reset_dns(&self) -> anyhow::Result<()> {
        self.dns_manager.reset_dns("shadowmesh-wg0").await
    }
}

impl Daemon {
    pub fn new(
        api_client: Arc<dyn ShadowApi>,
        file_system: Arc<dyn FileSystem>,
        secure_storage: Arc<dyn SecureStorage>,
        command_runner: Arc<dyn SystemCommandRunner>,
    ) -> anyhow::Result<Self> {
        let device_id = get_persistent_device_id();
        let settings = UserSettings::default();
        let vpn_manager = Arc::new(VPNManager::new(settings));

        let security_logger = SecurityEventLogger::new(
            device_id.clone(),
            "1.0.0-PRO".to_string(),
            format!("{}/security_logs", CONFIG_DIR),
        )
        .map(Arc::new)?;

        let anti_tamper = Arc::new(AntiTamperChecker::new(AntiTamperConfig {
            expected_hashes: std::collections::HashMap::new(),
        }));

        let kill_switch_manager = Arc::new(KillSwitchManager::new());

        let dns_manager = crate::network_config::create_dns_manager(Arc::clone(&command_runner));

        api_client.set_device_id(device_id.clone());

        let initial_logs = ArrayQueue::new(200);
        initial_logs.push("[INFO] ShadowMesh Pro-Daemon Start".to_string()).ok();

        Ok(Daemon {
            vpn_manager,
            api_client,
            file_system,
            secure_storage,
            security_logger,
            anti_tamper,
            kill_switch_manager,
            command_runner,
            dns_manager,
            device_id,
            active_tunnel: Mutex::new(None),
            operational_state: RwLock::new(OperationalState::Initializing),
            recent_logs: initial_logs,
            config: ArcSwap::from_pointee(DaemonConfig::default()),
            config_path: format!("{}/{}", CONFIG_DIR, CONFIG_FILE),
            last_error: RwLock::new(None),
            last_speed_result: RwLock::new(None),
            stats: AtomicStats {
                bytes_sent: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                last_update_ts: AtomicU64::new(0),
            },
            has_config_dir_been_checked: AtomicBool::new(false),
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn check_integrity(&self) {
        #[cfg(unix)]
        {
            if let Ok(mode) = self.file_system.metadata_permissions_mode(SOCKET_PATH)
                && mode & 0o777 != 0o666
            {
                warn!("🔒 Socket permissions sub-optimal (expected 666, got {:o})", mode & 0o777);
            }
        }

        if let Ok(exe_path) = std::env::current_exe()
            && let Some(path_str) = exe_path.to_str()
            && let Ok(data) = self.file_system.read(path_str).await
        {
            let anti_t = self.anti_tamper.clone();
            let data_c = data.clone();
            let verify_res = crate::run_blocking(move || {
                anti_t.verify_component("daemon-binary".into(), data_c)
            }).await;

            if let Ok(Ok(false)) = verify_res {
                warn!("🚨 TAMPERING DETECTED: Daemon binary hash mismatch!");
                let logger = Arc::clone(&self.security_logger);
                tokio::spawn(async move {
                    let _ = crate::run_blocking(move || {
                        logger.log_event(
                            SecurityEventType::TamperingAlert,
                            "Daemon binary integrity compromise detected".into(),
                            false,
                            None,
                        );
                    })
                    .await;
                });
            }
        }
    }

    pub async fn load_config(&self) {
        if let Ok(content) = self.file_system.read_to_string(&self.config_path).await
            && let Ok(mut conf) = serde_json::from_str::<DaemonConfig>(&content)
        {
            if let Ok(token) =
                self.secure_storage.get_password("org.shadowmesh.desktop", &self.device_id)
            {
                conf.auth_token = Some(token.clone());
                self.api_client.set_auth_token(Some(token));
            }
            self.config.store(Arc::new(conf));
        }
    }

    pub async fn save_config(&self) {
        if !self.has_config_dir_been_checked.load(Ordering::Relaxed) {
            let _ = self.file_system.create_dir_all(CONFIG_DIR).await;
            self.has_config_dir_been_checked.store(true, Ordering::Relaxed);
        }
        let config = self.config.load();

        if let Some(token) = &config.auth_token {
            let _ =
                self.secure_storage.set_password("org.shadowmesh.desktop", &self.device_id, token);
        }

        if let Ok(content) = serde_json::to_string_pretty(&**config) {
            let _ = self.file_system.write(&self.config_path, content).await;
        }
    }

    pub async fn log(&self, msg: String) {
        let scrubbed = shadowmesh_core::scrub_pii(&msg);
        let log_line =
            format!("[{}] {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), scrubbed);
        info!("{}", scrubbed);
        // Lock-free push to ring-buffer
        if self.recent_logs.push(log_line).is_err() {
            // Buffer full, pop one and retry
            let _ = self.recent_logs.pop();
            let _ = self.recent_logs.push(scrubbed);
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn handle_activate(&self, mut code: String) -> VpnResponse {
        code = code.replace("-", "");
        self.log(format!("🔑 Activation attempt for code: {}", code)).await;

        let challenge_res = self
            .api_client
            .request_activation_challenge(self.device_id.clone())
            .await
            .map_err(|e| e.to_string());

        let challenge = match challenge_res {
            Ok(c) => c,
            Err(e) => {
                return VpnResponse {
                    success: false,
                    message: format!("Task Error: {}", e),
                    data: None,
                };
            }
        };

        if !challenge.challenge.is_empty() {
            self.log(format!(
                "🧩 Solving Adaptive Friction Challenge (Difficulty: {})",
                challenge.difficulty
            ))
            .await;

            let sol_res = crate::run_blocking(move || {
                solve_pow(PoWChallenge {
                    challenge: challenge.challenge,
                    difficulty: challenge.difficulty,
                })
            })
            .await;

            match sol_res {
                Ok(Ok(sol)) => {
                    self.api_client.set_pow_solution(sol.solution, sol.challenge);
                }
                Ok(Err(e)) => {
                    return VpnResponse {
                        success: false,
                        message: format!("PoW Solve Failed: {}", e),
                        data: None,
                    };
                }
                Err(e) => {
                    return VpnResponse {
                        success: false,
                        message: format!("Runtime Error (PoW): {}", e),
                        data: None,
                    };
                }
            }
        }

        let hw_fingerprint = format!(
            "{}-{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".to_string())
        );

        let req = ActivationRequest {
            code: code.clone(),
            device_name: format!(
                "{} Desktop ({})",
                std::env::consts::OS,
                std::env::var("HOSTNAME")
                    .or_else(|_| std::env::var("COMPUTERNAME"))
                    .unwrap_or_else(|_| "Unknown".to_string())
            ),
            device_type: "desktop".into(),
            device_id: self.device_id.clone(),
            hardware_fingerprint: hw_fingerprint,
            public_key: None,
            deep_fingerprint: None,
            oob_nonce: None,
            oob_sig: None,
            oob_ts: None,
        };

        match self.api_client.activate(req).await {
            Ok(res) => {
                self.log(format!("✨ Activation Granted (Plan: {:?})", res.plan)).await;
                self.api_client.set_auth_token(res.token.clone());

                self.config.rcu(|config| {
                    let mut new_config = (**config).clone();
                    new_config.auth_token = res.token.clone();
                    new_config.activation_code = Some(code.clone());
                    new_config.plan_name = res.plan.clone().unwrap_or_else(|| "Solo".into());
                    new_config.devices_remaining = res.devices_remaining;
                    new_config.remaining_days = res.remaining_days;
                    new_config
                });

                self.save_config().await;

                let d_v = self.vpn_manager.clone();
                let res_clone = res.clone();
                let _ = crate::run_blocking(move || {
                    d_v.activate(
                        code,
                        res_clone.token,
                        res_clone.plan,
                        res_clone.devices_remaining,
                        res_clone.remaining_days,
                    )
                })
                .await;

                let data = serde_json::to_value(res).ok();
                VpnResponse {
                    success: true,
                    message: "Activated".into(),
                    data: data.map(crate::types::VpnResponseData::Generic),
                }
            }
            Err(e) => VpnResponse {
                success: false,
                message: format!("Activation Refused: {}", e),
                data: None,
            },
        }
    }

    pub async fn handle_list_nodes(&self) -> VpnResponse {
        match self.api_client.get_nodes().await {
            Ok(nodes) => VpnResponse {
                success: true,
                message: "OK".into(),
                data: Some(crate::types::VpnResponseData::Nodes(nodes)),
            },
            Err(e) => {
                VpnResponse { success: false, message: format!("API Error: {}", e), data: None }
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn handle_connect(
        &self,
        mut node_id: String,
        mut mode: Option<String>,
    ) -> VpnResponse {
        if node_id == "best" {
            if let Ok(nodes) = self.api_client.get_nodes().await {
                let best_res = crate::run_blocking(move || {
                    shadowmesh_core::shadow_route_best_node(nodes)
                })
                .await;

                if let Ok(Some(best)) = best_res {
                    self.log(format!(
                        "🎯 Shadow-Router selected best node: {} ({})",
                        best.name, best.id
                    ))
                    .await;
                    node_id = best.id;
                } else {
                    return VpnResponse {
                        success: false,
                        message: "No nodes available".into(),
                        data: None,
                    };
                }
            } else {
                return VpnResponse {
                    success: false,
                    message: "Failed to fetch nodes".into(),
                    data: None,
                };
            }
        }

        {
            let config = self.config.load();
            if config.plan_name.to_lowercase() == "team"
                && (mode.as_deref() == Some("normal") || mode.is_none())
            {
                self.log("🛡️ Team Plan detected: Enforcing Mandatory Stealth (Fragmented)".into())
                    .await;
                mode = Some("fragmented".to_string());
            }
        }

        self.log(format!("🚀 Initiating connection to node: {} | mode: {:?}", node_id, mode)).await;

        let priv_key = {
            let config = self.config.load();
            if config.private_key.is_none() {
                drop(config);
                let keys_res = crate::run_blocking(move || {
                    shadowmesh_core::generate_wireguard_keys()
                }).await;

                if let Ok(Ok(keys)) = keys_res {
                    self.config.rcu(|c| {
                        let mut new_c = (**c).clone();
                        new_c.private_key = Some(keys[0].clone());
                        new_c.public_key = Some(keys[1].clone());
                        new_c
                    });
                    self.save_config().await;
                } else {
                    return VpnResponse {
                        success: false,
                        message: "Key Generation Failed".into(),
                        data: None,
                    };
                }
            }
            self.config.load().private_key.clone().unwrap_or_default()
        };

        match self.api_client.get_config(node_id.clone(), priv_key.clone(), mode.clone()).await {
            Ok(config) => {
                self.log(format!("📝 Config received for endpoint: {}", config.endpoint)).await;
                if let Some(ref reality) = config.reality_config {
                    self.log("🌑 Reality Config detected. Starting Sing-box...".into()).await;
                    return self.process_singbox_config(reality, node_id, mode).await;
                }
                self.process_vpn_config(config, node_id, mode).await
            }
            Err(shadowmesh_core::ShadowMeshError::AdaptiveFrictionRequired(challenge)) => {
                self.log(
                    "🧩 Solving Adaptive Friction Challenge for Connection (Difficulty: 10+)"
                        .to_string(),
                )
                .await;
                let pow_challenge = shadowmesh_core::PoWChallenge { challenge, difficulty: 10 };
                let sol_res = crate::run_blocking(move || {
                    shadowmesh_core::solve_pow(pow_challenge)
                }).await;

                match sol_res {
                    Ok(Ok(sol)) => {
                        self.api_client.set_pow_solution(sol.solution, sol.challenge);
                        match self
                            .api_client
                            .get_config(node_id.clone(), priv_key, mode.clone())
                            .await
                        {
                            Ok(config) => {
                                if let Some(ref reality) = config.reality_config {
                                    return self
                                        .process_singbox_config(reality, node_id, mode)
                                        .await;
                                }
                                self.process_vpn_config(config, node_id, mode).await
                            }
                            Err(e) => VpnResponse {
                                success: false,
                                message: format!("API Error (Retry): {}", e),
                                data: None,
                            },
                        }
                    }
                    Ok(Err(e)) => VpnResponse {
                        success: false,
                        message: format!("PoW Solve Failed: {}", e),
                        data: None,
                    },
                    Err(e) => VpnResponse {
                        success: false,
                        message: format!("Runtime Error (PoW): {}", e),
                        data: None,
                    },
                }
            }
            Err(e) => {
                VpnResponse { success: false, message: format!("API Error: {}", e), data: None }
            }
        }
    }

    pub async fn process_singbox_config(
        &self,
        config: &shadowmesh_core::RealityConfig,
        node_id: String,
        mode: Option<String>,
    ) -> VpnResponse {
        let singbox_config = serde_json::json!({
            "log": { "level": "info" },
            "inbounds": [{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 1080
            }],
            "outbounds": [{
                "type": "vless",
                "tag": "vless-out",
                "server": config.server_ip,
                "server_port": config.port,
                "uuid": config.uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": true,
                    "server_name": config.sni_target,
                    "utls": { "enabled": true, "fingerprint": config.fingerprint },
                    "reality": { "enabled": true, "public_key": config.public_key, "short_id": config.short_id }
                }
            }]
        });

        let config_path = std::env::temp_dir().join("shadowmesh-singbox.json");
        let singbox_json = match serde_json::to_string_pretty(&singbox_config) {
            Ok(j) => j,
            Err(e) => {
                return VpnResponse {
                    success: false,
                    message: format!("JSON Error: {}", e),
                    data: None,
                };
            }
        };

        let path_str = config_path.to_str().unwrap_or_default();
        if let Err(e) = self.file_system.write(path_str, singbox_json).await {
            return VpnResponse {
                success: false,
                message: format!("Failed to write sing-box config: {}", e),
                data: None,
            };
        }

        // Mutual Exclusion: Ensure old tunnel is killed before starting new one
        {
            let mut active = self.active_tunnel.lock().await;
            if let Some(old_tunnel) = active.take() {
                old_tunnel.shutdown().await;
            }

            match self
                .command_runner
                .spawn_tunnel("sing-box", &["run", "-c", path_str], "sing-box".into())
                .await
            {
                Ok(tunnel) => {
                    *active = Some(TunnelHandle::new(tunnel, "sing-box".into()));
                }
                Err(e) => {
                    return VpnResponse {
                        success: false,
                        message: format!("Failed to spawn sing-box: {}", e),
                        data: None,
                    };
                }
            }
        }

        self.log("✅ Sing-box (REALITY) started successfully".into()).await;
        let d_v = self.vpn_manager.clone();
        let _ = crate::run_blocking(move || {
            d_v.complete_connection()
        }).await;

        self.config.rcu(|c| {
            let mut new_c = (**c).clone();
            new_c.selected_node_id = Some(node_id.clone());
            new_c.traffic_mode = mode.clone().unwrap_or_else(|| "reality".into());
            new_c.singbox_enabled = true;
            new_c
        });

        self.save_config().await;
        VpnResponse { success: true, message: "Reality Connected".into(), data: None }
    }

    pub async fn process_vpn_config(
        &self,
        config: shadowmesh_core::VPNConfig,
        node_id: String,
        mode: Option<String>,
    ) -> VpnResponse {
        self.log(format!("📝 Applying config for endpoint: {}", config.endpoint)).await;

        let wg_config = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}\nDNS = {}\nMTU = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
            config.private_key.clone().unwrap_or_default(),
            config.address,
            config.dns,
            config.mtu,
            config.public_key,
            config.endpoint
        );

        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("shadowmesh-wg0.conf");
        let path_str = config_path.to_str().unwrap_or_default();
        if let Err(e) = self.file_system.write(path_str, wg_config).await {
            return VpnResponse {
                success: false,
                message: format!("Failed to write config: {}", e),
                data: None,
            };
        }

        // Mutual Exclusion
        {
            let mut active = self.active_tunnel.lock().await;
            if let Some(old_tunnel) = active.take() {
                old_tunnel.shutdown().await;
            }

            let (cmd, args) = match std::env::consts::OS {
                "windows" => ("wireguard.exe", vec!["/installtunnelservice", path_str]),
                "linux" | "macos" => ("wg-quick", vec!["up", path_str]),
                _ => {
                    return VpnResponse {
                        success: false,
                        message: "Unsupported OS".into(),
                        data: None,
                    };
                }
            };

            match self.command_runner.spawn_tunnel(cmd, &args, cmd.into()).await {
                Ok(tunnel) => {
                    *active = Some(TunnelHandle::new(tunnel, cmd.into()));
                }
                Err(e) => {
                    return VpnResponse {
                        success: false,
                        message: format!("WireGuard execution failed: {}", e),
                        data: None,
                    };
                }
            }
        }

        // Apply System DNS in parallel with final connection state updates
        let dns_servers: Vec<String> =
            config.dns.split(',').map(|s| s.trim().to_string()).collect();
        let dns_task = self.enforce_dns(dns_servers);

        let d_v = self.vpn_manager.clone();
        let manager_task = async move {
            let _ = crate::run_blocking(move || {
                d_v.complete_connection()
            }).await;
            Ok::<(), anyhow::Error>(())
        };

        if let Err(e) = tokio::try_join!(dns_task, manager_task) {
            warn!("⚠️ Failed to finalize network config: {}", e);
        }

        self.config.rcu(|c| {
            let mut new_c = (**c).clone();
            new_c.selected_node_id = Some(node_id.clone());
            new_c.traffic_mode = mode.clone().unwrap_or_else(|| "normal".into());
            new_c
        });

        self.save_config().await;

        VpnResponse { success: true, message: "Reality Connected".into(), data: None }
    }

    pub async fn handle_disconnect(&self) -> VpnResponse {
        self.log("🔌 Disconnecting VPN...".into()).await;
        let d_v = self.vpn_manager.clone();
        let _ = crate::run_blocking(move || {
            d_v.disconnect()
        }).await;

        let tunnel_task = async {
            let mut active = self.active_tunnel.lock().await;
            if let Some(tunnel) = active.take() {
                tunnel.shutdown().await;
            }
            Ok::<(), anyhow::Error>(())
        };

        // Reset DNS in parallel with tunnel shutdown
        let dns_task = self.reset_dns();

        if let Err(e) = tokio::try_join!(tunnel_task, dns_task) {
            warn!("⚠️ Disconnect cleanup had issues: {}", e);
        }

        VpnResponse { success: true, message: "Stopped".into(), data: None }
    }
}
