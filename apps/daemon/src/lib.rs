pub mod api;
pub mod daemon;
pub mod ipc;
pub mod ipc_codec;
pub mod metrics;
pub mod network_config;
pub mod orchestration;
pub mod types;

#[cfg(test)]
mod api_mock_test;

use futures::FutureExt;
use shadowmesh_core::SecurityEnforcer;
use std::sync::Arc;
use tracing::{error, info};

pub use crate::api::{CoreApiWrapper, ShadowApi};
pub use crate::daemon::Daemon;
pub use crate::ipc::{handle_ipc_io, process_command};
pub use crate::orchestration::{
    FileSystem, RealCommandRunner, RealFileSystem, RealSecureStorage, SecureStorage,
    SystemCommandRunner, VpnTunnel,
};
pub use crate::types::{
    CONFIG_DIR, DaemonConfig, SOCKET_PATH, VpnAction, VpnCommand, VpnResponse, VpnResponseData,
};

pub async fn run_daemon_service(daemon: Arc<Daemon>) -> anyhow::Result<()> {
    daemon.load_config().await;

    // Big-Tech Standard: Observability First
    metrics::register_metrics();
    tokio::spawn(async {
        if let Err(e) = metrics::start_metrics_server(9090).await {
            tracing::error!("❌ Metrics server failed: {}", e);
        }
    });

    // Apply persistent settings on startup
    {
        let config = daemon.config.load();
        if let Some(code) = &config.activation_code {
            let d_v = daemon.vpn_manager.clone();
            let code_c = code.clone();
            let auth_t = config.auth_token.clone();
            let plan_n = Some(config.plan_name.clone());
            let dev_r = config.devices_remaining;
            let rem_d = config.remaining_days;

            let _ = crate::run_blocking(move || {
                d_v.activate(code_c, auth_t, plan_n, dev_r, rem_d)
            })
            .await;
        }

        if config.kill_switch {
            let d = Arc::clone(&daemon);
            tokio::spawn(async move {
                if let Err(e) = d.apply_kill_switch().await {
                    error!("Failed to apply kill switch on startup: {}", e);
                }
            });
        }
    }

    // Security: Check for IPC token from parent process
    let expected_token = std::env::var("SHADOWMESH_IPC_TOKEN").ok();
    if expected_token.is_none() && !cfg!(debug_assertions) {
        error!(
            "❌ Security Error: SHADOWMESH_IPC_TOKEN environment variable not set. IPC is insecure. Aborting."
        );
        std::process::exit(1);
    }

    let d_sig = Arc::clone(&daemon);
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!("Failed to listen for shutdown signal: {}", e);
        }
        d_sig.log("🛑 Shutdown signal received".into()).await;
        #[cfg(unix)]
        let _ = d_sig.file_system.remove_file(SOCKET_PATH).await;
        std::process::exit(0);
    });

    let d_hb = Arc::clone(&daemon);
    tokio::spawn(async move {
        loop {
            let res = std::panic::AssertUnwindSafe(async {
                tokio::time::sleep(tokio::time::Duration::from_secs(45)).await;
                let auth_token = d_hb.config.load().auth_token.clone();
                let d_hb_core = Arc::clone(&d_hb);
                if auth_token.is_some() {
                    let stats_res = crate::run_blocking(move || {
                        d_hb_core.vpn_manager.get_protocol_stats()
                    })
                    .await;

                    if let Ok(stats) = stats_res {
                        let hb_res = d_hb
                            .api_client
                            .heartbeat(shadowmesh_core::HeartbeatRequest {
                                device_id: d_hb.device_id.clone(),
                                background_mode: false,
                                deep_fingerprint: None,
                                bytes_sent_quantum: Some(stats.quantum_sent),
                                bytes_received_quantum: Some(stats.quantum_received),
                                bytes_sent_reality: Some(stats.reality_sent),
                                bytes_received_reality: Some(stats.reality_received),
                            })
                            .await;

                        match hb_res {
                            Ok(resp) => {
                                *d_hb.last_error.write().await = None;
                                if !resp.session_active {
                                    d_hb.log("⚠️ Session no longer active according to server"
                                        .into())
                                        .await;
                                }
                            }
                            Err(shadowmesh_core::ShadowMeshError::TooManyRequests(msg)) => {
                                d_hb.log(format!("🚫 Device Limit Reached: {}", msg)).await;
                                *d_hb.last_error.write().await =
                                    Some(format!("Device Limit Reached: {}", msg));

                                let d_hb_disc = Arc::clone(&d_hb);
                                let status_res = crate::run_blocking(move || {
                                    d_hb_disc.vpn_manager.get_status()
                                }).await;

                                if let Ok(shadowmesh_core::ConnectionStatus::Connected) = status_res {
                                    d_hb.log("🔌 Proactively disconnecting due to device limit"
                                        .into())
                                        .await;
                                    let d_hb_final = Arc::clone(&d_hb);
                                    let _ = crate::run_blocking(move || {
                                        d_hb_final.vpn_manager.disconnect()
                                    }).await;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            })
            .catch_unwind()
            .await;

            if res.is_err() {
                error!("🚨 Daemon Heartbeat Panic detected. Self-healing...");
            }
        }
    });

    start_background_tasks(daemon.clone());

    #[cfg(unix)]
    {
        use socket2::{Domain, Socket, Type};
        use std::os::unix::net::UnixListener as StdUnixListener;
        use tokio::net::UnixListener;

        if std::path::Path::new(SOCKET_PATH).exists() {
            let _ = daemon.file_system.remove_file(SOCKET_PATH).await;
        }

        // Use socket2 for fine-tuned Unix socket creation
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)
            .map_err(|e| anyhow::anyhow!("Failed to create socket: {}", e))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| anyhow::anyhow!("Failed to set nonblocking: {}", e))?;

        // Optimize IPC buffer sizes for desktop responsiveness
        let _ = socket.set_recv_buffer_size(65536);
        let _ = socket.set_send_buffer_size(65536);

        let addr = socket2::SockAddr::unix(SOCKET_PATH)
            .map_err(|e| anyhow::anyhow!("Failed to create sockaddr: {}", e))?;
        socket.bind(&addr).map_err(|e| anyhow::anyhow!("Failed to bind socket: {}", e))?;
        socket.listen(128).map_err(|e| anyhow::anyhow!("Failed to listen on socket: {}", e))?;

        let listener: StdUnixListener = socket.into();
        let listener = UnixListener::from_std(listener)
            .map_err(|e| anyhow::anyhow!("Failed to convert listener: {}", e))?;

        let _ = daemon.file_system.set_permissions_mode(SOCKET_PATH, 0o666);

        info!("🛡️ ShadowMesh Daemon [PRO] active on {} (Optimized IPC)", SOCKET_PATH);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let d = Arc::clone(&daemon);
                    tokio::spawn(async move {
                        let (reader, writer) = tokio::io::split(stream);
                        if let Err(e) = handle_ipc_io(reader, writer, d).await {
                            error!("IPC Error: {}", e);
                        }
                    });
                }
                Err(e) => error!("Accept Error: {}", e),
            }
        }
    }

    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;
        info!("🛡️ ShadowMesh Daemon [PRO] active on {}", SOCKET_PATH);
        loop {
            let server = ServerOptions::new().first_pipe_instance(true).create(SOCKET_PATH)?;

            server.connect().await?;
            let d = Arc::clone(&daemon);
            tokio::spawn(async move {
                let (reader, writer) = tokio::io::split(server);
                if let Err(e) = handle_ipc_io(reader, writer, d).await {
                    error!("IPC Error: {}", e);
                }
            });
        }
    }
}

fn start_background_tasks(daemon: Arc<Daemon>) {
    let d_check = Arc::clone(&daemon);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            d_check.check_integrity().await;
        }
    });

    let d_health = Arc::clone(&daemon);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            let d_health_check = Arc::clone(&d_health);
            let status_res = crate::run_blocking(move || {
                d_health_check.vpn_manager.get_status()
            }).await;

            if let Ok(status) = status_res {
                if status == shadowmesh_core::ConnectionStatus::Connected
                    || status == shadowmesh_core::ConnectionStatus::Degraded
                {
                    let api = Arc::clone(&d_health.api_client);
                    tokio::spawn(async move {
                        if let Ok(_health) = api.check_health().await {
                            // Restored logic...
                        }
                    });
                }
            }
        }
    });

    let d_auto = Arc::clone(&daemon);
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let (node_id, mode, auto) = {
            let config = d_auto.config.load();
            (
                config.selected_node_id.clone(),
                Some(config.traffic_mode.clone()),
                config.auto_connect,
            )
        };
        if let Some(id) = node_id
            && auto
        {
            d_auto.log("🔄 Auto-connecting to last used node...".into()).await;
            let _ = d_auto.handle_connect(id, mode).await;
        }
    });

    let d_pause = Arc::clone(&daemon);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            let d_p = Arc::clone(&d_pause);
            let expired_res = crate::run_blocking(move || {
                d_p.vpn_manager.check_pause_expiry()
            }).await;

            if let Ok(true) = expired_res {
                d_pause.log("⏰ Pause duration expired. Connection resumed.".into()).await;
            }
        }
    });

    let d_watchdog = Arc::clone(&daemon);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            let mut active = d_watchdog.active_tunnel.lock().await;
            if let Some(ref mut tunnel) = *active {
                match tunnel.inner.try_wait() {
                    Ok(Some(status)) => {
                        error!(
                            "🚨 Tunnel process {} exited unexpectedly with status: {}",
                            tunnel.name, status
                        );
                        drop(active); // Release lock before calling log which might lock something or wait
                        let d = Arc::clone(&d_watchdog);
                        tokio::spawn(async move {
                            let d_v = Arc::clone(&d);
                            let _ = crate::run_blocking(move || {
                                d_v.vpn_manager.set_status(shadowmesh_core::ConnectionStatus::Disconnected)
                            }).await;
                            d.log("🚨 Tunnel process crashed".to_string()).await;
                        });
                        // Re-acquire lock to clear the tunnel handle
                        let mut active = d_watchdog.active_tunnel.lock().await;
                        *active = None;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error!("Error checking tunnel process status: {}", e);
                    }
                }
            }
        }
    });

    // Big-Tech Standard: Self-Healing & Metrics Synchronization
    let d_healing = Arc::clone(&daemon);
    tokio::spawn(async move {
        let mut last_network_id = String::new();
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            // 1. Sync stats to Prometheus
            let d_stats = Arc::clone(&d_healing);
            let stats_res = crate::run_blocking(move || {
                d_stats.vpn_manager.get_stats()
            }).await;

            if let Ok(stats) = stats_res {
                crate::metrics::VPN_BYTES_SENT
                    .inc_by(stats.bytes_sent.saturating_sub(crate::metrics::VPN_BYTES_SENT.get()));
                crate::metrics::VPN_BYTES_RECV
                    .inc_by(stats.bytes_received.saturating_sub(crate::metrics::VPN_BYTES_RECV.get()));

                let d_status = Arc::clone(&d_healing);
                let status_res = crate::run_blocking(move || {
                    d_status.vpn_manager.get_status()
                }).await;

                crate::metrics::VPN_TUNNEL_UP.set(
                    if let Ok(shadowmesh_core::ConnectionStatus::Connected) = status_res {
                        1
                    } else {
                        0
                    },
                );
            }

            // 2. Network Change Detection & Self-Healing
            let core_client = d_healing.api_client.clone().get_core_client();
            let detector_res = crate::run_blocking(move || {
                let detector = shadowmesh_core::NetworkDetector::new(core_client, None);
                detector.detect(false)
            })
            .await;

            if let Ok(Ok(report)) = detector_res {
                let current_net_id = format!("{:?}-{}", report.network_type, report.is_connected);

                if !last_network_id.is_empty() && current_net_id != last_network_id {
                    d_healing
                        .log(format!(
                            "🌐 Network Change Detected: {} -> {}. Triggering self-healing...",
                            last_network_id, current_net_id
                        ))
                        .await;

                    let d_healing_status = Arc::clone(&d_healing);
                    let status_res = crate::run_blocking(move || {
                        d_healing_status.vpn_manager.get_status()
                    }).await;

                    if let Ok(shadowmesh_core::ConnectionStatus::Connected) = status_res {
                        let node_id = d_healing.config.load().selected_node_id.clone();
                        let mode = Some(d_healing.config.load().traffic_mode.clone());

                        if let Some(id) = node_id {
                            d_healing
                                .log("🔄 Re-establishing tunnel on new network...".into())
                                .await;
                            let _ = d_healing.handle_connect(id, mode).await;
                        }
                    }
                }
                last_network_id = current_net_id;
            }
        }
    });
}

pub async fn run_blocking<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    if let Err(e) =
        std::thread::Builder::new().name("shadowmesh-blocking-io".to_string()).spawn(move || {
            let res = f();
            let _ = tx.send(res);
        })
    {
        return Err(format!("failed to spawn blocking thread: {}", e));
    }
    rx.await.map_err(|e| format!("blocking thread sender dropped: {}", e))
}

#[cfg(any(test, feature = "test-utils", feature = "benchmarking"))]
pub fn create_test_daemon(
    api_client: Arc<dyn ShadowApi>,
    command_runner: Arc<dyn SystemCommandRunner>,
) -> Arc<Daemon> {
    use crate::types::DaemonConfig;
    use arc_swap::ArcSwap;
    use crossbeam_queue::ArrayQueue;
    use shadowmesh_core::{
        AntiTamperChecker, AntiTamperConfig, KillSwitchManager, SecurityEventLogger, UserSettings,
        VPNManager,
    };
    use tokio::sync::{Mutex, RwLock};

    struct MockFS;
    #[async_trait::async_trait]
    impl FileSystem for MockFS {
        async fn read_to_string(&self, _: &str) -> anyhow::Result<String> {
            Ok("{}".into())
        }
        async fn read(&self, _: &str) -> anyhow::Result<Vec<u8>> {
            Ok(vec![])
        }
        async fn write(&self, _: &str, _: String) -> anyhow::Result<()> {
            Ok(())
        }
        async fn create_dir_all(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn remove_file(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        fn metadata_permissions_mode(&self, _: &str) -> anyhow::Result<u32> {
            Ok(0o666)
        }
        fn set_permissions_mode(&self, _: &str, _: u32) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct MockStorage;
    impl SecureStorage for MockStorage {
        fn get_password(&self, _: &str, _: &str) -> anyhow::Result<String> {
            Ok("test".into())
        }
        fn set_password(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        fn delete_password(&self, _: &str, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct MockDns;
    #[async_trait::async_trait]
    impl crate::network_config::DnsManager for MockDns {
        async fn set_dns(&self, _: &str, _: Vec<String>) -> anyhow::Result<()> {
            Ok(())
        }
        async fn reset_dns(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    let device_id = "test-device-id".to_string();
    api_client.set_device_id(device_id.clone());

    let dns_manager: Arc<dyn crate::network_config::DnsManager> = Arc::new(MockDns);
    let (fs, storage) = (Arc::new(MockFS), Arc::new(MockStorage));

    let initial_logs = ArrayQueue::new(200);

    Arc::new(Daemon {
        vpn_manager: Arc::new(VPNManager::new(UserSettings::default())),
        api_client,
        file_system: fs,
        secure_storage: storage,
        security_logger: SecurityEventLogger::new(
            device_id.clone(),
            "1.0.0-TEST".to_string(),
            "/tmp/test_logs".into(),
        )
        .unwrap()
        .into(),
        anti_tamper: Arc::new(AntiTamperChecker::new(AntiTamperConfig {
            expected_hashes: std::collections::HashMap::new(),
        })),
        kill_switch_manager: Arc::new(KillSwitchManager::new()),
        command_runner,
        dns_manager,
        device_id,
        active_tunnel: Mutex::new(None),
        operational_state: RwLock::new(crate::daemon::OperationalState::Active),
        recent_logs: initial_logs,
        config: ArcSwap::from_pointee(DaemonConfig::default()),
        config_path: "/tmp/test_config.json".into(),
        last_error: RwLock::new(None),
        last_speed_result: RwLock::new(None),
        stats: crate::daemon::AtomicStats {
            bytes_sent: std::sync::atomic::AtomicU64::new(0),
            bytes_received: std::sync::atomic::AtomicU64::new(0),
            last_update_ts: std::sync::atomic::AtomicU64::new(0),
        },
        has_config_dir_been_checked: std::sync::atomic::AtomicBool::new(true),
    })
}
