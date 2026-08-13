use crate::daemon::Daemon;
use crate::ipc_codec::IpcCodec;
use crate::types::{IpcError, VpnCommand, VpnResponse};
use bytes::BytesMut;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{Instrument, error, info, info_span, warn};

/// Handles incoming IPC connections with framing and persistent session support.
pub async fn handle_ipc_io<R, W>(
    mut reader: R,
    mut writer: W,
    daemon: Arc<Daemon>,
) -> Result<(), IpcError>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let span = info_span!("ipc_session");
    async move {
        let mut read_buf = BytesMut::with_capacity(IpcCodec::MAX_PAYLOAD_SIZE);
        let mut write_buf = BytesMut::with_capacity(IpcCodec::MAX_PAYLOAD_SIZE);

        loop {
            // 1. Read Frame
            let frame = match read_frame(&mut reader, &mut read_buf).await? {
                Some(f) => f,
                None => break, // Connection closed gracefully
            };

            // 2. Process Command (Zero-copy borrow from frame)
            let response = match serde_json::from_slice::<VpnCommand>(&frame) {
                Ok(cmd) => {
                    // Security: Verify IPC Token
                    if let Ok(expected) = std::env::var("SHADOWMESH_IPC_TOKEN") {
                        if cmd.token != expected {
                            warn!("🚨 Unauthorized IPC attempt detected");
                            crate::metrics::IPC_ERRORS_TOTAL.inc();
                            VpnResponse {
                                success: false,
                                message: "Unauthorized: Invalid Session Token".into(),
                                data: None,
                            }
                        } else {
                            process_command(cmd, Arc::clone(&daemon)).await
                        }
                    } else {
                        process_command(cmd, Arc::clone(&daemon)).await
                    }
                }
                Err(e) => {
                    warn!("Malformed IPC JSON: {}", e);
                    crate::metrics::IPC_ERRORS_TOTAL.inc();
                    VpnResponse {
                        success: false,
                        message: format!("Protocol Error: Malformed JSON: {}", e),
                        data: None,
                    }
                }
            };

            // 3. Encode & Write Response
            write_buf.clear();
            let resp_bytes = serde_json::to_vec(&response)?;
            IpcCodec::encode(&resp_bytes, &mut write_buf)?;
            writer.write_all(&write_buf).await?;
            writer.flush().await?;
        }
        Ok(())
    }
    .instrument(span)
    .await
}

async fn read_frame<R>(reader: &mut R, buf: &mut BytesMut) -> Result<Option<BytesMut>, IpcError>
where
    R: AsyncReadExt + Unpin,
{
    loop {
        if let Some(frame) = IpcCodec::decode(buf)? {
            return Ok(Some(frame));
        }

        match reader.read_buf(buf).await? {
            0 if buf.is_empty() => return Ok(None),
            0 => return Err(IpcError::Protocol("Unexpected EOF while reading frame".into())),
            _ => continue,
        }
    }
}

pub async fn process_command(cmd: VpnCommand<'_>, daemon: Arc<Daemon>) -> VpnResponse {
    let action_name = format!("{:?}", cmd.action);
    let span = info_span!("process_command", action = %action_name);

    use crate::types::{DaemonConfig, QrAuthOp, SecureTokenOp, VpnAction, VpnResponseData};
    use shadowmesh_core::{ConnectionStatus, SecurityEventType};
    use std::sync::atomic::Ordering;

    // Big-Tech Standard: Instrument IPC Performance
    crate::metrics::IPC_COMMANDS_TOTAL.inc();

    async move {
        match cmd.action {
            VpnAction::GetVersion => VpnResponse {
                success: true,
                message: "OK".into(),
                data: Some(VpnResponseData::Version {
                    version: "1.0.0-PRO".into(),
                    os: std::env::consts::OS.into(),
                    arch: std::env::consts::ARCH.into(),
                    features: vec![
                        "wireguard".into(),
                        "fragmentation".into(),
                        "reality".into(),
                        "kill-switch".into(),
                        "ipc-v4-framed".into(),
                    ],
                }),
            },
            VpnAction::Ping => VpnResponse { success: true, message: "pong".into(), data: None },
            VpnAction::Status => {
                let d_v = Arc::clone(&daemon);
                let stats_res = crate::run_blocking(move || {
                    let s = d_v.vpn_manager.get_stats();
                    let p = d_v.vpn_manager.get_protocol_stats();
                    let st = d_v.vpn_manager.get_status();
                    let pref = d_v.vpn_manager.get_traffic_mode_preference();
                    let split = d_v.vpn_manager.get_split_tunnel_config();
                    (s, p, st, pref, split)
                })
                .await;

                if let Ok((stats, p_stats, status, traffic_pref, split_config)) = stats_res {
                    let config = daemon.config.load();
                    let last_err = daemon.last_error.read().await.clone();

                    let now_nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64;

                    let prev_ts = daemon.stats.last_update_ts.swap(now_nanos, Ordering::SeqCst);
                    let prev_sent = daemon.stats.bytes_sent.swap(stats.bytes_sent, Ordering::SeqCst);
                    let prev_recv =
                        daemon.stats.bytes_received.swap(stats.bytes_received, Ordering::SeqCst);

                    let elapsed_secs = (now_nanos.saturating_sub(prev_ts) as f64) / 1_000_000_000.0;

                    let sent_bps = if elapsed_secs > 0.0 {
                        ((stats.bytes_sent.saturating_sub(prev_sent)) as f64 / elapsed_secs) as u64
                    } else {
                        0
                    };
                    let recv_bps = if elapsed_secs > 0.0 {
                        ((stats.bytes_received.saturating_sub(prev_recv)) as f64 / elapsed_secs)
                            as u64
                    } else {
                        0
                    };

                    VpnResponse {
                        success: true,
                        message: "OK".into(),
                        data: Some(VpnResponseData::Status(serde_json::json!({
                            "connected": status == ConnectionStatus::Connected,
                            "status": format!("{:?}", status),
                            "device_id": daemon.device_id,
                            "device_label": config.device_label,
                            "activated": config.auth_token.is_some(),
                            "plan": config.plan_name,
                            "devices_remaining": config.devices_remaining,
                            "remaining_days": config.remaining_days,
                            "traffic_mode": config.traffic_mode,
                            "traffic_preference": format!("{:?}", traffic_pref),
                            "auto_connect": config.auto_connect,
                            "dns_over_https": config.dns_over_https,
                            "split_tunnel": split_config,
                            "bytes_sent": stats.bytes_sent,
                            "bytes_received": stats.bytes_received,
                            "sent_bps": sent_bps,
                            "recv_bps": recv_bps,
                            "quantum_sent": p_stats.quantum_sent,
                            "quantum_received": p_stats.quantum_received,
                            "reality_sent": p_stats.reality_sent,
                            "reality_received": p_stats.reality_received,
                            "last_error": last_err,
                            "last_speed_test": *daemon.last_speed_result.read().await,
                        }))),
                    }
                } else {
                    VpnResponse {
                        success: false,
                        message: "Internal Security Error: Metrics Engine Failure".into(),
                        data: None,
                    }
                }
            }
            VpnAction::GetLogs => {
                let mut logs = Vec::new();
                while let Some(log) = daemon.recent_logs.pop() {
                    logs.push(log);
                }
                VpnResponse { success: true, message: "OK".into(), data: Some(VpnResponseData::Logs(logs)) }
            }
            VpnAction::GetIdentity => match daemon.api_client.get_identity_info().await {
                Ok(info) => VpnResponse {
                    success: true,
                    message: "OK".into(),
                    data: Some(VpnResponseData::Identity(info)),
                },
                Err(e) => VpnResponse { success: false, message: format!("API Error: {}", e), data: None },
            },
            VpnAction::ListNodes => daemon.handle_list_nodes().await,
            VpnAction::Activate { code } => daemon.handle_activate(code.into_owned()).await,
            VpnAction::Connect { node_id, mode } => daemon.handle_connect(node_id.into_owned(), mode.map(|m| m.into_owned())).await,
            VpnAction::Disconnect => daemon.handle_disconnect().await,
            VpnAction::Pause { minutes } => {
                let d_v = daemon.vpn_manager.clone();
                let res = crate::run_blocking(move || {
                    d_v.pause(minutes)
                }).await;

                match res {
                    Ok(Ok(_)) => {
                        daemon.log(format!("⏸️ VPN Paused for {} minutes", minutes)).await;
                        VpnResponse { success: true, message: format!("Paused for {}m", minutes), data: None }
                    }
                    Ok(Err(e)) => VpnResponse { success: false, message: format!("Pause Failed: {}", e), data: None },
                    Err(e) => VpnResponse { success: false, message: format!("Runtime Error: {}", e), data: None },
                }
            },
            VpnAction::Resume => {
                let d_v = daemon.vpn_manager.clone();
                let _ = crate::run_blocking(move || d_v.resume()).await;
                daemon.log("▶️ VPN Resumed".into()).await;
                VpnResponse { success: true, message: "Resumed".into(), data: None }
            }
            VpnAction::SetKillSwitch { enabled } => {
                let d_v = daemon.vpn_manager.clone();
                let _ = crate::run_blocking(move || d_v.set_kill_switch_enabled(enabled)).await;

                daemon.config.rcu(|c| {
                    let mut new_c = (**c).clone();
                    new_c.kill_switch = enabled;
                    new_c
                });

                use shadowmesh_core::SecurityEnforcer;
                let res = if enabled {
                    daemon.apply_kill_switch().await
                } else {
                    daemon.remove_kill_switch().await
                };

                let success = res.is_ok();
                if let Err(ref e) = res {
                    error!("Failed to toggle kill switch: {}", e);
                }

                daemon.save_config().await;
                VpnResponse { success, message: format!("Kill Switch {}", if enabled { "Active" } else { "Inactive" }), data: None }
            }
            VpnAction::SetAutoConnect { enabled } => {
                daemon.config.rcu(|c| {
                    let mut new_c = (**c).clone();
                    new_c.auto_connect = enabled;
                    new_c
                });
                daemon.save_config().await;
                VpnResponse { success: true, message: format!("Auto-connect {}", if enabled { "Enabled" } else { "Disabled" }), data: None }
            }
            VpnAction::SetDnsOverHttps { enabled } => {
                daemon.config.rcu(|c| {
                    let mut new_c = (**c).clone();
                    new_c.dns_over_https = enabled;
                    new_c
                });
                daemon.save_config().await;
                VpnResponse { success: true, message: format!("DoH {}", if enabled { "Enabled" } else { "Disabled" }), data: None }
            }
            VpnAction::SetTrafficPreference { preference } => {
                let pref = match preference.as_ref() {
                    "speed" => shadowmesh_core::TrafficModePreference::Speed,
                    "stealth" => shadowmesh_core::TrafficModePreference::Stealth,
                    _ => shadowmesh_core::TrafficModePreference::Auto,
                };
                let d_v = daemon.vpn_manager.clone();
                let _ = crate::run_blocking(move || d_v.set_traffic_mode_preference(pref)).await;
                VpnResponse { success: true, message: "Traffic Preference Updated".into(), data: None }
            }
            VpnAction::SetSplitTunnel { enabled, mode, apps } => {
                let split_mode = match mode.as_ref() {
                    "include" => shadowmesh_core::SplitTunnelMode::Include,
                    _ => shadowmesh_core::SplitTunnelMode::Exclude,
                };
                let apps_owned = apps.into_iter().map(|a| a.into_owned()).collect();
                let d_v = daemon.vpn_manager.clone();
                let _ = crate::run_blocking(move || {
                    d_v.set_split_tunnel_config(shadowmesh_core::SplitTunnelConfig { enabled, mode: split_mode, app_list: apps_owned })
                }).await;
                VpnResponse { success: true, message: "Split Tunnel Updated".into(), data: None }
            }
            VpnAction::SetDeviceLabel { label } => {
                daemon.config.rcu(|c| {
                    let mut new_c = (**c).clone();
                    new_c.device_label = Some(label.clone().into_owned());
                    new_c
                });
                daemon.save_config().await;
                VpnResponse { success: true, message: "Device Label Updated".into(), data: None }
            }
            VpnAction::SecureToken { op } => match op {
                SecureTokenOp::Get { key } => {
                    let val = daemon.secure_storage.get_password("org.shadowmesh.tokens", &key).ok();
                    VpnResponse { success: true, message: "OK".into(), data: val.map(VpnResponseData::Token) }
                }
                SecureTokenOp::Set { key, value } => match daemon.secure_storage.set_password("org.shadowmesh.tokens", &key, &value) {
                    Ok(_) => VpnResponse { success: true, message: "Stored".into(), data: None },
                    Err(e) => VpnResponse { success: false, message: format!("Store Error: {}", e), data: None },
                },
                SecureTokenOp::Remove { key } => {
                    let _ = daemon.secure_storage.delete_password("org.shadowmesh.tokens", &key);
                    VpnResponse { success: true, message: "Removed".into(), data: None }
                }
            },
            VpnAction::QrAuth { op } => match op {
                QrAuthOp::Generate => {
                    let device_id = daemon.device_id.clone();
                    match daemon.api_client.qr_generate(device_id, format!("{} Desktop", std::env::consts::OS), std::env::consts::OS.to_string(), "1.0.0".into(), std::env::consts::ARCH.to_string()).await {
                        Ok(token) => VpnResponse { success: true, message: "OK".into(), data: Some(VpnResponseData::QrToken { token }) },
                        Err(e) => VpnResponse { success: false, message: format!("API Error: {}", e), data: None },
                    }
                }
                QrAuthOp::CheckStatus { token } => match daemon.api_client.qr_status(token.into_owned()).await {
                    Ok(status_json) => {
                        let status: serde_json::Value = serde_json::from_str(&status_json).unwrap_or(serde_json::json!({ "status": "error" }));
                        if status["status"] == "authorized"
                            && let Some(token_str) = status["token"].as_str()
                        {
                            daemon.api_client.set_auth_token(Some(token_str.to_string()));
                            daemon.config.rcu(|c| {
                                let mut new_c = (**c).clone();
                                new_c.auth_token = Some(token_str.to_string());
                                if let Some(code) = status["code"].as_str() {
                                    new_c.activation_code = Some(code.to_string());
                                }
                                if let Some(plan) = status["plan"].as_str() {
                                    new_c.plan_name = plan.to_string();
                                }
                                if let Some(dr) = status["devices_remaining"].as_i64() {
                                    new_c.devices_remaining = dr as i32;
                                }
                                if let Some(rd) = status["remaining_days"].as_i64() {
                                    new_c.remaining_days = rd;
                                }
                                new_c
                            });
                            daemon.save_config().await;

                            if let Some(act_code) = status["code"].as_str() {
                                daemon
                                    .vpn_manager
                                    .activate(
                                        act_code.to_string(),
                                        Some(token_str.to_string()),
                                        status["plan"].as_str().map(|s| s.to_string()),
                                        status["devices_remaining"]
                                            .as_i64()
                                            .map(|v| v as i32)
                                            .unwrap_or(0),
                                        status["remaining_days"].as_i64().unwrap_or(0),
                                    )
                                    .ok();
                            }
                        }
                        VpnResponse { success: true, message: "OK".into(), data: Some(VpnResponseData::Generic(status)) }
                    }
                    Err(e) => VpnResponse { success: false, message: format!("API Error: {}", e), data: None },
                }
            },
            VpnAction::Obfuscation { action, config } => match action.as_ref() {
                "start" => {
                    let config_json = config.map(|c| c.into_owned()).unwrap_or_default();
                    daemon.log(format!("🕵️ Starting Obfuscation (Shadowsocks/UDP2RAW)... Config: {}", config_json)).await;
                    daemon.config.rcu(|c| {
                        let mut new_c = (**c).clone();
                        new_c.obfuscation_enabled = true;
                        new_c
                    });
                    daemon.save_config().await;
                    VpnResponse { success: true, message: "Obfuscation started".into(), data: None }
                }
                "stop" => {
                    daemon.log("🛑 Stopping Obfuscation...".into()).await;
                    daemon.config.rcu(|c| {
                        let mut new_c = (**c).clone();
                        new_c.obfuscation_enabled = false;
                        new_c
                    });
                    daemon.save_config().await;
                    VpnResponse { success: true, message: "Obfuscation stopped".into(), data: None }
                }
                _ => {
                    let enabled = daemon.config.load().obfuscation_enabled;
                    VpnResponse { success: true, message: "OK".into(), data: Some(VpnResponseData::Generic(serde_json::json!({ "running": enabled, "method": "shadowsocks" }))) }
                }
            },
            VpnAction::SingBox { action, config } => match action.as_ref() {
                "start" => {
                    let config_json = config.map(|c| c.into_owned()).unwrap_or_default();
                    daemon.log(format!("📦 Starting Sing-box (VLESS+REALITY)... Config: {}", config_json)).await;
                    daemon.config.rcu(|c| {
                        let mut new_c = (**c).clone();
                        new_c.singbox_enabled = true;
                        new_c
                    });
                    daemon.save_config().await;
                    VpnResponse { success: true, message: "Sing-box started".into(), data: None }
                }
                "stop" => {
                    daemon.log("🛑 Stopping Sing-box...".into()).await;
                    daemon.config.rcu(|c| {
                        let mut new_c = (**c).clone();
                        new_c.singbox_enabled = false;
                        new_c
                    });
                    daemon.save_config().await;
                    VpnResponse { success: true, message: "Sing-box stopped".into(), data: None }
                }
                _ => {
                    let enabled = daemon.config.load().singbox_enabled;
                    VpnResponse { success: true, message: "OK".into(), data: Some(VpnResponseData::Generic(serde_json::json!({ "running": enabled, "protocol": "vless-reality" }))) }
                }
            },
            VpnAction::SmartFallback { enabled } => {
                daemon.log(format!("🔄 Smart Fallback {}", if enabled { "Enabled" } else { "Disabled" })).await;
                daemon.config.rcu(|c| {
                    let mut new_c = (**c).clone();
                    new_c.smart_fallback_enabled = enabled;
                    new_c
                });
                daemon.save_config().await;
                VpnResponse { success: true, message: format!("Smart Fallback {}", if enabled { "enabled" } else { "disabled" }), data: None }
            }
            VpnAction::DuressPin { action, hash } => match action.as_ref() {
                "set" => {
                    if let Some(h) = hash {
                        let h_owned = h.into_owned();
                        daemon.config.rcu(|c| {
                            let mut new_c = (**c).clone();
                            new_c.duress_pin_hash = Some(h_owned.clone());
                            new_c
                        });
                        daemon.save_config().await;
                        VpnResponse { success: true, message: "Duress PIN set".into(), data: None }
                    } else {
                        VpnResponse { success: false, message: "Missing hash".into(), data: None }
                    }
                }
                _ => {
                    let h = daemon.config.load().duress_pin_hash.clone();
                    VpnResponse { success: true, message: "OK".into(), data: h.map(|v| VpnResponseData::Generic(serde_json::json!(v))) }
                }
            },
            VpnAction::PanicWipe => {
                daemon.log("🚨 PANIC PROTOCOL INITIATED 🚨".into()).await;
                let logger = Arc::clone(&daemon.security_logger);
                let _ = crate::run_blocking(move || {
                    logger.log_event(SecurityEventType::PanicInitiated, "User triggered forensic wipe".into(), true, None);
                }).await;
                daemon.vpn_manager.disconnect();
                let _ = daemon.api_client.report_compromised(daemon.device_id.clone(), "User triggered forensic wipe".into()).await;
                {
                    daemon.config.rcu(|_| {
                        let mut new_config = DaemonConfig::default();
                        use zeroize::Zeroize;
                        new_config.zeroize();
                        new_config
                    });
                }
                let _ = daemon.file_system.remove_file(&daemon.config_path).await;
                #[cfg(unix)]
                let _ = daemon.file_system.remove_file(crate::types::SOCKET_PATH).await;
                daemon.log("🧹 Forensic Wipe Complete. Terminating...".into()).await;
                std::process::exit(0);
            }
            VpnAction::Camouflage { enabled } => {
                daemon.log(format!("🎭 Camouflage Mode {}", if enabled { "Active" } else { "Inactive" })).await;
                VpnResponse { success: true, message: format!("Camouflage {}", if enabled { "Active" } else { "Inactive" }), data: Some(VpnResponseData::Generic(serde_json::json!(enabled))) }
            }
            VpnAction::Shutdown => {
                daemon.log("🛑 Shutdown command received via IPC".into()).await;
                daemon.vpn_manager.disconnect();
                // We use a small delay to allow the response to reach the client before exiting
                tokio::spawn(async {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    info!("👋 ShadowMesh Daemon exiting gracefully...");
                    std::process::exit(0);
                });
                VpnResponse { success: true, message: "Shutting down".into(), data: None }
            }
        }
    }
    .instrument(span)
    .await
}
