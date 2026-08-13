use crate::daemon::{QrAuthOp, SecureTokenOp, VpnAction, send_daemon_command};
use crate::state::{CoreState, SessionToken};
use serde::Serialize;
use std::borrow::Cow;
use tauri::{AppHandle, Manager, Runtime};

#[tauri::command]
pub async fn run_helper<R: Runtime>(
    app: AppHandle<R>,
    args: Vec<String>,
) -> Result<String, String> {
    if args.is_empty() {
        return Err("No arguments provided".to_string());
    }

    let action_str = args[0].as_str();
    let token = app.state::<SessionToken>().0.clone();

    let action = match action_str {
        "version" => VpnAction::GetVersion,
        "ping" => VpnAction::Ping,
        "status" => VpnAction::Status,
        "get-logs" => VpnAction::GetLogs,
        "get-identity" => VpnAction::GetIdentity,
        "list-nodes" => VpnAction::ListNodes,
        "disconnect" => VpnAction::Disconnect,
        "panic-wipe" => VpnAction::PanicWipe,
        "resume" => VpnAction::Resume,
        "activate" => {
            VpnAction::Activate { code: Cow::Owned(args.get(1).cloned().unwrap_or_default()) }
        }
        "connect" => VpnAction::Connect {
            node_id: Cow::Owned(args.get(1).cloned().unwrap_or_default()),
            mode: args.get(2).map(|m| Cow::Owned(m.clone())),
        },
        "set-split-tunnel" => VpnAction::SetSplitTunnel {
            enabled: args.get(1).map(|s| s == "enable").unwrap_or(false),
            mode: Cow::Owned(args.get(2).cloned().unwrap_or_else(|| "exclude".into())),
            apps: args
                .get(3)
                .map(|s| s.split(',').map(|a| Cow::Owned(a.to_string())).collect())
                .unwrap_or_default(),
        },
        "set-secure-token" => VpnAction::SecureToken {
            op: SecureTokenOp::Set {
                key: Cow::Owned(args.get(1).cloned().unwrap_or_default()),
                value: Cow::Owned(args.get(2).cloned().unwrap_or_default()),
            },
        },
        "get-secure-token" => VpnAction::SecureToken {
            op: SecureTokenOp::Get { key: Cow::Owned(args.get(1).cloned().unwrap_or_default()) },
        },
        "remove-secure-token" => VpnAction::SecureToken {
            op: SecureTokenOp::Remove { key: Cow::Owned(args.get(1).cloned().unwrap_or_default()) },
        },
        "qr-generate" => VpnAction::QrAuth { op: QrAuthOp::Generate },
        "qr-status" => VpnAction::QrAuth {
            op: QrAuthOp::CheckStatus {
                token: Cow::Owned(args.get(1).cloned().unwrap_or_default()),
            },
        },
        "camouflage" => {
            VpnAction::Camouflage { enabled: args.get(1).map(|s| s == "enable").unwrap_or(false) }
        }
        "kill-switch" => VpnAction::SetKillSwitch {
            enabled: args.get(1).map(|s| s == "enable").unwrap_or(false),
        },
        _ => return Err(format!("Unsupported action: {}", action_str)),
    };

    send_daemon_command(action, token).await
}

#[tauri::command]
pub async fn get_machine_id() -> Result<String, String> {
    Ok(shadowmesh_core::get_persistent_device_id())
}

#[tauri::command]
pub async fn ping_server(host: String) -> Result<u64, String> {
    let start = std::time::Instant::now();
    let addr = format!("{}:443", host);

    match std::net::TcpStream::connect_timeout(
        &addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?,
        std::time::Duration::from_secs(2),
    ) {
        Ok(_) => Ok(start.elapsed().as_millis() as u64),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
pub fn generate_keys() -> Result<Vec<String>, String> {
    shadowmesh_core::generate_wireguard_keys().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn solve_pow_challenge(challenge: String, difficulty: u32) -> Result<String, String> {
    let pow_challenge = shadowmesh_core::PoWChallenge { challenge, difficulty };
    shadowmesh_core::solve_pow(pow_challenge).map(|res| res.solution).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_best_node(nodes: Vec<shadowmesh_core::VPNNode>) -> Option<shadowmesh_core::VPNNode> {
    shadowmesh_core::shadow_route_best_node(nodes)
}

#[tauri::command]
pub fn get_preferred_mode(region: String) -> String {
    shadowmesh_core::preferred_traffic_mode_for_region(region)
}

#[tauri::command]
pub fn get_traffic_stats(state: tauri::State<'_, CoreState>) -> serde_json::Value {
    serde_json::json!({
        "totalBytes": state.analytics.get_total_bytes(),
        "monthlyBytes": state.analytics.get_bytes_this_month()
    })
}

#[tauri::command]
pub async fn get_security_events(
    state: tauri::State<'_, CoreState>,
) -> Result<Vec<serde_json::Value>, String> {
    let events = state.logger.get_events();
    Ok(events.iter().map(|e| serde_json::json!(e)).collect())
}

#[tauri::command]
pub async fn get_network_report(
    state: tauri::State<'_, CoreState>,
) -> Result<shadowmesh_core::NetworkReport, String> {
    let detector = shadowmesh_core::create_network_detector(state.api_client.clone(), None);
    detector.detect(false).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn run_full_speed_test(
    state: tauri::State<'_, CoreState>,
) -> Result<shadowmesh_core::SpeedTestResult, String> {
    let speed_test = shadowmesh_core::create_speed_test(state.api_client.clone());
    speed_test.run_full_test().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn encrypt_pairing_data(plaintext: Vec<u8>, pin: String) -> Vec<u8> {
    shadowmesh_core::encrypt_qr_pairing_payload(plaintext, pin)
}

#[tauri::command]
pub fn decrypt_pairing_data(ciphertext: Vec<u8>, pin: String) -> Vec<u8> {
    shadowmesh_core::decrypt_qr_pairing_payload(ciphertext, pin)
}

#[tauri::command]
pub async fn get_identity_info<R: Runtime>(
    app: AppHandle<R>,
    _state: tauri::State<'_, CoreState>,
) -> Result<serde_json::Value, String> {
    let token = app.state::<SessionToken>().0.clone();
    let res_str = send_daemon_command(VpnAction::GetIdentity, token).await?;
    let val: serde_json::Value = serde_json::from_str(&res_str).map_err(|e| e.to_string())?;
    Ok(val)
}

#[tauri::command]
pub async fn logout<R: Runtime>(
    app: AppHandle<R>,
    _state: tauri::State<'_, CoreState>,
) -> Result<(), String> {
    let token = app.state::<SessionToken>().0.clone();
    let _ = send_daemon_command(VpnAction::Disconnect, token.clone()).await;
    let _ = send_daemon_command(VpnAction::PanicWipe, token).await;
    Ok(())
}

#[tauri::command]
pub async fn verify_core_integrity(_state: tauri::State<'_, CoreState>) -> Result<bool, String> {
    let mut expected_hashes = std::collections::HashMap::new();
    expected_hashes.insert(
        "desktop-binary".to_string(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
    );

    let checker = shadowmesh_core::AntiTamperChecker::new(shadowmesh_core::AntiTamperConfig {
        expected_hashes,
    });

    if let Ok(exe_path) = std::env::current_exe() {
        if let Ok(data) = std::fs::read(&exe_path) {
            return checker
                .verify_component("desktop-binary".into(), data)
                .map_err(|e| e.to_string());
        }
    }
    Ok(true)
}

#[tauri::command]
pub fn get_quantum_params() -> serde_json::Value {
    serde_json::json!({
        "mtu": shadowmesh_core::get_quantum_mtu(),
        "tcp_mss": shadowmesh_core::get_quantum_tcp_mss()
    })
}

#[derive(Serialize)]
pub struct CommandResult {
    pub success: bool,
    pub error: Option<String>,
}

#[tauri::command]
pub fn close_app(window: tauri::Window) {
    let _ = window.close();
}

#[tauri::command]
pub fn minimize_app(window: tauri::Window) {
    let _ = window.minimize();
}

#[tauri::command]
pub async fn set_split_tunnel<R: Runtime>(
    app: AppHandle<R>,
    enabled: bool,
    mode: String,
    apps: Vec<String>,
) -> Result<CommandResult, String> {
    let token = app.state::<SessionToken>().0.clone();
    let action = VpnAction::SetSplitTunnel {
        enabled,
        mode: Cow::Owned(mode),
        apps: apps.into_iter().map(Cow::Owned).collect(),
    };

    match send_daemon_command(action, token).await {
        Ok(_) => Ok(CommandResult { success: true, error: None }),
        Err(e) => Ok(CommandResult { success: false, error: Some(e) }),
    }
}

#[tauri::command]
pub async fn set_autostart<R: Runtime>(_app: AppHandle<R>, _enabled: bool) -> Result<(), String> {
    Ok(())
}

#[tauri::command]
pub async fn get_logs<R: Runtime>(app: AppHandle<R>) -> Result<Vec<String>, String> {
    let token = app.state::<SessionToken>().0.clone();
    let res_str = send_daemon_command(VpnAction::GetLogs, token).await?;
    serde_json::from_str(&res_str).map_err(|e| e.to_string())
}
