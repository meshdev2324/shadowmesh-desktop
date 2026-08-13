use std::sync::Arc;
use tauri::{Emitter, Listener, Manager, RunEvent, WindowEvent};
use uuid::Uuid;

pub mod commands;
pub mod daemon;
pub mod deeplink;
pub mod notifications;
pub mod state;
pub mod tray;

use crate::commands::*;
use crate::daemon::{VpnAction, send_daemon_command};
use crate::state::{CoreState, SessionToken};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_log::Builder::default().build())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .plugin(tauri_plugin_deep_link::init())
        .invoke_handler(tauri::generate_handler![
            run_helper,
            get_machine_id,
            ping_server,
            generate_keys,
            solve_pow_challenge,
            get_best_node,
            get_preferred_mode,
            get_traffic_stats,
            get_security_events,
            get_network_report,
            run_full_speed_test,
            encrypt_pairing_data,
            decrypt_pairing_data,
            get_quantum_params,
            verify_core_integrity,
            get_identity_info,
            logout,
            close_app,
            minimize_app,
            set_split_tunnel,
            get_logs,
            set_autostart
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            let session_token = Uuid::new_v4().to_string();
            app.manage(SessionToken(session_token.clone()));

            // Initialize System Tray
            let _tray = tray::create_tray(app.handle())?;

            // Initialize Deep Link Listener
            let handle_dl = app.handle().clone();
            app.listen("deep-link://new-url", move |event| {
                let url_str = event.payload();
                let action = deeplink::parse_deeplink(url_str);

                match action {
                    deeplink::DeepLinkAction::Activate { token } => {
                        let _ = handle_dl.emit("activate-token", token);
                        if let Some(window) = handle_dl.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    deeplink::DeepLinkAction::Connect { node_id } => {
                        let _ = handle_dl.emit("trigger-connect", node_id);
                    }
                    _ => {}
                }
            });

            // Start ShadowMesh Daemon Watchdog (Big-Tech Standard)
            #[cfg(not(mobile))]
            {
                crate::daemon::spawn_daemon_watchdog(app.handle().clone(), session_token.clone());
            }

            let config_dir = handle.path().app_config_dir().unwrap_or_default();
            let _ = std::fs::create_dir_all(&config_dir);

            let analytics = Arc::new(shadowmesh_core::TrafficAnalytics::new());
            let device_id = shadowmesh_core::get_persistent_device_id();
            let app_version = handle.package_info().version.to_string();
            let storage_dir = config_dir.join("logs").to_str().unwrap_or_default().to_string();

            let logger = shadowmesh_core::create_security_logger(
                device_id.clone(),
                app_version,
                storage_dir,
            )
            .map_err(|e| e.to_string())?;

            let api_client =
                shadowmesh_core::create_api_client("https://api.shadowmesh.org".into())
                    .map_err(|e| e.to_string())?;
            api_client.set_device_id(device_id);

            app.manage(CoreState {
                analytics: analytics.clone(),
                logger: logger.clone(),
                api_client: api_client.clone(),
            });

            // Status Polling Loop
            let session_token_clone = session_token.clone();
            tauri::async_runtime::spawn(async move {
                let mut daemon_online = true;
                let mut last_connected = false;

                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    match send_daemon_command(VpnAction::Status, session_token_clone.clone()).await
                    {
                        Ok(stdout) => {
                            if !daemon_online {
                                daemon_online = true;
                                let _ = handle.emit("daemon-status", true);
                            }
                            if let Ok(status) = serde_json::from_str::<serde_json::Value>(&stdout) {
                                let connected = status["connected"].as_bool().unwrap_or(false);
                                let state_str = status["status"].as_str().unwrap_or("disconnected");

                                // Notification Logic (TDD Green)
                                if connected != last_connected {
                                    if let Some(note) =
                                        notifications::map_vpn_status_to_notification(
                                            connected, state_str,
                                        )
                                    {
                                        use tauri_plugin_notification::NotificationExt;
                                        handle
                                            .notification()
                                            .builder()
                                            .title(note.title)
                                            .body(note.body)
                                            .show()
                                            .unwrap_or_default();
                                    }
                                    last_connected = connected;
                                }

                                let _ = handle.emit(
                                    "vpn-status-changed",
                                    serde_json::json!({
                                        "connected": connected,
                                        "state": state_str
                                    }),
                                );
                                let _ = handle.emit("traffic-stats", status);
                            }
                        }
                        Err(_) => {
                            if daemon_online {
                                daemon_online = false;
                                let _ = handle.emit("daemon-status", false);
                            }
                        }
                    }
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Hide window instead of closing
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            match event {
                RunEvent::Exit => {
                    // Big-Tech Standard: Graceful Shutdown Orchestration
                    let handle = app_handle.clone();
                    tauri::async_runtime::spawn(async move {
                        log::info!("🛑 ShadowMesh: Orchestrating graceful shutdown...");
                        if let Some(token) = handle.try_state::<SessionToken>() {
                            let _ = send_daemon_command(VpnAction::Shutdown, token.0.clone()).await;
                        }
                    });
                }
                RunEvent::ExitRequested { api, .. } => {
                    // We keep it running in tray, only explicit exit from tray menu works
                    api.prevent_exit();
                }
                _ => {}
            }
        });
}
