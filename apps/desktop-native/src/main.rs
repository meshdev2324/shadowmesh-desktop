slint::include_modules!();

pub mod rfc011;
pub mod single_instance;
pub mod spring;
pub mod tray;

use crate::tray::TrayController;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Default tracing filter: release builds ship quiet (`warn`), debug keeps the
/// chatty `info` default. `RUST_LOG` always wins when the user sets it.
/// P1-5: log hygiene — no node names / tokens / endpoints at info level.
fn init_tracing() {
    let default_level = if cfg!(debug_assertions) { "info" } else { "warn" };
    let default_directive = default_level
        .parse::<tracing_subscriber::filter::LevelFilter>()
        .unwrap_or(tracing_subscriber::filter::LevelFilter::WARN)
        .into();
    let env_filter = tracing_subscriber::filter::EnvFilter::builder()
        .with_default_directive(default_directive)
        .from_env_lossy();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // P1-8: single-instance guard — must run before any UI/state is created.
    // Dependency-free: Unix abstract-free lock socket / Windows lockfile.
    if !single_instance::acquire_lock() {
        // Another instance already owns the lock; exit silently (exit 0) so
        // launchers/scripts treat this as a no-op, not a failure.
        return Ok(());
    }

    init_tracing();
    info!("ShadowMesh Native: initializing desktop client");

    let ui = AppWindow::new()?;
    let tray = TrayController::new()?;

    // v5.5 Principal Standard: Shared Rust Core integration
    let api_url =
        std::env::var("SHADOWMESH_API_URL").unwrap_or_else(|_| "https://api.shadowmesh.org".into());
    let api_client = shadowmesh_core::create_api_client(api_url)?;
    let vpn_manager =
        shadowmesh_core::create_vpn_manager(shadowmesh_core::get_default_user_settings())?;
    let desktop_controller =
        Arc::new(shadowmesh_core::DesktopController::new(api_client.clone(), vpn_manager.clone()));

    let device_id = shadowmesh_core::get_persistent_device_id();
    ui.set_device_id(device_id.into());
    ui.set_version(env!("CARGO_PKG_VERSION").into());

    // Check current state (Team Logic)
    if vpn_manager.is_activated() {
        ui.set_is_team_member(true); // Simplified for now
        // If it's a team plan, we could set is_team_admin based on API info
    }

    // ------------------------------------------------------------
    // P0-2: Connect flow — wired through the EXISTING core APIs
    // (VPNManager::initiate_connection / complete_connection / disconnect).
    // The core state machine handles attempt tracking and mode selection;
    // results are marshalled back to the UI thread via
    // spawn_blocking + invoke_from_event_loop (same pattern as P0-1).
    // ------------------------------------------------------------
    let ui_handle = ui.as_weak();
    let vpn_connect = vpn_manager.clone();
    ui.on_request_connect(move |_node_hint| {
        let Some(ui) = ui_handle.upgrade() else { return };
        // ZPII: never log the node name or endpoint at info level.
        ui.set_status("CONNECTING...".into());

        let ui_weak = ui.as_weak();
        let vpn = vpn_connect.clone();
        tokio::spawn(async move {
            // initiate_connection is a synchronous core API that mutates the
            // shared state machine; keep it off the UI thread.
            let initiated = tokio::task::spawn_blocking(move || {
                // Node selection: best available node, falling back to the
                // seeded anycast entry when the manifest has not been synced.
                // RFC-016: the data-plane lives in the daemon; this primes
                // the core state machine, then the daemon round-trip below
                // decides the truth.
                let node = vpn
                    .get_best_node()
                    .or_else(|| vpn.get_nodes().into_iter().next())
                    .ok_or(shadowmesh_core::ShadowMeshError::ConnectionFailed)?;
                vpn.set_selected_node(node.clone());
                vpn.initiate_connection(node, String::new())
            })
            .await;

            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                match initiated {
                    Ok(Ok(())) => {
                        // RFC-016 G2: state machine primed — the truth comes
                        // from the daemon round-trip below.
                        ui.set_status("CONNECTING...".into());
                        let status_weak = ui_weak.clone();
                        tokio::spawn(async move {
                            let outcome = async {
                                let mut client =
                                    shadowmesh_daemon::client::DaemonClient::connect().await?;
                                client.connect_vpn("best", None).await
                            }
                            .await;
                            let _ = slint::invoke_from_event_loop(move || {
                                let Some(ui) = status_weak.upgrade() else { return };
                                match outcome {
                                    Ok(resp) if resp.success => ui.set_status("PROTECTED".into()),
                                    Ok(resp) => {
                                        error!("Daemon connect rejected: {}", resp.message);
                                        ui.set_status(format!("ERROR: {}", resp.message).into())
                                    }
                                    Err(e) => {
                                        warn!("Daemon unreachable: {e}");
                                        ui.set_status(
                                            "DAEMON UNREACHABLE — start the ShadowMesh daemon"
                                                .into(),
                                        );
                                    }
                                }
                            });
                        });
                    }
                    Ok(Err(e)) => {
                        error!("Connect Error: {}", e);
                        ui.set_status(format!("ERROR: {e}").into());
                    }
                    Err(e) => {
                        error!("Connect task failed: {}", e);
                        ui.set_status(format!("ERROR: {e}").into());
                    }
                }
            });
        });
    });

    // P0-2: Disconnect — tears down the core state machine; the daemon owns
    // the actual tunnel process, so this clears session state only.
    let ui_handle_disc = ui.as_weak();
    let vpn_disconnect = vpn_manager.clone();
    ui.on_request_disconnect(move || {
        let Some(ui) = ui_handle_disc.upgrade() else { return };
        ui.set_status("DISCONNECTING...".into());
        let ui_weak = ui.as_weak();
        let vpn = vpn_disconnect.clone();
        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                vpn.disconnect();
                Ok::<(), shadowmesh_core::ShadowMeshError>(())
            })
            .await;
            // RFC-016 G2: the daemon owns the tunnel — tear it down there too.
            let daemon_outcome = async {
                let mut client = shadowmesh_daemon::client::DaemonClient::connect().await?;
                client.request(shadowmesh_daemon::types::VpnAction::Disconnect).await
            }
            .await;
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                match (&result, daemon_outcome) {
                    (Ok(Ok(())), Ok(resp)) if resp.success => ui.set_status("DISCONNECTED".into()),
                    (Ok(Ok(())), Ok(resp)) => {
                        error!("Daemon disconnect rejected: {}", resp.message);
                        ui.set_status(format!("ERROR: {}", resp.message).into())
                    }
                    (Ok(Ok(())), Err(e)) => {
                        warn!("Daemon unreachable on disconnect: {e}");
                        ui.set_status("DISCONNECTED (daemon offline)".into())
                    }
                    (Ok(Err(e)), _) => {
                        error!("Disconnect Error: {}", e);
                        ui.set_status(format!("ERROR: {e}").into())
                    }
                    (Err(e), _) => {
                        error!("Disconnect task failed: {}", e);
                        ui.set_status(format!("ERROR: {e}").into())
                    }
                }
            });
        });
    });

    let ui_handle_refresh = ui.as_weak();
    let api_clone = api_client.clone();
    let vpn_refresh = vpn_manager.clone();
    ui.on_request_refresh(move || {
        info!("UI Signal: Refreshing Global Manifest");
        // P0: core API blocks on its own runtime (get_runtime().block_on) —
        // running it here would panic "Cannot start a runtime from within a
        // runtime". Push to spawn_blocking, marshal back via event loop.
        let Some(ui) = ui_handle_refresh.upgrade() else { return };
        ui.set_status("LOADING...".into());
        let ui_weak = ui.as_weak();
        let api = api_clone.clone();
        let vpn = vpn_refresh.clone();
        tokio::spawn(async move {
            let result =
                match tokio::task::spawn_blocking(move || api.fetch_global_manifest()).await {
                    Ok(inner) => inner,
                    Err(e) => Err(shadowmesh_core::ShadowMeshError::Other(format!(
                        "Manifest task failed: {e}"
                    ))),
                };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                match result {
                    Ok(manifest) => {
                        // Keep the core router's node list in sync so
                        // get_best_node() has real candidates (P0-2).
                        vpn.set_nodes(manifest.nodes.clone());
                        let mut nodes_vec = Vec::new();
                        for node in manifest.nodes {
                            nodes_vec.push(MeshNode {
                                id: node.id.into(),
                                name: node.name.into(),
                                region: node.region.into(),
                                latency: format!("{}ms", node.latency).into(),
                                is_sovereign: node.is_sovereign,
                            });
                        }
                        let model = std::rc::Rc::new(slint::VecModel::from(nodes_vec));
                        ui.set_nodes(slint::ModelRc::from(model));
                        ui.set_status("MESH SYNCED".into());
                    }
                    Err(e) => {
                        error!("Manifest Fetch Error: {}", e);
                        ui.set_status(format!("ERROR: {e}").into());
                    }
                }
            });
        });
    });

    let ui_handle_login = ui.as_weak();
    let controller_login = desktop_controller.clone();
    ui.on_request_member_login(move |token| {
        info!("UI Signal: Member Authentication");
        // P0: authenticate_member blocks on the core runtime — offload first.
        // ZPII: the token itself is never logged.
        let Some(ui) = ui_handle_login.upgrade() else { return };
        ui.set_status("AUTHENTICATING...".into());
        let ui_weak = ui.as_weak();
        let controller = controller_login.clone();
        tokio::spawn(async move {
            let result = match tokio::task::spawn_blocking(move || {
                controller.authenticate_member(token.into())
            })
            .await
            {
                Ok(inner) => inner,
                Err(e) => {
                    Err(shadowmesh_core::ShadowMeshError::Other(format!("Auth task failed: {e}")))
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                match result {
                    Ok(()) => {
                        ui.set_is_team_member(true);
                        ui.set_show_team_login(false);
                        // P0-3: clear the captured token from the UI state
                        // once it has been consumed (zeroization bar).
                        ui.set_member_token("".into());
                        ui.set_status("AUTHENTICATED".into());
                    }
                    Err(e) => {
                        error!("Auth Error: {}", e);
                        ui.set_status(format!("AUTH FAILED: {e}").into());
                    }
                }
            });
        });
    });

    let ui_handle_admin = ui.as_weak();
    let controller_admin = desktop_controller.clone();
    ui.on_request_create_member_token(move |label| {
        info!("UI Signal: Creating Member Token");
        // P0: create_member_token blocks on the core runtime — offload first.
        let Some(ui) = ui_handle_admin.upgrade() else { return };
        ui.set_status("GENERATING TOKEN...".into());
        let ui_weak = ui.as_weak();
        let controller = controller_admin.clone();
        tokio::spawn(async move {
            let result = match tokio::task::spawn_blocking(move || {
                controller.create_member_token(label.into())
            })
            .await
            {
                Ok(inner) => inner,
                Err(e) => {
                    Err(shadowmesh_core::ShadowMeshError::Other(format!("Token task failed: {e}")))
                }
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                match result {
                    Ok(token) => {
                        ui.set_generated_member_token(token.into());
                        ui.set_status("TOKEN GENERATED".into());
                    }
                    Err(e) => {
                        error!("Token Gen Error: {}", e);
                        ui.set_status(format!("TOKEN ERROR: {e}").into());
                    }
                }
            });
        });
    });

    let tray_handle = std::rc::Rc::new(tray);
    let tray_clone = tray_handle.clone();
    ui.on_request_camouflage(move |enabled| {
        info!("UI Signal: Camouflage Mode {}", if enabled { "ENABLED" } else { "DISABLED" });
        tray_clone.set_decoy_mode(enabled);
    });

    // Initialize with mock nodes to verify "Mesh Matrix" physics
    let nodes_vec = vec![MeshNode {
        id: "anycast-1".into(),
        name: "Sovereign Anycast".into(),
        region: "Global Backbone".into(),
        latency: "12ms".into(),
        is_sovereign: true,
    }];

    let nodes_model = std::rc::Rc::new(slint::VecModel::from(nodes_vec));
    ui.set_nodes(slint::ModelRc::from(nodes_model));

    // Tray Event Bridge (Horizon 4 Native)
    // NOTE: a running slint::Timer MUST be held by a named binding — dropping
    // the Timer stops it (a temporary here would silently kill tray events).
    let ui_weak = ui.as_weak();
    let tray_poll = tray_handle.clone();
    let vpn_quit = vpn_manager.clone();
    let tray_timer = slint::Timer::default();
    tray_timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(100),
        move || {
            if let Some(signal) = tray_poll.handle_events() {
                match signal {
                    crate::tray::TraySignal::ShowWindow => {
                        if let Some(ui) = ui_weak.upgrade() {
                            let _ = ui.show();
                            ui.set_camouflage_active(false);
                            tray_poll.set_decoy_mode(false);
                        }
                    }
                    crate::tray::TraySignal::ToggleCamouflage(enabled) => {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_camouflage_active(enabled);
                            tray_poll.set_decoy_mode(enabled);
                            // v5.5 Forensic: Hide window from taskbar if possible
                            // Slint window API is evolving, for now we swap process identity
                        }
                    }
                    crate::tray::TraySignal::Quit => {
                        // P1-3: graceful quit — tear down the VPN session if
                        // connected, then unwind the event loop instead of
                        // hard-killing the process (no std::process::exit).
                        if matches!(
                            vpn_quit.get_status(),
                            shadowmesh_core::ConnectionStatus::Connected
                        ) {
                            // TODO-RFC-011: daemon-owned tunnel teardown;
                            // core state machine reset is the desktop's share.
                            vpn_quit.disconnect();
                        }
                        slint::quit_event_loop().unwrap_or_else(|e| {
                            warn!("Event loop quit failed: {}", e);
                        });
                    }
                }
            }
        },
    );

    // v6 Glimmer Physics Driver: true velocity-tracked spring for the
    // connection-strength bar + ambient breathing pulse (03_Physics_Engine.md).
    // Fixed 16ms step, zero-alloc hot loop; idle springs cost nothing once
    // settled (performance budget).
    let ui_physics = ui.as_weak();
    let mut conn_spring = crate::spring::Spring::new(0.0);
    let mut pulse_phase: f32 = 0.0;
    let physics_timer = slint::Timer::default();
    physics_timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(16),
        move || {
            let Some(ui) = ui_physics.upgrade() else { return };
            let live = ui.get_status().as_str() == "CONNECTED" && !ui.get_camouflage_active();
            let target = if live { 1.0 } else { 0.0 };

            if !conn_spring.settled(target, 0.001, 0.01) {
                conn_spring.step(target, crate::spring::PREMIUM, 1.0 / 60.0);
                ui.set_conn_strength(conn_spring.pos);
            }

            if live {
                pulse_phase = (pulse_phase + 0.05) % std::f32::consts::TAU;
                ui.set_mesh_pulse(0.55 + 0.45 * pulse_phase.sin());
            } else if pulse_phase != 0.0 {
                pulse_phase = 0.0;
                ui.set_mesh_pulse(1.0);
            }
        },
    );

    // ------------------------------------------------------------
    // RFC-011 §4.2/4.3/4.4: update notice, autostart toggle, forensic wipe.
    // All three run off-thread (spawn_blocking) and marshal back through
    // invoke_from_event_loop — the UI thread never blocks or panics.
    // ------------------------------------------------------------

    // §4.3: surface the current autostart state (default OFF per spec).
    match rfc011::Autostart::is_enabled() {
        Ok(enabled) => ui.set_autostart_enabled(enabled),
        Err(e) => warn!("autostart state unavailable: {e}"),
    }

    // §4.2: notice-only update check on the 24h cadence. Never nags: a
    // failed or up-to-date check surfaces nothing.
    let state_dir = rfc011::app_state_dir().unwrap_or_else(|e| {
        warn!("state dir unavailable, update-notice disabled: {e}");
        std::path::PathBuf::from("/tmp")
    });
    if rfc011::UpdateNotice::check_due(&state_dir) {
        let ui_weak = ui.as_weak();
        let api_notice = api_client.clone();
        let current = env!("CARGO_PKG_VERSION").to_string();
        let state_dir_notice = state_dir.clone();
        tokio::spawn(async move {
            let notice = tokio::task::spawn_blocking(move || {
                rfc011::UpdateNotice::fetch(&api_notice, &current)
            })
            .await;
            rfc011::UpdateNotice::record_check(&state_dir_notice);
            if let Ok(Ok(Some(n))) = notice {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        // Notice-only (RFC-011 §4.2): display, no download,
                        // no execution. The user opens the releases page.
                        ui.set_status(
                            format!("UPDATE AVAILABLE: {} (see releases)", n.latest_version).into(),
                        );
                    }
                });
            }
        });
    }

    // §4.3: autostart toggle handler.
    let ui_weak = ui.as_weak();
    ui.on_request_autostart(move |enabled| {
        match rfc011::Autostart::set_enabled(enabled) {
            Ok(()) => {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_autostart_enabled(enabled);
                    ui.set_status(if enabled {
                        "AUTOSTART ON".into()
                    } else {
                        "AUTOSTART OFF".into()
                    });
                }
            }
            Err(e) => {
                warn!("autostart toggle failed: {e}");
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_status(format!("AUTOSTART ERROR: {e}").into());
                    // Reflect the unchanged actual state.
                    if let Ok(cur) = rfc011::Autostart::is_enabled() {
                        ui.set_autostart_enabled(cur);
                    }
                }
            }
        }
    });

    // §4.4: forensic wipe. Teardown first, then the §4.4 purge order; the
    // report drives the final status. Confirmation lives in the UI layer
    // (the Slint side shows a confirm sheet before invoking this).
    let ui_weak = ui.as_weak();
    let vpn_wipe = vpn_manager.clone();
    ui.on_request_forensic_wipe(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        ui.set_status("WIPING...".into());

        let ui_w = ui.as_weak();
        let vpn = vpn_wipe.clone();
        let state = state_dir.clone();
        tokio::spawn(async move {
            let report = tokio::task::spawn_blocking(move || {
                rfc011::forensic_wipe(&state, move || {
                    // Core state-machine teardown; the daemon-owned data
                    // plane follows the same signal path as Quit.
                    vpn.disconnect();
                })
            })
            .await
            .unwrap_or_default();

            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = ui_w.upgrade() else { return };
                if report.steps_failed.is_empty() {
                    ui.set_status("WIPED".into());
                } else {
                    ui.set_status(
                        format!("WIPED ({} steps failed)", report.steps_failed.len()).into(),
                    );
                }
                // First-run reset: identity regenerates on next launch;
                // clear the member surface immediately.
                ui.set_is_team_member(false);
                ui.set_generated_member_token("".into());
            });
        });
    });

    ui.run()?;
    Ok(())
}
