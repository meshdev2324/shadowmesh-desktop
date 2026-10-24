slint::include_modules!();

pub mod qr;
pub mod rfc011;
pub mod single_instance;
pub mod spring;
pub mod tray;
// The daemon's IPC arms, read the way an untagged union has to be read: the
// `QrToken` arm this tree needs, and the roster's projection (RFC-047 §2.3).
//
// ⚠️ **`roster_projection` and `projection_label` are read by the TESTS only
// now, and that is deliberate.** The status line states the **manifest's**
// projection (RFC-051 §3, requirement 1) — so the desktop no longer asks the
// daemon for the *roster route's* projection — and the wire/token word may
// not appear on a client surface at all (L6's V-4 and V-5). The module
// stays: the daemon's arms are a reader surface with their own gates, and
// these two readers are what those gates assert.
#[allow(dead_code)]
pub mod ipc_arms;
// RFC-051 — the manifest row's read-out contract.
//
// The runtime half is the roster state's own vocabulary: the state's short
// label (L6's **reading** — never the wire/token word) and the status line
// the desktop reads it out on. The gate half — the **R12** structural check
// on `main.slint`'s row type — lives with it, because a gate that does not
// see the thing it gates is a gate nobody has seen go red.
pub mod rfc051;
// F101 — the desktop's **closed set** of connection failures.
//
// The client's failure text is looked up from a **class**, and the control
// plane's own string is never carried into a render path or a log line
// (L10's M-2, M-8; gate RP-2; AC-2.1 … AC-2.7).
pub mod connection_failure;
// C-2 — the desktop client's crash-artefact posture. The binary sets it as
// main()'s FIRST statement, before anything can place credential material in
// resident memory (L10's dumpability-ruling.md §3.2 — same posture, same
// reason as the daemon: this client resolves the same IPC credential through
// client.rs:278).
pub mod dumpability;
// The attribution checker is TEST-ONLY, and that is a correctness property,
// not a style choice: the marker strings ("MadeWithSlint", "https://slint.dev/")
// must NOT be linked into the shipped binary, or the R1 check would be
// satisfied by the checker's own constants instead of by the upstream widget.
// The checker checks the artefact from the outside, so it must live outside it.
#[cfg(test)]
mod attribution;
#[cfg(test)]
mod testing;
// The daemon's IPC union, read FROM THE WIRE. TEST-ONLY because the thing
// under test is the decoder's arm order, not a runtime path.
#[cfg(test)]
mod ipc_wire;

use crate::tray::TrayController;
use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};

/// The stamp of the sources this binary was built from.
///
/// `build.rs` digests every source file that determines the binary, writes
/// the digest into `OUT_DIR` (where the artefact-level check reads it) and
/// stamps the same string into the artefact itself (where the check finds it).
/// Comparing the two is what stops the check from certifying an artefact that
/// was built from something else — see `src/attribution.rs`.
///
/// It is a digest of public source, not a secret, and it is logged at startup
/// so that a running binary can be traced back to the tree it came from.
pub const SOURCE_STAMP: &str = env!("SHADOWMESH_DESKTOP_SOURCE_STAMP");

/// Groups flat manifest nodes into country sections for the matrix UI.
/// First-seen order preserves the core router's preference ordering; empty
/// country codes fall back to the region as the section label so legacy
/// nodes never disappear under a blank header.
fn group_nodes_by_country(nodes: &[crate::MeshNode]) -> Vec<crate::CountryGroup> {
    let mut sections: Vec<(String, Vec<crate::MeshNode>)> = Vec::new();
    for node in nodes {
        let label = if node.country.is_empty() {
            node.region.to_string()
        } else {
            node.country.to_string()
        };
        match sections.iter_mut().find(|(l, _)| *l == label) {
            Some((_, section)) => section.push(node.clone()),
            None => sections.push((label, vec![node.clone()])),
        }
    }
    sections
        .into_iter()
        .map(|(label, section)| crate::CountryGroup {
            label: label.into(),
            nodes: slint::ModelRc::from(std::rc::Rc::new(slint::VecModel::from(section))),
        })
        .collect()
}

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
    // C-2 — the posture comes FIRST: nothing may place credential material in
    // a still-dumpable memory image (M-3's desktop shape; the gate below
    // asserts the order against this file). The single-instance guard's
    // early-exit runs with the posture already set — dying quietly with the
    // posture on is as safe as running with it.
    crate::dumpability::apply();

    // P1-8: single-instance guard — must run before any UI/state is created.
    // Dependency-free: Unix abstract-free lock socket / Windows lockfile.
    if !single_instance::acquire_lock() {
        // Another instance already owns the lock; exit silently (exit 0) so
        // launchers/scripts treat this as a no-op, not a failure.
        return Ok(());
    }

    init_tracing();
    // The source stamp is in the log line so that the artefact a user is
    // running can be traced back to the tree it was built from — and so that
    // the stamp is a *referenced* string in the binary rather than one the
    // linker is free to drop.
    info!("ShadowMesh Native: initializing desktop client (source {})", SOURCE_STAMP);

    let ui = AppWindow::new()?;
    let tray = TrayController::new()?;

    // ------------------------------------------------------------
    // F40 — Slint §2(a) attribution.
    //
    // The top level menu's "Help > About ShadowMesh" entry raises
    // `request_show_about`; this handler shows the About screen, which
    // displays the upstream `AboutSlint` widget. The licence text is
    // `LICENSES/LicenseRef-Slint-Royalty-free-2.0.md` §2(a):
    //
    //   "Display the [`AboutSlint`] widget in an "About" screen or dialog
    //    that is accessible from the top level menu of the Application."
    //
    // The artefact-level check that the widget survived into the shipped
    // binary lives in `src/attribution.rs`.
    // ------------------------------------------------------------
    let about = AboutWindow::new()?;
    // `set_about_version` takes a `SharedString`, so the `&'static str` has to
    // be converted. (Observed: removing the `.into()` fails with E0308 —
    // "expected `SharedString`, found `&str`".)
    about.set_about_version(env!("CARGO_PKG_VERSION").into());
    {
        let about_weak = about.as_weak();
        ui.on_request_show_about(move || {
            let Some(about) = about_weak.upgrade() else { return };
            // Runtime self-check. The upstream widget must actually be
            // instantiated for the licence condition to be met; an import
            // alone would satisfy nothing. Logged rather than fatal — the
            // gate is the artefact-level check.
            if !about.get_about_slint_instantiated() {
                error!(
                    "Slint attribution widget is not instantiated — \
                     licence §2(a) is NOT satisfied"
                );
            }
            let _ = about.show();
        });
    }
    {
        let about_weak = about.as_weak();
        about.on_request_close(move || {
            if let Some(about) = about_weak.upgrade() {
                let _ = about.hide();
            }
        });
    }
    {
        // The main window hides rather than exits (the app lives in the
        // tray), so the About screen must not be left floating on its own.
        let about_weak = about.as_weak();
        ui.window().on_close_requested(move || {
            if let Some(about) = about_weak.upgrade() {
                let _ = about.hide();
            }
            slint::CloseRequestResponse::HideWindow
        });
    }

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
    // The **listing rows** the desktop holds, and where they came from.
    //
    // ⚠️ **These rows are held PLATFORM-SIDE, and they are held as
    // `PublicNode`s — the listing row.** They are **not** pushed into the
    // core's `VPNManager`, which is the **connect** surface and takes
    // `VPNNode`s (RFC-050 §2.1). The desktop needs them for exactly two
    // things: the rows it renders, and the **filter** it applies when the
    // user asks to connect (RFC-050 §2.5).
    //
    // ⇒ The shape of the answer is Android's: the listing rows live on the
    // client, and the connect surface is fed by the connect route, not by
    // the roster (`apps/android/.../VpnRepositoryImpl.kt:33`).
    // ------------------------------------------------------------
    let listing_rows: Arc<Mutex<Vec<shadowmesh_core::PublicNode>>> =
        Arc::new(Mutex::new(Vec::new()));

    // ------------------------------------------------------------
    // P0-2: Connect flow.
    //
    // ⚠️ **The roster is a LISTING, and it never enters the connect
    // surface** (RFC-050 §2.1, §3.3).
    //
    // The core's `VPNManager` is the **connect** surface: it holds
    // `VPNNode`s — eight mandatory fields, the connect material among
    // them — and the manifest's rows are `PublicNode`s, four fields. A
    // listing row is not a connect row, and turning one into a connect
    // row means inventing the fields the listing does not carry. That is
    // the fabrication class (RFC-050 §6 item 6), and the desktop does not
    // do it.
    //
    // ⇒ The desktop SELECTS by the **filter** — RFC-050 §2.5: *the first
    // **online** row, in the server's own SQL order* — and hands the daemon
    // that row's **id**. The daemon is what dials: it has its own session,
    // and it fetches the connect material from the authenticated config
    // route (RFC-043 R2). That is the daemon's own design, unchanged
    // (`apps/daemon/src/daemon.rs:53-57`).
    //
    // ⚠️ **The core's state machine is therefore NOT primed from the
    // roster.** RFC-016 G2's *"the truth comes from the daemon round-trip"*
    // was always the operative half; the priming was a courtesy, and the
    // courtesy needed a connect row the desktop does not have.
    // ------------------------------------------------------------
    let ui_handle = ui.as_weak();
    let listing = listing_rows.clone();
    ui.on_request_connect(move |_node_hint| {
        let Some(ui) = ui_handle.upgrade() else { return };
        // ZPII: never log the node name or endpoint at info level.
        ui.set_status("CONNECTING...".into());

        let ui_weak = ui.as_weak();
        // The handler is `FnMut` — it may be called again — so the cell is
        // cloned per invocation rather than moved out of the closure.
        let listing = listing.clone();
        tokio::spawn(async move {
            // The selection: a **filter**, never a ranking (RFC-050 §2.5).
            //
            // ⚠️ The filter is the daemon's own function, called on the
            // rows the desktop holds — one implementation of the rule, not
            // two (RFC-050 §2.5: *"the desktop's selection becomes the
            // daemon's"*).
            let selected_id = {
                let guard = listing.lock().unwrap_or_else(|e| e.into_inner());
                shadowmesh_daemon::select_best_public_node(&guard).map(|n| n.id.clone())
            };
            // ⇒ The **id** the daemon is asked to dial. When the desktop
            // holds no online row it asks the daemon for **"best"** — which
            // is the **same filter**, applied by the daemon to the **roster
            // route**, on the daemon's own session. That is not a fallback
            // row: it is a request for the daemon to select, and the daemon
            // selects from rows it fetched itself.
            let node_id = selected_id.unwrap_or_else(|| "best".to_string());

            let outcome = async {
                let mut client = shadowmesh_daemon::client::DaemonClient::connect().await?;
                client.connect_vpn(&node_id, None).await
            }
            .await;
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                match outcome {
                    Ok(resp) if resp.success => ui.set_status("CONNECTED".into()),
                    Ok(_resp) => {
                        // 🔴 **The daemon's message is NOT carried**
                        // (L10's M-2, AC-2.1, AC-2.2). It is the control
                        // plane's answer, relayed — and it reaches the
                        // always-visible status line.
                        //
                        // ⇒ The client holds a **class** and looks the text up
                        // from the class. The class here is the client's own
                        // knowledge: the daemon refused, and the client does
                        // not read why.
                        let failure = crate::connection_failure::ConnectionFailure::Refused;
                        error!("Daemon connect refused — {}", failure.label());
                        ui.set_status(failure.label().into())
                    }
                    Err(_e) => {
                        // ⚠️ **The transport's error is not logged either**
                        // (L10's M-8, AC-2.4): the log line carries the
                        // **label**, and never the error's `Display`.
                        let failure =
                            crate::connection_failure::ConnectionFailure::DaemonUnreachable;
                        warn!("Daemon unreachable — {}", failure.label());
                        ui.set_status(failure.label().into());
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
                    (Ok(Ok(())), Ok(_resp)) => {
                        // 🔴 **The daemon's message is NOT carried** (L10's
                        // M-2, AC-2.1, AC-2.2), and neither is the error's
                        // `Display` (AC-2.4).
                        let failure = crate::connection_failure::DisconnectFailure::Refused;
                        error!("Daemon disconnect refused — {}", failure.label());
                        ui.set_status(failure.label().into())
                    }
                    (Ok(Ok(())), Err(_e)) => {
                        let failure =
                            crate::connection_failure::DisconnectFailure::DaemonUnreachable;
                        warn!("Daemon unreachable on disconnect — {}", failure.label());
                        ui.set_status(failure.label().into())
                    }
                    (Ok(Err(_e)), _) => {
                        let failure = crate::connection_failure::DisconnectFailure::Core;
                        error!("Disconnect refused — {}", failure.label());
                        ui.set_status(failure.label().into())
                    }
                    (Err(_e), _) => {
                        let failure = crate::connection_failure::DisconnectFailure::Core;
                        error!("Disconnect task failed — {}", failure.label());
                        ui.set_status(failure.label().into())
                    }
                }
            });
        });
    });

    // RFC-018: dismiss a pending pairing request. Without this the only way out
    // of a code started by mistake was to regenerate it, leaving a live
    // approval prompt on the phone for no reason.
    let ui_weak_for_cancel = ui.as_weak();
    ui.on_request_pairing_cancel(move || {
        let ui_weak_for_cancel = ui_weak_for_cancel.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak_for_cancel.upgrade() {
                ui.set_pairing_token("".into());
                ui.set_pairing_qr(slint::Image::default());
                ui.set_pairing_waiting(false);
            }
        });
    });

    // RFC-018: desktop pairing — generate the session token and poll until
    // the authorized device approves; the daemon auto-activates on approval.
    let ui_handle_pair = ui.as_weak();
    ui.on_request_pairing_generate(move || {
        let Some(ui) = ui_handle_pair.upgrade() else { return };
        ui.set_status("PAIRING...".into());
        let ui_weak = ui.as_weak();
        tokio::spawn(async move {
            // 1. Generate the session.
            let generated = async {
                let mut client = shadowmesh_daemon::client::DaemonClient::connect().await?;
                let resp = client
                    .request(shadowmesh_daemon::types::VpnAction::QrAuth {
                        op: shadowmesh_daemon::types::QrAuthOp::Generate,
                    })
                    .await?;
                // The arm is read in `ipc_arms`, which names the arm that
                // arrived when it is not this one — and never prints the
                // payload, which is where the token lives (RFC-043 §3.4).
                crate::ipc_arms::qr_token(&resp)
            }
            .await;
            let token = match generated {
                Ok(t) => {
                    let ui_for_token = ui_weak.clone();
                    let token_for_ui = t.clone();
                    // v2 pairing UX: render the scannable QR on the UI thread
                    // (slint::Image is not Send — only the token crosses here).
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_for_token.upgrade() {
                            ui.set_pairing_token(token_for_ui.clone().into());
                            ui.set_pairing_waiting(true);
                            if let Some(image) = qr::pairing_qr_image(&token_for_ui) {
                                ui.set_pairing_qr(image);
                            }
                        }
                    });
                    t
                }
                Err(_e) => {
                    // 🔴 **The error's `Display` is neither rendered nor
                    // logged** (L10's M-2, M-8, AC-2.2, AC-2.4): the client's
                    // own label, and nothing the daemon or the control plane
                    // said.
                    warn!(
                        "Pairing generate failed — {}",
                        crate::connection_failure::PAIRING_FAILED
                    );
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_status(crate::connection_failure::PAIRING_FAILED.into());
                        }
                    });
                    return;
                }
            };

            // 2. Poll until the authorized device approves (or ~5 minutes).
            for _ in 0..60 {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let poll = async {
                    let mut client = shadowmesh_daemon::client::DaemonClient::connect().await?;
                    client
                        .request(shadowmesh_daemon::types::VpnAction::QrAuth {
                            op: shadowmesh_daemon::types::QrAuthOp::CheckStatus {
                                token: token.clone().into(),
                            },
                        })
                        .await
                }
                .await;
                if let Ok(resp) = poll
                    && resp.success
                    && resp.message == "Pairing activated"
                {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_pairing_waiting(false);
                            ui.set_status("CONNECTED".into());
                        }
                    });
                    return;
                }
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_pairing_waiting(false);
                    ui.set_status("PAIRING EXPIRED".into());
                }
            });
        });
    });

    let ui_handle_refresh = ui.as_weak();
    let api_clone = api_client.clone();
    ui.on_request_refresh(move || {
        info!("UI Signal: Refreshing Global Manifest");
        // P0: core API blocks on its own runtime (get_runtime().block_on) —
        // running it here would panic "Cannot start a runtime from within a
        // runtime". Push to spawn_blocking, marshal back via event loop.
        let Some(ui) = ui_handle_refresh.upgrade() else { return };
        // ⚠️ **The roster's lifecycle writes to the ROSTER's line, not to the
        // connection's status card** (L6's §6.2 row 1; F-7). The status card
        // is the connection's slot, and a roster fact rendered in the
        // connection card is incoherent — and, before this move, it was
        // conditionally present: the connection state overwrote the roster
        // state, so the roster state was present only when the last event
        // happened to be a manifest read (A-10, L10's RP-19).
        //
        // ⇒ While the request is outstanding the state line says so:
        // `READING THE ROSTER` (L6's §2.2 `pending`).
        crate::rfc051::publish(&ui, crate::rfc051::RosterState::Pending);
        let ui_weak = ui.as_weak();
        let api = api_clone.clone();
        let listing_rows = listing_rows.clone();
        tokio::spawn(async move {
            let result =
                match tokio::task::spawn_blocking(move || api.fetch_global_manifest()).await {
                    Ok(inner) => inner,
                    // ⚠️ **The join error's text is not carried into the error
                    // type** (L10's M-2): the error's `message` is a field the
                    // control plane may have written, and this one is a fixed
                    // string so it cannot be. The classification reads the
                    // **discriminant** — `RosterState::from_failure` — and
                    // never the message.
                    Err(_e) => {
                        Err(shadowmesh_core::ShadowMeshError::Other("Manifest task failed".into()))
                    }
                };
            // F86 — which projection the roster carried.
            //
            // ⚠️ **The MANIFEST's projection, and the daemon hop is gone.**
            //
            // The comment that used to stand here said the manifest path
            // *"cannot say"* — that the core's `GlobalManifest` carried no
            // `projection` field. **That stopped being true** when the core
            // grew the field (the roster envelope, commit `11836fe`): the
            // manifest route serves the same `"projection"` the roster route's
            // envelope serves, and the type now carries it.
            //
            // ⇒ The desktop asks the surface it actually read. The daemon
            // reads the **roster** route and the desktop reads the
            // **manifest** route: **two surfaces, two projections, and they
            // can differ** (RFC-051 §3, requirement 1). Reading the daemon's
            // projection and reporting it as the manifest's would be a
            // statement about a roster the daemon served.
            //
            // And the hop was not free: a daemon connect + a `ListNodes`
            // round-trip on every refresh, to read a field the answer
            // already carried.

            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                match result {
                    Ok(manifest) => {
                        // ⚠️ **The roster does NOT enter the connect surface.**
                        //
                        // This used to be `vpn.set_nodes(manifest.nodes.clone())`
                        // — and it is the line RFC-050 §3.3 item 1 names as the
                        // type error that stopped the desktop compiling. The
                        // manifest's rows are `PublicNode`s; the core's
                        // `VPNManager` holds `VPNNode`s. Feeding one to the
                        // other is the fabrication class (RFC-050 §6 item 6):
                        // the listing carries no `endpoint` and no
                        // `public_key`, so a connect row built from it would
                        // be a row with invented connect material.
                        //
                        // ⇒ The rows are held **here**, platform-side, and the
                        // **filter** reads them (§2.5).
                        let listing = manifest.nodes.clone();
                        {
                            let mut guard = listing_rows.lock().unwrap_or_else(|e| e.into_inner());
                            *guard = listing.clone();
                        }
                        let mut nodes_vec = Vec::new();
                        for node in &listing {
                            // The row is built from the **four published
                            // fields** and no others (RFC-051 §2.1).
                            //
                            // ⚠️ **The compiler is the gate.** The Slint row
                            // type has no `name`, no `latency` and no
                            // `is_sovereign`, so this builder cannot
                            // re-synthesise them: a boolean the surface
                            // cannot fill is `false`, and `false` about
                            // sovereignty is a jurisdictional claim about a
                            // node this client never asked about.
                            nodes_vec.push(MeshNode {
                                id: node.id.clone().into(),
                                region: node.region.clone().into(),
                                country: node.country.clone().into(),
                                is_online: node.is_online,
                            });
                        }
                        ui.set_nodes(slint::ModelRc::from(std::rc::Rc::new(
                            slint::VecModel::from(nodes_vec.clone()),
                        )));
                        ui.set_country_groups(slint::ModelRc::from(std::rc::Rc::new(
                            slint::VecModel::from(group_nodes_by_country(&nodes_vec)),
                        )));
                        // The state is the MANIFEST's projection, in L6's
                        // **reading** — the short label, never the wire or
                        // token word (L6's V-4 and V-5; L10's RP-17) — and it
                        // goes on the roster's OWN line, under the matrix
                        // panel (L6's §6.2).
                        crate::rfc051::publish(
                            &ui,
                            crate::rfc051::RosterState::from_projection(manifest.projection),
                        );
                    }
                    Err(e) => {
                        // 🔴 **The roster is CLEARED, not left standing.**
                        //
                        // A refresh that fails must not leave the PREVIOUS
                        // fetch's rows on screen: those rows are not this
                        // fetch's rows, and a matrix that keeps them after a
                        // failed read says the control plane served them
                        // *now* (RFC-051 §5, fact 2).
                        //
                        // ⇒ The matrix is **empty and labelled**: an empty
                        // roster is a fact the user can act on, and a
                        // fabricated one is a lie they cannot.
                        //
                        // ⚠️ **The HELD rows are cleared with the matrix.**
                        // They are the same fact: if the matrix is empty,
                        // the filter must not still be able to name a row
                        // the user cannot see. A connect that dialed a row
                        // that is not on screen would be the roster
                        // outliving the read that failed.
                        {
                            let mut guard = listing_rows.lock().unwrap_or_else(|e| e.into_inner());
                            guard.clear();
                        }
                        let empty_nodes: Vec<MeshNode> = Vec::new();
                        ui.set_nodes(slint::ModelRc::from(std::rc::Rc::new(
                            slint::VecModel::from(empty_nodes),
                        )));
                        let empty_groups: Vec<CountryGroup> = Vec::new();
                        ui.set_country_groups(slint::ModelRc::from(std::rc::Rc::new(
                            slint::VecModel::from(empty_groups),
                        )));
                        // The state is the CLIENT's own label, chosen from
                        // L6's closed set — never the control plane's string
                        // (L10's M-2, gate RP-2) and never an account event
                        // (L10's R-1). The log line carries the same label
                        // and **not** the error's text: the error may BE the
                        // server's text (L10's M-8).
                        let state = crate::rfc051::RosterState::from_failure(&e);
                        error!("Manifest read failed — roster: {}", state.label());
                        crate::rfc051::publish(&ui, state);
                    }
                }
            });
        });
    });

    // ------------------------------------------------------------
    // The roster's CONDITION, on its own line — and the FIRST read.
    //
    // ⚠️ The state line is present in EVERY state (A-10, M-6, RP-19), so it
    // must carry a TRUE content from the first frame. Before the first read
    // the honest state is L6's §2.2 `pending` — the request is outstanding —
    // and the desktop now reads the roster **at launch** instead of waiting
    // for a click on REFRESH.
    //
    // ⚠️ Why the launch read: the roster's condition has to be true from
    // the first frame, and "the control plane has not been asked" is not a
    // state L6's vocabulary has (the aspect rule: *"not asked" is not "asked
    // and refused"*). The read is the SAME read the REFRESH control
    // performs — the control is still there, and it still does the same
    // thing.
    //
    // ⚠️ The timer is a ONE-SHOT and it must be HELD by a named binding:
    // dropping a `slint::Timer` stops it, and a timer that never fires
    // would leave the matrix empty with no error anywhere.
    // ------------------------------------------------------------
    crate::rfc051::publish(&ui, crate::rfc051::RosterState::Pending);
    let startup_timer = slint::Timer::default();
    {
        let ui_startup = ui.as_weak();
        startup_timer.start(
            slint::TimerMode::SingleShot,
            std::time::Duration::from_millis(0),
            move || {
                if let Some(ui) = ui_startup.upgrade() {
                    ui.invoke_request_refresh();
                }
            },
        );
    }

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
                // ⚠️ **The join error's text is not carried into the error
                // type** (L10's M-2): the error's `message` is a field the
                // control plane may have written, and this one is a fixed
                // string so it cannot be.
                Err(_e) => Err(shadowmesh_core::ShadowMeshError::Other("Auth task failed".into())),
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
                    Err(_e) => {
                        // 🔴 **The error's `Display` is neither rendered nor
                        // logged** (L10's M-2, M-8, AC-2.2, AC-2.4). The
                        // client's own label, and nothing the control plane
                        // said.
                        error!("Authentication refused — AUTHENTICATION FAILED");
                        ui.set_status("AUTHENTICATION FAILED".into());
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
                Err(_e) => Err(shadowmesh_core::ShadowMeshError::Other("Token task failed".into())),
            };
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                match result {
                    Ok(token) => {
                        ui.set_generated_member_token(token.into());
                        ui.set_status("TOKEN GENERATED".into());
                    }
                    Err(_e) => {
                        // 🔴 **The error's `Display` is neither rendered nor
                        // logged** (L10's M-2, M-8, AC-2.2, AC-2.4).
                        error!("Token generation refused — TOKEN GENERATION FAILED");
                        ui.set_status("TOKEN GENERATION FAILED".into());
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

    // ⚠️ **The matrix starts EMPTY, and there is no mock row here.**
    //
    // This block used to install a hard-coded row at every launch:
    //
    //     id: "anycast-1", name: "Sovereign Anycast", region: "Global Backbone",
    //     latency: "12ms", is_sovereign: true
    //
    // ⚠️ **That was a false statement about a third party, displayed as
    // fact.** A *sovereignty claim* about a node that does not exist, in the
    // purple stripe, and a *latency measurement* nobody took, in the pill —
    // and it **survived a failed fetch**, so a control plane that never
    // answered still left a populated matrix on screen. (The same class iOS
    // paid for in `b6d74fd`; the desktop had not paid it.)
    //
    // ⇒ **An empty roster is a fact the user can act on; a fabricated one is
    // a lie they cannot.** (RFC-051 §5, F103-15; iOS's own words.)
    //
    // There is no `set_nodes` before the first manifest read — the Slint
    // properties default to `[]` (`main.slint:440-442`), so the matrix is
    // empty until the control plane's own rows arrive — and a failed read
    // leaves it empty (see the refresh handler above).

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
                        slint::quit_event_loop().unwrap_or_else(|_e| {
                            // ⚠️ **The error's `Display` is not logged**
                            // (L10's AC-2.4): the log line carries the
                            // client's own label.
                            warn!("Event loop quit failed");
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
        // ⚠️ **The error's `Display` is not logged** (L10's AC-2.4).
        Err(_e) => warn!("autostart state unavailable"),
    }

    // §4.2: notice-only update check on the 24h cadence. Never nags: a
    // failed or up-to-date check surfaces nothing.
    let state_dir = rfc011::app_state_dir().unwrap_or_else(|_e| {
        warn!("state dir unavailable, update-notice disabled");
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
            Err(_e) => {
                // 🔴 **The error's `Display` is not rendered** (L10's M-2,
                // AC-2.2): the client's own label.
                warn!("autostart toggle failed — AUTOSTART FAILED");
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_status("AUTOSTART FAILED".into());
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
