use crate::daemon::{VpnAction, send_daemon_command};
use crate::state::SessionToken;
use tauri::{
    AppHandle, Manager, Runtime,
    menu::{Menu, MenuItem},
    tray::{TrayIcon, TrayIconBuilder, TrayIconEvent},
};

pub fn create_tray<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<TrayIcon<R>> {
    let quit_i = MenuItem::with_id(app, "quit", "Quit ShadowMesh", true, None::<&str>)?;
    let show_i = MenuItem::with_id(app, "show", "Open ShadowMesh", true, None::<&str>)?;
    let connect_i = MenuItem::with_id(app, "connect", "Connect VPN", true, None::<&str>)?;
    let disconnect_i = MenuItem::with_id(app, "disconnect", "Disconnect VPN", true, None::<&str>)?;
    let autostart_i = MenuItem::with_id(app, "autostart", "Launch on Login", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show_i, &connect_i, &disconnect_i, &autostart_i, &quit_i])?;

    let tray = TrayIconBuilder::<R>::with_id("main")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "quit" => {
                app.exit(0);
            }
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "connect" => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let token = handle.state::<SessionToken>().0.clone();
                    let _ = send_daemon_command(
                        VpnAction::Connect {
                            node_id: std::borrow::Cow::Borrowed("best"),
                            mode: None,
                        },
                        token,
                    )
                    .await;
                });
            }
            "disconnect" => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let token = handle.state::<SessionToken>().0.clone();
                    let _ = send_daemon_command(VpnAction::Disconnect, token).await;
                });
            }
            "autostart" => {
                // use tauri_plugin_autostart::ManagerExt;
                // let handle = app.clone();
                // let _manager = handle.autostart();
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: tauri::tray::MouseButton::Left, .. } = event {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(tray)
}
