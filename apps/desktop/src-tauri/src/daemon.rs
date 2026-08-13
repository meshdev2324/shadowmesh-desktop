use bytes::BytesMut;
use shadowmesh_daemon::ipc_codec::IpcCodec;
pub use shadowmesh_daemon::types::{
    QrAuthOp, SOCKET_PATH, SecureTokenOp, VpnAction, VpnCommand, VpnResponse, VpnResponseData,
};
use std::borrow::Cow;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(windows)]
use tokio::net::windows::named_pipe::ClientOptions;

pub async fn send_daemon_command(action: VpnAction<'_>, token: String) -> Result<String, String> {
    let mut last_err = String::new();
    let max_attempts = 5;

    // Big-Tech Standard: Exponential Backoff for IPC Resilience
    for attempt in 0..max_attempts {
        if attempt > 0 {
            let backoff = Duration::from_millis(100 * (2u64.pow(attempt as u32 - 1)));
            log::info!(
                "⏳ Retrying daemon IPC in {:?} (Attempt {}/{})",
                backoff,
                attempt + 1,
                max_attempts
            );
            tokio::time::sleep(backoff).await;
        }

        match connect_and_send(action.clone(), token.clone()).await {
            Ok(res) => return Ok(res),
            Err(e) => {
                last_err = e;
                log::warn!("⚠️ Daemon IPC attempt {} failed: {}", attempt + 1, last_err);
            }
        }
    }

    Err(format!(
        "ShadowMesh Daemon unreachable after {} attempts. Last error: {}",
        max_attempts, last_err
    ))
}

async fn connect_and_send(action: VpnAction<'_>, token: String) -> Result<String, String> {
    #[cfg(unix)]
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .await
        .map_err(|e| format!("Socket error: {}. Ensure daemon sidecar is running.", e))?;

    #[cfg(windows)]
    let mut stream = {
        let client = ClientOptions::new()
            .open(SOCKET_PATH)
            .map_err(|e| format!("Named pipe error: {}. Ensure daemon sidecar is running.", e))?;
        client
    };

    let cmd = VpnCommand { action, token: Cow::Owned(token) };
    let cmd_bytes = serde_json::to_vec(&cmd).map_err(|e| e.to_string())?;

    let mut write_buf = BytesMut::new();
    IpcCodec::encode(&cmd_bytes, &mut write_buf).map_err(|e| e.to_string())?;

    stream.write_all(&write_buf).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let mut read_buf = BytesMut::with_capacity(IpcCodec::MAX_PAYLOAD_SIZE);

    // Read response frame
    loop {
        if let Some(frame) = IpcCodec::decode(&mut read_buf).map_err(|e| e.to_string())? {
            let response: VpnResponse = serde_json::from_slice(&frame).map_err(|e| {
                format!("Parse error: {}. Raw: {}", e, String::from_utf8_lossy(&frame))
            })?;

            if response.success {
                if let Some(data) = response.data {
                    return Ok(serde_json::to_string(&data).unwrap_or_default());
                } else {
                    return Ok(response.message);
                }
            } else {
                return Err(response.message);
            }
        }

        let n = stream.read_buf(&mut read_buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("Daemon closed connection prematurely".into());
        }
    }
}

pub fn spawn_daemon_watchdog<R: tauri::Runtime>(
    handle: tauri::AppHandle<R>,
    session_token: String,
) {
    use tauri::Emitter;
    use tauri_plugin_shell::ShellExt;

    tauri::async_runtime::spawn(async move {
        let mut retry_count = 0;
        let max_retries = 10;

        loop {
            log::info!("🚀 ShadowMesh Watchdog: Spawning daemon sidecar...");
            let sidecar = handle.shell().sidecar("shadowmesh-daemon");

            match sidecar {
                Ok(sc) => {
                    let sc = sc.env("SHADOWMESH_IPC_TOKEN", session_token.clone());
                    match sc.spawn() {
                        Ok((mut rx, _child)) => {
                            log::info!("✅ ShadowMesh Daemon sidecar active");
                            retry_count = 0; // Reset on success
                            let _ = handle.emit("daemon-status", true);

                            // Monitor sidecar output/exit
                            while let Some(event) = rx.recv().await {
                                match event {
                                    tauri_plugin_shell::process::CommandEvent::Terminated(
                                        status,
                                    ) => {
                                        log::error!(
                                            "🚨 ShadowMesh Daemon sidecar terminated with status: {:?}",
                                            status.code
                                        );
                                        let _ = handle.emit("daemon-status", false);
                                        break;
                                    }
                                    tauri_plugin_shell::process::CommandEvent::Error(e) => {
                                        log::error!("🚨 ShadowMesh Daemon sidecar error: {}", e);
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("❌ Failed to spawn daemon: {}", e);
                        }
                    }
                }
                Err(e) => {
                    log::error!("❌ Failed to find daemon sidecar: {}", e);
                }
            }

            retry_count += 1;
            if retry_count > max_retries {
                log::error!("💥 ShadowMesh Watchdog: Max retries exceeded. Daemon giving up.");
                let _ = handle
                    .emit("daemon-fatal-error", "Daemon failed to start after multiple attempts");
                break;
            }

            let backoff = Duration::from_secs(2u64.pow(retry_count.min(5) as u32));
            log::warn!("🔄 ShadowMesh Watchdog: Restarting daemon in {:?}...", backoff);
            tokio::time::sleep(backoff).await;
        }
    });
}
