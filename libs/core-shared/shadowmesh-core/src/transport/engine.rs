use crate::transport::hysteria::HysteriaTransport;
use crate::transport::reality::RealityTransport;
use crate::transport::shadowsocks::ShadowsocksTransport;
use crate::transport::wireguard::WireGuardTransport;
use crate::transport::{AsyncTransport, TransportStack};
use crate::{ShadowMeshError, VPNConfig};
use bytes::Bytes;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Global control flag for the engine.
static ENGINE_RUNNING: AtomicBool = AtomicBool::new(false);
/// Storage for the active transport stack.
static STACK: OnceLock<Arc<TransportStack>> = OnceLock::new();
/// Storage for the active configuration (for fallback).
static ACTIVE_CONFIG: OnceLock<VPNConfig> = OnceLock::new();

use std::sync::OnceLock;

/// Starts the unified VPN engine.
pub fn start_engine(fd: i32, config: VPNConfig) -> Result<(), ShadowMeshError> {
    if ENGINE_RUNNING.load(Ordering::SeqCst) {
        warn!("Engine already running, restarting...");
        stop_engine();
    }

    let rt = crate::api_client::get_runtime()?;

    rt.block_on(async move {
        let _ = ACTIVE_CONFIG.set(config.clone());
        let stack = STACK.get_or_init(|| Arc::new(TransportStack::default()));

        // v6.9.1 Adaptive Entry: If mode is Reality, start with REALITY directly to avoid
        // UDP blockage delay.
        if config.traffic_mode == "reality" && config.reality_config.is_some() {
            let reality_config = config
                .reality_config
                .as_ref()
                .ok_or_else(|| ShadowMeshError::Other("missing reality config".into()))?;

            let priv_key = decode_key(config.private_key.as_deref().unwrap_or_default())?;
            let pub_key = decode_key(&config.public_key)?;

            let reality = RealityTransport::new(reality_config.clone(), priv_key, pub_key);
            reality.connect().await?;
            stack.swap(Box::new(reality)).await;
        } else if config.traffic_mode == "shadowsocks" && config.shadowsocks_config.is_some() {
            let ss_config = config
                .shadowsocks_config
                .as_ref()
                .ok_or_else(|| ShadowMeshError::Other("missing shadowsocks config".into()))?;

            let priv_key =
                decode_key(config.private_key.as_deref().unwrap_or_default()).unwrap_or([0u8; 32]);
            let pub_key = decode_key(&config.public_key).unwrap_or([0u8; 32]);

            let ss = ShadowsocksTransport::new(ss_config.clone(), priv_key, pub_key);
            ss.connect().await?;
            stack.swap(Box::new(ss)).await;
        } else if config.traffic_mode == "hysteria" && config.hysteria_config.is_some() {
            let hysteria_config = config
                .hysteria_config
                .as_ref()
                .ok_or_else(|| ShadowMeshError::Other("missing hysteria config".into()))?;

            let priv_key =
                decode_key(config.private_key.as_deref().unwrap_or_default()).unwrap_or([0u8; 32]);
            let pub_key = decode_key(&config.public_key).unwrap_or([0u8; 32]);

            let hysteria = HysteriaTransport::new(hysteria_config.clone(), priv_key, pub_key);
            hysteria.connect().await?;
            stack.swap(Box::new(hysteria)).await;
        } else if config.traffic_mode == "vmess" && config.vmess_config.is_some() {
            let vmess_config = config
                .vmess_config
                .as_ref()
                .ok_or_else(|| ShadowMeshError::Other("missing vmess config".into()))?;

            // v6.9.22: VMess Support in Unified Engine
            let (priv_key_vec, pub_key_vec) = shadowmesh_common::crypto::generate_x25519_keypair();
            let mut priv_key = [0u8; 32];
            priv_key.copy_from_slice(&priv_key_vec);
            let mut pub_key = [0u8; 32];
            pub_key.copy_from_slice(&pub_key_vec);

            let vmess = crate::transport::outbound::vmess::VmessTransport::new(
                vmess_config.clone(),
                priv_key,
                pub_key,
            );
            vmess.connect().await?;
            stack.swap(Box::new(vmess)).await;
        } else {
            // Tier 1: Initialize WireGuard (UDP/443)
            let remote_addr = config
                .endpoint
                .parse()
                .map_err(|_| ShadowMeshError::Other("Invalid endpoint address".into()))?;

            let wg = WireGuardTransport::new(
                remote_addr,
                config.private_key.clone().unwrap_or_default(),
                config.public_key.clone(),
            )?;

            wg.connect().await?;
            stack.swap(Box::new(wg)).await;
        }

        ENGINE_RUNNING.store(true, Ordering::SeqCst);

        // Start IO loops
        tokio::spawn(tun_loop(fd, stack.clone()));

        info!("🚀 ShadowMesh Unified Engine Started on FD {}", fd);
        Ok::<(), ShadowMeshError>(())
    })
}

/// Stops the engine.
pub fn stop_engine() {
    ENGINE_RUNNING.store(false, Ordering::SeqCst);
    info!("🛑 ShadowMesh Unified Engine Stopped.");
}

async fn tun_loop(fd: RawFd, stack: Arc<TransportStack>) {
    use std::os::unix::io::OwnedFd;
    use std::sync::atomic::Ordering;
    use tokio::io::unix::AsyncFd;

    // v6.9.5: High-Performance Non-blocking TUN
    // Ensure the FD is non-blocking before wrapping in AsyncFd
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let async_fd = match AsyncFd::new(owned_fd) {
        Ok(afd) => Arc::new(afd),
        Err(e) => {
            error!("Failed to create AsyncFd for TUN: {}", e);
            return;
        }
    };

    let manager = crate::vpn_manager::GLOBAL_MANAGER.get();

    // Read from TUN (AsyncFd), Send to Transport
    let stack_send = stack.clone();
    let manager_send = manager.cloned();
    let read_fd = async_fd.clone();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while ENGINE_RUNNING.load(Ordering::Relaxed) {
            match read_fd.readable().await {
                Ok(mut guard) => {
                    match guard.try_io(|inner| {
                        let res = unsafe {
                            libc::read(
                                inner.as_raw_fd(),
                                b.as_mut_ptr() as *mut libc::c_void,
                                b.len(),
                            )
                        };
                        if res > 0 {
                            Ok(res as usize)
                        } else {
                            Err(std::io::Error::last_os_error())
                        }
                    }) {
                        Ok(Ok(n)) => {
                            let data = Bytes::copy_from_slice(&b[..n]);

                            // v6.9.22: Mandatory Throttling in IO Hot-Path (RFC-001)
                            if let Some(ref m) = manager_send {
                                let _ = m.get_throttler().throttle(n).await;
                                m.get_atomic_stats()
                                    .bytes_sent
                                    .fetch_add(n as u64, Ordering::Relaxed);
                                m.get_atomic_stats().packets_sent.fetch_add(1, Ordering::Relaxed);
                            }

                            if let Err(e) = stack_send.send(data).await {
                                error!("Transport send error: {}", e);
                            }
                        }
                        Ok(Err(e)) => {
                            if e.kind() != std::io::ErrorKind::WouldBlock {
                                error!("TUN raw read error: {}", e);
                            }
                        }
                        Err(_would_block) => continue,
                    }
                }
                Err(e) => {
                    error!("AsyncFd readable error: {}", e);
                    break;
                }
            }
        }
    });

    // Receive from Transport, Write to TUN (AsyncFd)
    let stack_recv = stack.clone();
    let manager_recv = manager.cloned();
    let write_fd = async_fd.clone();
    tokio::spawn(async move {
        while ENGINE_RUNNING.load(Ordering::Relaxed) {
            match stack_recv.recv().await {
                Ok(packet) if !packet.is_empty() => {
                    match write_fd.writable().await {
                        Ok(mut guard) => {
                            // v6.9.22: Mandatory Throttling in IO Hot-Path (RFC-001)
                            if let Some(ref m) = manager_recv {
                                let _ = m.get_throttler().throttle(packet.len()).await;
                                m.get_atomic_stats()
                                    .bytes_received
                                    .fetch_add(packet.len() as u64, Ordering::Relaxed);
                                m.get_atomic_stats()
                                    .packets_received
                                    .fetch_add(1, Ordering::Relaxed);
                                let now = chrono::Utc::now().timestamp();
                                m.get_atomic_stats().last_handshake.store(now, Ordering::Relaxed);
                            }

                            let _ = guard.try_io(|inner| {
                                let res = unsafe {
                                    libc::write(
                                        inner.as_raw_fd(),
                                        packet.as_ptr() as *const libc::c_void,
                                        packet.len(),
                                    )
                                };
                                if res > 0 {
                                    Ok(res as usize)
                                } else {
                                    Err(std::io::Error::last_os_error())
                                }
                            });
                        }
                        Err(e) => {
                            error!("AsyncFd writable error: {}", e);
                            break;
                        }
                    }
                }
                Ok(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(e) => {
                    error!("Transport receive error: {}", e);
                    fallback_to_reality(stack_recv.clone()).await;
                }
            }
        }
    });
}

async fn fallback_to_reality(stack: Arc<TransportStack>) {
    warn!("⚠️ UDP Transport failure detected. Escalating to REALITY (TCP/443)...");

    if let Some(config) = ACTIVE_CONFIG.get() {
        if let Some(reality_config) = &config.reality_config {
            let priv_key =
                decode_key(config.private_key.as_deref().unwrap_or_default()).unwrap_or([0u8; 32]);
            let pub_key = decode_key(&config.public_key).unwrap_or([0u8; 32]);

            let reality = RealityTransport::new(reality_config.clone(), priv_key, pub_key);
            if let Err(e) = reality.connect().await {
                error!("Failed to connect to REALITY fallback: {}", e);
            } else {
                stack.swap(Box::new(reality)).await;
                info!("✅ Successfully escalated to REALITY transport.");
            }
        } else {
            error!("REALITY fallback failed: No reality_config found in active config.");
        }
    } else {
        error!("REALITY fallback failed: No active configuration found.");
    }
}

fn decode_key(s: &str) -> Result<[u8; 32], ShadowMeshError> {
    use base64::prelude::*;
    let b = BASE64_STANDARD
        .decode(s)
        .map_err(|_| ShadowMeshError::Other("Invalid key format".into()))?;
    if b.len() != 32 {
        return Err(ShadowMeshError::Other("Invalid key length".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&b);
    Ok(key)
}
