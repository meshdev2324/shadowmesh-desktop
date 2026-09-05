//! Native in-process engine tunnel (RFC-016 §4.3).
//!
//! Composes `shadowmesh-core` in its CLIENT role — the exact engine Android
//! uses via FFI (`start_engine` on a TUN fd, RealityTransport/SS stacks by
//! `traffic_mode`) — as a `VpnTunnel` behind the daemon's existing lifecycle.
//! Kernel wg-quick remains the transport for plain WireGuard nodes; this
//! mode serves the censorship-resistant tiers (REALITY / Shadowsocks).

use crate::daemon::TunnelHandle;
use crate::orchestration::VpnTunnel;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use shadowmesh_core::VPNConfig;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Which transport realization a node config requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelMode {
    /// Plain WireGuard node → kernel wg-quick / wireguard.exe (existing path).
    KernelWgQuick,
    /// REALITY or Shadowsocks tier → the in-process clean-room engine.
    InProcessEngine,
}

impl TunnelMode {
    /// Pure decision table (tested): the tier is determined by what the
    /// control plane actually returned, never by client-side guessing.
    pub fn for_config(config: &VPNConfig) -> Self {
        if config.reality_config.is_some() || config.shadowsocks_config.is_some() {
            Self::InProcessEngine
        } else {
            Self::KernelWgQuick
        }
    }
}

/// An engine session running against a TUN device inside the daemon.
///
/// The device is owned here and dropped in `shutdown` (after the engine is
/// stopped) so connect cycles never leak TUN interfaces or fds.
pub struct InProcessEngineTunnel {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
    /// Held until shutdown; the engine thread reads the raw fd.
    #[cfg(target_os = "linux")]
    dev: Mutex<Option<tun::AsyncDevice>>,
}

impl InProcessEngineTunnel {
    /// Spawns the engine on a dedicated OS thread with a fresh TUN device.
    ///
    /// Runtime bring-up requires root/CAP_NET_ADMIN (TUN creation) — the
    /// daemon runs privileged on desktop installs. Compile-checked on
    /// Linux; on-device verification is an operator step (RFC-016 §6).
    #[cfg(target_os = "linux")]
    pub fn spawn(config: VPNConfig) -> Result<TunnelHandle> {
        use std::os::fd::AsRawFd;

        let mut address = config.address.clone();
        if address.is_empty() {
            address = "10.8.0.2".into();
        }
        let mtu = if config.mtu == 0 { 1420 } else { config.mtu };

        let mut tuncfg = tun::Configuration::default();
        tuncfg.address(address).netmask("255.255.255.0").mtu(mtu as i32).up();
        tuncfg.platform(|p| {
            p.packet_information(true);
        });
        let dev = tun::create_as_async(&tuncfg)
            .map_err(|e| anyhow!("TUN device creation failed (root required): {e}"))?;
        let fd = dev.get_ref().as_raw_fd();

        // The engine owns its runtime; normalize the tier so start_engine's
        // adaptive entry picks the right stack.
        let mut engine_config = config.clone();
        if engine_config.traffic_mode.is_empty() {
            if engine_config.reality_config.is_some() {
                engine_config.traffic_mode = "reality".into();
            } else if engine_config.shadowsocks_config.is_some() {
                engine_config.traffic_mode = "shadowsocks".into();
            }
        }

        let stop = Arc::new(AtomicBool::new(false));
        let thread = std::thread::Builder::new()
            .name("shadowmesh-engine".into())
            .spawn(move || {
                if let Err(e) = shadowmesh_core::transport::engine::start_engine(fd, engine_config)
                {
                    tracing::error!("in-process engine exited with error: {e}");
                }
            })
            .map_err(|e| anyhow!("engine thread spawn failed: {e}"))?;

        Ok(TunnelHandle::new(
            Box::new(Self { stop, thread, dev: Mutex::new(Some(dev)) }),
            "in-process-engine".into(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn spawn(_config: VPNConfig) -> Result<TunnelHandle> {
        Err(anyhow!(
            "in-process engine is Linux-only in RFC-016 v1 (wg-quick path covers this platform)"
        ))
    }
}

#[async_trait]
impl VpnTunnel for InProcessEngineTunnel {
    fn pid(&self) -> Option<u32> {
        None // in-process: no child process
    }

    fn try_wait(&mut self) -> anyhow::Result<Option<std::process::ExitStatus>> {
        if self.thread.is_finished() {
            // Model the engine as exited once its thread is gone.
            return Ok(Some(std::process::ExitStatus::default()));
        }
        Ok(None)
    }

    async fn shutdown(&mut self) -> anyhow::Result<()> {
        self.stop.store(true, Ordering::SeqCst);
        shadowmesh_core::transport::engine::stop_engine();

        // Give the engine thread a bounded window to observe the stop and
        // stop polling the fd before the device (and its fd) is closed.
        #[cfg(target_os = "linux")]
        {
            for _ in 0..30 {
                if self.thread.is_finished() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            if let Ok(mut slot) = self.dev.lock() {
                *slot = None; // closes the TUN fd; a still-running poll sees EOF/EBADF and exits
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_nodes_use_the_in_process_engine() {
        let mut config = VPNConfig::test_fixture();
        config.reality_config = Some(shadowmesh_core::RealityConfig::new(
            "1.2.3.4".into(),
            443,
            "uuid".into(),
            "pub".into(),
            "sid".into(),
            "sni".into(),
            None,
        ));
        assert_eq!(TunnelMode::for_config(&config), TunnelMode::InProcessEngine);
    }

    #[test]
    fn shadowsocks_nodes_use_the_in_process_engine() {
        let mut config = VPNConfig::test_fixture();
        config.shadowsocks_config = Some(shadowmesh_core::ShadowsocksConfig {
            server: "1.2.3.4".into(),
            port: 8388,
            method: "aes-256-gcm".into(),
            password: "per-run".into(),
        });
        assert_eq!(TunnelMode::for_config(&config), TunnelMode::InProcessEngine);
    }

    #[test]
    fn plain_wireguard_nodes_keep_the_kernel_path() {
        let config = VPNConfig::test_fixture();
        assert_eq!(TunnelMode::for_config(&config), TunnelMode::KernelWgQuick);
    }
}
