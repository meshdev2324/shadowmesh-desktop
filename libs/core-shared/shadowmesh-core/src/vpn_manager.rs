use crate::config::UserSettings;
use crate::network::throttler::BandwidthThrottler;
use crate::transport::TransportStack;
use crate::vault::SovereigntyVault;
use crate::VPNNode;
use arc_swap::ArcSwap;
use aya::maps::HashMap;
use aya::Ebpf;
use shadowmesh_ebpf_common::RateLimitConfig;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::info;
use zeroize::{Zeroize, ZeroizeOnDrop};

use tokio::runtime::Runtime;

/// Global storage for the async runtime to avoid repeated initialization.
static RUNTIME: std::sync::OnceLock<Runtime> = std::sync::OnceLock::new();
/// Global reference to the active VPN Manager for internal engine access.
pub static GLOBAL_MANAGER: std::sync::OnceLock<Arc<VPNManager>> = std::sync::OnceLock::new();

/// Internal helper to obtain the global tokio runtime safely.
fn get_runtime() -> Result<&'static Runtime, crate::ShadowMeshError> {
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| {
            crate::ShadowMeshError::Other(format!("Failed to initialize Async Runtime: {}", e))
        })?;

    let _ = RUNTIME.set(rt);
    RUNTIME
        .get()
        .ok_or_else(|| crate::ShadowMeshError::Other("Async Runtime initialization failed".into()))
}

/// Represents the current state of the VPN connection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize)]
pub enum ConnectionStatus {
    Disconnected,
    ConnectingDirect,
    ConnectingFragmented,
    ConnectingReality,
    ConnectingWebSocket,
    ConnectingShadowsocks,
    ConnectingHysteria,
    ConnectingVmess,
    Connected,
    Degraded,
    Paused,
    Disconnecting,
    Error,
}

/// The technical protocol mode used for the VPN tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize)]
pub enum TrafficMode {
    Normal,
    Fragmented,
    Reality,
    WebSocket,
    Shadowsocks,
    Hysteria,
    Vmess,
}

/// User preference for balancing speed vs. concealment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize)]
pub enum TrafficModePreference {
    Auto,
    Speed,
    Stealth,
}

/// The strategy used for split tunneling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize)]
pub enum SplitTunnelMode {
    Include,
    Exclude,
}

/// The user's active service plan level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize)]
#[serde(rename_all = "lowercase")]
pub enum ServicePlan {
    Solo,
    Team,
    Premium,
    Family,
    Trial,
}

/// Configuration for the split tunneling feature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Zeroize)]
pub struct SplitTunnelConfig {
    #[zeroize(skip)]
    pub enabled: bool,
    pub mode: SplitTunnelMode,
    pub app_list: Vec<String>,
}

impl Default for SplitTunnelConfig {
    fn default() -> Self {
        SplitTunnelConfig { enabled: false, mode: SplitTunnelMode::Exclude, app_list: vec![] }
    }
}

/// Represents a single connection attempt to a node.
#[derive(Debug, Clone)]
pub struct ConnectionAttempt {
    pub mode: TrafficMode,
    pub start_time: Instant,
    pub timeout_ms: u64,
}

/// Statistics for the specific protocol modes used.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, Zeroize)]
pub struct ProtocolStats {
    #[zeroize(skip)]
    pub quantum_sent: u64,
    #[zeroize(skip)]
    pub quantum_received: u64,
    #[zeroize(skip)]
    pub reality_sent: u64,
    #[zeroize(skip)]
    pub reality_received: u64,
    #[zeroize(skip)]
    pub shadowsocks_sent: u64,
    #[zeroize(skip)]
    pub shadowsocks_received: u64,
    #[zeroize(skip)]
    pub hysteria_sent: u64,
    #[zeroize(skip)]
    pub hysteria_received: u64,
}

/// VMess specific configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Zeroize)]
pub struct VmessConfig {
    pub server: String,
    pub port: u32,
    pub uuid: String,
    pub security: String,
}

/// Handles for the active eBPF program and its associated resources.
#[derive(Debug)]
pub struct EbpfHandles {
    pub bpf: Ebpf,
    pub tc_link: aya::programs::links::FdLink,
}

/// Atomic version of ConnectionStats for wait-free telemetry.
#[derive(Debug, Default)]
pub struct AtomicConnectionStats {
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub last_handshake: AtomicI64,
    pub connected_since: AtomicI64,
}

impl AtomicConnectionStats {
    pub fn load(&self) -> crate::ConnectionStats {
        crate::ConnectionStats {
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            last_handshake: self.last_handshake.load(Ordering::Relaxed),
            connected_since: self.connected_since.load(Ordering::Relaxed),
        }
    }

    pub fn store(&self, stats: &crate::ConnectionStats) {
        self.bytes_received.store(stats.bytes_received, Ordering::Relaxed);
        self.bytes_sent.store(stats.bytes_sent, Ordering::Relaxed);
        self.packets_received.store(stats.packets_received, Ordering::Relaxed);
        self.packets_sent.store(stats.packets_sent, Ordering::Relaxed);
        self.last_handshake.store(stats.last_handshake, Ordering::Relaxed);
        self.connected_since.store(stats.connected_since, Ordering::Relaxed);
    }
}

/// Atomic version of ProtocolStats.
#[derive(Debug, Default)]
pub struct AtomicProtocolStats {
    pub quantum_sent: AtomicU64,
    pub quantum_received: AtomicU64,
    pub reality_sent: AtomicU64,
    pub reality_received: AtomicU64,
    pub shadowsocks_sent: AtomicU64,
    pub shadowsocks_received: AtomicU64,
    pub hysteria_sent: AtomicU64,
    pub hysteria_received: AtomicU64,
}

impl AtomicProtocolStats {
    pub fn load(&self) -> ProtocolStats {
        ProtocolStats {
            quantum_sent: self.quantum_sent.load(Ordering::Relaxed),
            quantum_received: self.quantum_received.load(Ordering::Relaxed),
            reality_sent: self.reality_sent.load(Ordering::Relaxed),
            reality_received: self.reality_received.load(Ordering::Relaxed),
            shadowsocks_sent: self.shadowsocks_sent.load(Ordering::Relaxed),
            shadowsocks_received: self.shadowsocks_received.load(Ordering::Relaxed),
            hysteria_sent: self.hysteria_sent.load(Ordering::Relaxed),
            hysteria_received: self.hysteria_received.load(Ordering::Relaxed),
        }
    }
}

/// The internal state of the `VPNManager`.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VPNManagerState {
    pub status: ConnectionStatus,
    pub selected_node: Option<VPNNode>,
    pub nodes: Vec<VPNNode>,
    #[zeroize(skip)]
    pub is_loading_nodes: bool,
    pub activation_code: Option<String>,
    pub auth_token: Option<String>,
    pub plan: ServicePlan,
    #[zeroize(skip)]
    pub devices_remaining: i32,
    #[zeroize(skip)]
    pub remaining_days: i64,
    #[zeroize(skip)]
    pub is_activated: bool,
    pub traffic_mode: TrafficMode,
    pub traffic_mode_preference: TrafficModePreference,
    #[zeroize(skip)]
    pub kill_switch_enabled: bool,
    #[zeroize(skip)]
    pub connection_attempt: Option<ConnectionAttempt>,
    #[zeroize(skip)]
    pub current_attempt: u32,
    pub split_tunnel_config: SplitTunnelConfig,
    #[zeroize(skip)]
    pub paused_until: Option<chrono::DateTime<chrono::Utc>>,
    #[zeroize(skip)]
    pub dpi_detected: bool,
    #[zeroize(skip)]
    pub frag_success_rates: std::collections::HashMap<String, f64>,
    #[zeroize(skip)]
    pub bandwidth_throttler: Arc<BandwidthThrottler>,
    #[zeroize(skip)]
    pub transport_stack: Arc<TransportStack>,
    #[zeroize(skip)]
    pub vault: Option<Arc<SovereigntyVault>>,
    #[zeroize(skip)]
    pub ebpf_active: bool,
    pub baseline_ip: Option<String>,
}

impl Default for VPNManagerState {
    fn default() -> Self {
        VPNManagerState {
            status: ConnectionStatus::Disconnected,
            selected_node: None,
            nodes: vec![],
            is_loading_nodes: false,
            activation_code: None,
            auth_token: None,
            plan: ServicePlan::Solo,
            devices_remaining: 0,
            remaining_days: 0,
            is_activated: false,
            traffic_mode: TrafficMode::Normal,
            traffic_mode_preference: TrafficModePreference::Auto,
            kill_switch_enabled: true,
            connection_attempt: None,
            current_attempt: 0,
            split_tunnel_config: SplitTunnelConfig::default(),
            paused_until: None,
            dpi_detected: false,
            frag_success_rates: std::collections::HashMap::new(),
            bandwidth_throttler: Arc::new(BandwidthThrottler::default()),
            transport_stack: Arc::new(TransportStack::default()),
            vault: None,
            ebpf_active: false,
            baseline_ip: None,
        }
    }
}

pub struct VPNManager {
    state: ArcSwap<VPNManagerState>,
    stats: AtomicConnectionStats,
    protocol_stats: AtomicProtocolStats,
    ebpf_handles: Arc<Mutex<Option<EbpfHandles>>>,
    settings: UserSettings,
}

impl VPNManager {
    pub fn new(settings: UserSettings) -> Self {
        let mut state = VPNManagerState::default();
        state.kill_switch_enabled = settings.kill_switch_enabled;
        VPNManager {
            state: ArcSwap::from_pointee(state),
            stats: AtomicConnectionStats::default(),
            protocol_stats: AtomicProtocolStats::default(),
            ebpf_handles: Arc::new(Mutex::new(None)),
            settings,
        }
    }

    pub fn activate(
        &self,
        code: String,
        token: Option<String>,
        plan: Option<String>,
        devices_remaining: i32,
        remaining_days: i64,
    ) -> Result<(), crate::ShadowMeshError> {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.activation_code = Some(code.clone());
            new_state.auth_token = token.clone();
            if let Some(ref p) = plan {
                new_state.plan = match p.to_lowercase().as_str() {
                    "team" => ServicePlan::Team,
                    "premium" => ServicePlan::Premium,
                    "family" => ServicePlan::Family,
                    "trial" => ServicePlan::Trial,
                    _ => ServicePlan::Solo,
                };
            }
            new_state.devices_remaining = devices_remaining;
            new_state.remaining_days = remaining_days;
            new_state.is_activated = true;
            new_state
        });

        self.update_throttler_settings();
        Ok(())
    }

    pub fn is_activated(&self) -> bool {
        self.state.load().is_activated
    }

    pub fn load_kernel_throttler(&self, interface: &str) -> Result<(), crate::ShadowMeshError> {
        info!("🧬 Attempting to load eBPF kernel throttler on interface: {}", interface);
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.ebpf_active = false;
            new_state
        });
        Ok(())
    }

    fn update_throttler_settings(&self) {
        let state = self.state.load();
        let mode = state.traffic_mode;
        let plan = state.plan;

        let limit = match mode {
            TrafficMode::Fragmented => match plan {
                ServicePlan::Premium | ServicePlan::Team | ServicePlan::Family => 12_500_000,
                _ => 2_621_440,
            },
            _ => 125_000_000,
        };

        state.bandwidth_throttler.set_rate_limit(limit);

        if state.ebpf_active {
            if let Ok(mut handles_guard) = self.ebpf_handles.lock() {
                if let Some(ref mut handles) = *handles_guard {
                    if let Some(map) = handles.bpf.map_mut("CONFIG") {
                        if let Ok(mut config_map) =
                            HashMap::<_, u32, RateLimitConfig>::try_from(map)
                        {
                            let config = RateLimitConfig {
                                bytes_per_second: limit as u64,
                                max_burst: limit as u64,
                                enabled: 1,
                                _padding: 0,
                            };
                            let _ = config_map.insert(0, config, 0);
                        }
                    }
                }
            }
        }
    }

    pub fn get_status(&self) -> ConnectionStatus {
        self.state.load().status.clone()
    }

    pub fn set_status(&self, status: ConnectionStatus) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.status = status.clone();
            new_state
        });
    }

    pub fn set_selected_node(&self, node: VPNNode) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.selected_node = Some(node.clone());
            new_state
        });
    }

    pub fn get_selected_node(&self) -> Option<VPNNode> {
        self.state.load().selected_node.clone()
    }

    pub fn set_nodes(&self, nodes: Vec<VPNNode>) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.nodes = nodes.clone();
            new_state
        });
    }

    pub fn set_traffic_mode(&self, mode: TrafficMode) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.traffic_mode = mode;
            new_state
        });
        self.update_throttler_settings();
    }

    pub fn get_nodes(&self) -> Vec<VPNNode> {
        self.state.load().nodes.clone()
    }

    pub fn refresh_node_latencies(&self) {
        let nodes = self.get_nodes();
        if nodes.is_empty() {
            return;
        }
        let rt = match get_runtime() {
            Ok(rt) => rt,
            Err(_) => return,
        };

        rt.block_on(async {
            let mut tasks = Vec::with_capacity(nodes.len());
            for mut node in nodes {
                tasks.push(tokio::spawn(async move {
                    let start = Instant::now();
                    let host = node.endpoint.split(':').next().unwrap_or(&node.endpoint);
                    let addr = format!("{}:443", host);
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(1500),
                        tokio::net::TcpStream::connect(&addr),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            node.latency = start.elapsed().as_millis() as u32;
                            node.is_online = true;
                        }
                        _ => {
                            node.latency = 0;
                            node.is_online = false;
                        }
                    }
                    node
                }));
            }
            let mut updated_nodes = Vec::with_capacity(tasks.len());
            for task in tasks {
                if let Ok(node) = task.await {
                    updated_nodes.push(node);
                }
            }
            self.set_nodes(updated_nodes);
        });
    }

    pub fn get_best_node(&self) -> Option<VPNNode> {
        let state = self.state.load();
        let filtered_nodes: Vec<&VPNNode> = state.nodes.iter().filter(|n| n.is_online).collect();
        if filtered_nodes.is_empty() {
            return None;
        }
        filtered_nodes
            .into_iter()
            .min_by(|a, b| {
                let frag_a = state.frag_success_rates.get(&a.id).cloned().unwrap_or(0.8);
                let frag_b = state.frag_success_rates.get(&b.id).cloned().unwrap_or(0.8);
                let score_a = crate::shadow_router::score_node(a, frag_a, 0.0, 0.5).score;
                let score_b = crate::shadow_router::score_node(b, frag_b, 0.0, 0.5).score;
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()
    }

    pub fn initiate_connection(
        &self,
        node: VPNNode,
        _device_public_key: String,
    ) -> Result<(), crate::ShadowMeshError> {
        let (mode, attempt_num) = {
            let state = self.state.load();
            let traffic_mode_pref = state.traffic_mode_preference;
            let current_attempt = state.current_attempt;
            let plan = state.plan;
            let dpi_detected = state.dpi_detected;
            let current_traffic_mode = state.traffic_mode;

            let m = if plan == ServicePlan::Team {
                if current_attempt <= 1 {
                    TrafficMode::Fragmented
                } else {
                    TrafficMode::Reality
                }
            } else if current_traffic_mode != TrafficMode::Normal {
                current_traffic_mode
            } else {
                match traffic_mode_pref {
                    TrafficModePreference::Speed => {
                        if current_attempt > 1 {
                            return Err(crate::ShadowMeshError::ConnectionFailed);
                        }
                        TrafficMode::Normal
                    }
                    TrafficModePreference::Stealth => {
                        if current_attempt <= 1 {
                            TrafficMode::Fragmented
                        } else {
                            TrafficMode::Reality
                        }
                    }
                    TrafficModePreference::Auto => {
                        let is_high_risk =
                            crate::shadow_router::preferred_mode_for_region(&node.region)
                                == TrafficMode::Fragmented;
                        if dpi_detected || is_high_risk {
                            if current_attempt <= 1 {
                                TrafficMode::Fragmented
                            } else {
                                TrafficMode::Reality
                            }
                        } else {
                            match current_attempt {
                                0 | 1 => TrafficMode::Normal,
                                2 => TrafficMode::Fragmented,
                                _ => TrafficMode::Reality,
                            }
                        }
                    }
                }
            };
            (m, if current_attempt == 0 { 1 } else { current_attempt })
        };
        self.update_throttler_settings();
        self.start_connection_with_attempt(node, mode, attempt_num)
    }

    fn start_connection_with_attempt(
        &self,
        _node: VPNNode,
        mode: TrafficMode,
        attempt_num: u32,
    ) -> Result<(), crate::ShadowMeshError> {
        self.stats.store(&crate::ConnectionStats::default());
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.status = match mode {
                TrafficMode::Normal => ConnectionStatus::ConnectingDirect,
                TrafficMode::Fragmented => ConnectionStatus::ConnectingFragmented,
                TrafficMode::Reality => ConnectionStatus::ConnectingReality,
                TrafficMode::WebSocket => ConnectionStatus::ConnectingWebSocket,
                TrafficMode::Shadowsocks => ConnectionStatus::ConnectingShadowsocks,
                TrafficMode::Hysteria => ConnectionStatus::ConnectingHysteria,
                TrafficMode::Vmess => ConnectionStatus::ConnectingVmess,
            };
            new_state.connection_attempt =
                Some(ConnectionAttempt { mode, start_time: Instant::now(), timeout_ms: 10000 });
            new_state.current_attempt = attempt_num;
            new_state
        });
        Ok(())
    }

    pub fn complete_connection(&self) {
        let now = chrono::Utc::now().timestamp();
        self.stats.connected_since.store(now, Ordering::Relaxed);
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.status = ConnectionStatus::Connected;
            new_state.connection_attempt = None;
            new_state.current_attempt = 0;
            new_state
        });
    }

    pub fn is_connection_timed_out(&self) -> bool {
        let state = self.state.load();
        if let Some(ref attempt) = state.connection_attempt {
            return attempt.start_time.elapsed().as_millis() as u64 >= attempt.timeout_ms;
        }
        false
    }

    /// Re-runs connection establishment with the escalation counter advanced.
    ///
    /// This is the public driver for multi-phase failover
    /// (Normal, then Fragmented, then REALITY): `initiate_connection` picks a
    /// mode from `current_attempt`, and each retry advances the counter so the
    /// next phase escalates. Kept separate from `initiate_connection` so
    /// automatic reconnects and operator-driven failovers are auditable as
    /// distinct state transitions.
    pub fn retry_connection(
        &self,
        node: VPNNode,
        device_public_key: String,
    ) -> Result<(), crate::ShadowMeshError> {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.current_attempt = new_state.current_attempt.saturating_add(1);
            new_state
        });
        self.initiate_connection(node, device_public_key)
    }

    pub fn get_current_connection_mode(&self) -> Option<TrafficMode> {
        self.state.load().connection_attempt.as_ref().map(|a| a.mode)
    }

    pub fn get_user_settings(&self) -> UserSettings {
        self.settings.clone()
    }

    pub fn set_kill_switch_enabled(&self, enabled: bool) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.kill_switch_enabled = enabled;
            new_state
        });
    }

    pub fn is_kill_switch_enabled(&self) -> bool {
        self.state.load().kill_switch_enabled
    }

    pub fn set_traffic_mode_preference(&self, preference: TrafficModePreference) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.traffic_mode_preference = preference;
            new_state
        });
    }

    pub fn get_traffic_mode_preference(&self) -> TrafficModePreference {
        self.state.load().traffic_mode_preference
    }

    pub fn get_stats(&self) -> crate::ConnectionStats {
        self.stats.load()
    }

    pub fn set_stats(&self, stats: crate::ConnectionStats) {
        let old_sent = self.stats.bytes_sent.load(Ordering::Relaxed);
        let old_recv = self.stats.bytes_received.load(Ordering::Relaxed);
        let sent_diff = stats.bytes_sent.saturating_sub(old_sent);
        let recv_diff = stats.bytes_received.saturating_sub(old_recv);

        let mode = self.state.load().traffic_mode;
        match mode {
            TrafficMode::Fragmented => {
                self.protocol_stats.quantum_sent.fetch_add(sent_diff, Ordering::Relaxed);
                self.protocol_stats.quantum_received.fetch_add(recv_diff, Ordering::Relaxed);
            }
            TrafficMode::Reality => {
                self.protocol_stats.reality_sent.fetch_add(sent_diff, Ordering::Relaxed);
                self.protocol_stats.reality_received.fetch_add(recv_diff, Ordering::Relaxed);
            }
            TrafficMode::Shadowsocks => {
                self.protocol_stats.shadowsocks_sent.fetch_add(sent_diff, Ordering::Relaxed);
                self.protocol_stats.shadowsocks_received.fetch_add(recv_diff, Ordering::Relaxed);
            }
            TrafficMode::Hysteria => {
                self.protocol_stats.hysteria_sent.fetch_add(sent_diff, Ordering::Relaxed);
                self.protocol_stats.hysteria_received.fetch_add(recv_diff, Ordering::Relaxed);
            }
            _ => {}
        }
        self.stats.store(&stats);
    }

    pub fn get_protocol_stats(&self) -> ProtocolStats {
        self.protocol_stats.load()
    }

    pub fn disconnect(&self) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.status = ConnectionStatus::Disconnected;
            new_state.connection_attempt = None;
            new_state.current_attempt = 0;
            new_state.paused_until = None;
            new_state
        });
    }

    pub fn pause(&self, minutes: u32) -> Result<(), crate::ShadowMeshError> {
        if !(5..=15).contains(&minutes) {
            return Err(crate::ShadowMeshError::InvalidDuration);
        }
        if !self.is_activated() {
            return Err(crate::ShadowMeshError::ConnectionFailed);
        }
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.status = ConnectionStatus::Paused;
            new_state.paused_until =
                Some(chrono::Utc::now() + chrono::Duration::minutes(minutes as i64));
            new_state
        });
        Ok(())
    }

    pub fn resume(&self) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            if new_state.status == ConnectionStatus::Paused {
                new_state.status = ConnectionStatus::Disconnected;
                new_state.paused_until = None;
            }
            new_state
        });
    }

    pub fn check_pause_expiry(&self) -> bool {
        if let Some(until) = self.state.load().paused_until {
            if chrono::Utc::now() >= until {
                self.resume();
                return true;
            }
        }
        false
    }

    pub fn get_paused_until(&self) -> Option<i64> {
        self.state.load().paused_until.map(|t| t.timestamp())
    }

    pub fn get_split_tunnel_config(&self) -> SplitTunnelConfig {
        self.state.load().split_tunnel_config.clone()
    }

    pub fn set_split_tunnel_config(&self, config: SplitTunnelConfig) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.split_tunnel_config = config.clone();
            new_state
        });
    }

    pub fn get_atomic_stats(&self) -> &AtomicConnectionStats {
        &self.stats
    }

    pub fn get_throttler(&self) -> Arc<BandwidthThrottler> {
        self.state.load().bandwidth_throttler.clone()
    }

    pub fn set_baseline_ip(&self, ip: String) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.baseline_ip = Some(ip.clone());
            new_state
        });
    }

    pub fn get_baseline_ip(&self) -> Option<String> {
        self.state.load().baseline_ip.clone()
    }

    pub fn set_dpi_detected(&self, detected: bool) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.dpi_detected = detected;
            new_state
        });
    }

    pub fn is_dpi_detected(&self) -> bool {
        self.state.load().dpi_detected
    }

    pub fn get_plan(&self) -> ServicePlan {
        self.state.load().plan
    }

    pub fn get_devices_remaining(&self) -> i32 {
        self.state.load().devices_remaining
    }

    pub fn get_remaining_days(&self) -> i64 {
        self.state.load().remaining_days
    }

    pub fn is_ebpf_active(&self) -> bool {
        self.state.load().ebpf_active
    }

    pub fn zeroize(&self) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.zeroize();
            new_state
        });
    }

    pub fn panic_wipe(&self) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.status = ConnectionStatus::Disconnected;
            new_state.zeroize();
            new_state.nodes.clear();
            new_state.selected_node = None;
            new_state
        });
    }
}

/// In-process cache of the persistent device identity. Keeps the value stable
/// for the process lifetime even when the on-disk store is unavailable.
static DEVICE_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Location of the persisted device identity, if an OS config directory exists.
fn device_id_store_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|dir| dir.join("shadowmesh").join("device_id"))
}

/// Best-effort persistence of the device identity with owner-only permissions
/// (0600 on Unix). Returns true when the file was written.
fn persist_device_id(path: &std::path::Path, id: &str) -> bool {
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return false;
        }
    }
    if std::fs::write(path, id.as_bytes()).is_err() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    true
}

/// Loads the per-install device identity, minting and persisting a fresh UUID
/// on first use. The identity is never logged; when the filesystem is
/// unavailable, the freshly minted UUID is kept as an ephemeral in-process
/// fallback rather than returning any fixed literal.
fn load_or_create_device_id() -> String {
    let store = device_id_store_path();

    // 1. Reuse the persisted identity when present and well-formed.
    if let Some(ref path) = store {
        if let Ok(raw) = std::fs::read_to_string(path) {
            if let Ok(id) = uuid::Uuid::parse_str(raw.trim()) {
                return id.to_string();
            }
        }
    }

    // 2. Mint a fresh per-install identity.
    let id = uuid::Uuid::new_v4().to_string();

    // 3. Best-effort persistence for subsequent runs.
    if let Some(ref path) = store {
        let _ = persist_device_id(path, &id);
    }

    id
}

pub fn get_persistent_device_id() -> String {
    DEVICE_ID.get_or_init(load_or_create_device_id).clone()
}
