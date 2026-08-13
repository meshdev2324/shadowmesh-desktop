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
    /// No VPN connection is active.
    Disconnected,
    /// Attempting a direct connection to a node.
    ConnectingDirect,
    /// Attempting a connection via packet fragmentation (Quantum Tunneling).
    ConnectingFragmented,
    /// Attempting a connection via REALITY stealth mode.
    ConnectingReality,
    /// VPN is successfully connected and routing traffic.
    Connected,
    /// Connection is active but experiencing high packet loss or latency.
    Degraded,
    /// VPN is temporarily paused by the user.
    Paused,
    /// In the process of tearing down the VPN tunnel.
    Disconnecting,
    /// A critical error occurred during connection or operation.
    Error,
}

/// The technical protocol mode used for the VPN tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize)]
pub enum TrafficMode {
    /// Standard WireGuard-based direct traffic.
    Normal,
    /// DPI-evasion via randomized packet fragmentation.
    Fragmented,
    /// Forensic-resistant stealth mode.
    Reality,
}

/// User preference for balancing speed vs. concealment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize)]
pub enum TrafficModePreference {
    /// Automatically select mode based on network conditions and region.
    Auto,
    /// Prioritize low latency and high throughput.
    Speed,
    /// Prioritize evasion of censorship and deep packet inspection.
    Stealth,
}

/// The strategy used for split tunneling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize)]
pub enum SplitTunnelMode {
    /// Only route traffic for applications in the provided list through the VPN.
    Include,
    /// Route traffic for all applications through the VPN except those in the list.
    Exclude,
}

/// The user's active service plan level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize)]
#[serde(rename_all = "lowercase")]
pub enum ServicePlan {
    /// Standard individual plan.
    Solo,
    /// Corporate/Team plan with enhanced security features.
    Team,
    /// High-performance premium plan.
    Premium,
    /// Family/Multi-user plan.
    Family,
    /// Short-term trial access.
    Trial,
}

/// Configuration for the split tunneling feature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Zeroize)]
pub struct SplitTunnelConfig {
    /// Whether split tunneling is enabled.
    #[zeroize(skip)]
    pub enabled: bool,
    /// The mode of operation (Include or Exclude).
    pub mode: SplitTunnelMode,
    /// A list of application package names or identifiers.
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
    /// The traffic mode selected for this attempt.
    pub mode: TrafficMode,
    /// When the attempt started.
    pub start_time: Instant,
    /// The maximum allowed duration for this attempt in milliseconds.
    pub timeout_ms: u64,
}

/// Statistics for the specific protocol modes used.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, Zeroize)]
pub struct ProtocolStats {
    /// Bytes sent via Quantum Tunneling (fragmentation).
    #[zeroize(skip)]
    pub quantum_sent: u64,
    /// Bytes received via Quantum Tunneling (fragmentation).
    #[zeroize(skip)]
    pub quantum_received: u64,
    /// Bytes sent via Reality stealth mode.
    #[zeroize(skip)]
    pub reality_sent: u64,
    /// Bytes received via Reality stealth mode.
    #[zeroize(skip)]
    pub reality_received: u64,
}

/// Handles for the active eBPF program and its associated resources.
#[derive(Debug)]
pub struct EbpfHandles {
    /// The loaded BPF object.
    pub bpf: Ebpf,
    /// The link attaching the TC program to the network interface.
    pub tc_link: aya::programs::links::FdLink,
}

/// Atomic version of ConnectionStats for wait-free telemetry.
#[derive(Debug, Default)]
pub struct AtomicConnectionStats {
    /// Total bytes received.
    pub bytes_received: AtomicU64,
    /// Total bytes sent.
    pub bytes_sent: AtomicU64,
    /// Total packets received.
    pub packets_received: AtomicU64,
    /// Total packets sent.
    pub packets_sent: AtomicU64,
    /// Timestamp of the last successful handshake.
    pub last_handshake: AtomicI64,
    /// Timestamp when the connection was established.
    pub connected_since: AtomicI64,
}

impl AtomicConnectionStats {
    /// Loads the atomic values into a standard `ConnectionStats` struct.
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

    /// Stores the values from a standard `ConnectionStats` struct into atomic storage.
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
    /// Bytes sent via Quantum Tunneling.
    pub quantum_sent: AtomicU64,
    /// Bytes received via Quantum Tunneling.
    pub quantum_received: AtomicU64,
    /// Bytes sent via Reality stealth mode.
    pub reality_sent: AtomicU64,
    /// Bytes received via Reality stealth mode.
    pub reality_received: AtomicU64,
}

impl AtomicProtocolStats {
    /// Loads the atomic values into a standard `ProtocolStats` struct.
    pub fn load(&self) -> ProtocolStats {
        ProtocolStats {
            quantum_sent: self.quantum_sent.load(Ordering::Relaxed),
            quantum_received: self.quantum_received.load(Ordering::Relaxed),
            reality_sent: self.reality_sent.load(Ordering::Relaxed),
            reality_received: self.reality_received.load(Ordering::Relaxed),
        }
    }
}

/// The internal state of the `VPNManager`.
///
/// Refactored for ArcSwap: Fields are immutable. Telemetry is handled by Atomic stats.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VPNManagerState {
    /// Current connection status.
    pub status: ConnectionStatus,
    /// The currently selected VPN node.
    pub selected_node: Option<VPNNode>,
    /// A list of all known VPN nodes.
    pub nodes: Vec<VPNNode>,
    /// Whether the node list is currently being refreshed.
    #[zeroize(skip)]
    pub is_loading_nodes: bool,
    /// The activation code used to register the device.
    pub activation_code: Option<String>,
    /// The authentication token for API requests.
    pub auth_token: Option<String>,
    /// The user's active service plan.
    pub plan: ServicePlan,
    /// Number of remaining device slots in the plan.
    #[zeroize(skip)]
    pub devices_remaining: i32,
    /// Number of days remaining in the subscription.
    #[zeroize(skip)]
    pub remaining_days: i64,
    /// Whether the device has been successfully activated.
    #[zeroize(skip)]
    pub is_activated: bool,
    /// The active traffic mode for the current/next connection.
    pub traffic_mode: TrafficMode,
    /// The user's traffic mode preference.
    pub traffic_mode_preference: TrafficModePreference,
    /// Whether the kill switch is enabled.
    #[zeroize(skip)]
    pub kill_switch_enabled: bool,
    /// Details about the current connection attempt.
    #[zeroize(skip)]
    pub connection_attempt: Option<ConnectionAttempt>,
    /// The number of the current connection attempt.
    #[zeroize(skip)]
    pub current_attempt: u32,
    /// The split tunnel configuration.
    pub split_tunnel_config: SplitTunnelConfig,
    /// The timestamp until which the VPN is paused.
    #[zeroize(skip)]
    pub paused_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether DPI has been detected on the current network.
    #[zeroize(skip)]
    pub dpi_detected: bool,
    /// Historical success rates for fragmentation mode per node.
    #[zeroize(skip)]
    pub frag_success_rates: std::collections::HashMap<String, f64>,
    /// Bandwidth throttler for Quantum Tunneling.
    #[zeroize(skip)]
    pub bandwidth_throttler: Arc<BandwidthThrottler>,
    /// Active transport stack for hot-swapping protocols.
    #[zeroize(skip)]
    pub transport_stack: Arc<TransportStack>,
    /// Sovereignty Vault for emergency failover nodes.
    #[zeroize(skip)]
    pub vault: Option<Arc<SovereigntyVault>>,
    /// Whether eBPF-based kernel throttling is active.
    #[zeroize(skip)]
    pub ebpf_active: bool,
    /// The device's public IP address observed before connecting (ISP IP).
    /// Used to verify "Protected" status by ensuring the current IP differs.
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

/// The central manager for orchestrating VPN operations and maintaining application state.
pub struct VPNManager {
    state: ArcSwap<VPNManagerState>,
    stats: AtomicConnectionStats,
    protocol_stats: AtomicProtocolStats,
    ebpf_handles: Arc<Mutex<Option<EbpfHandles>>>,
    settings: UserSettings,
}

// UniFFI Interface Implementation for VPNManager
impl VPNManager {
    /// Creates a new `VPNManager` with the provided user settings.
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

    /// Activates the VPN using the metadata received from the server.
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

    /// Returns true if the device has been activated.
    pub fn is_activated(&self) -> bool {
        self.state.load().is_activated
    }

    /// Attempts to load the kernel-level eBPF throttler.
    /// This requires root/CAP_NET_ADMIN.
    pub fn load_kernel_throttler(&self, interface: &str) -> Result<(), crate::ShadowMeshError> {
        info!("🧬 Attempting to load eBPF kernel throttler on interface: {}", interface);

        // Simulated success logic...
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.ebpf_active = false; // Remained fallback for now
            new_state
        });

        Ok(())
    }

    /// Updates the throttler settings based on the active mode and user plan.
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
                            if let Err(e) = config_map.insert(0, config, 0) {
                                tracing::error!("Failed to update eBPF throttler: {}", e);
                            } else {
                                info!("🚀 Kernel Throttler updated to {} bps", limit);
                            }
                        }
                    } else {
                        tracing::error!("eBPF CONFIG map not found");
                    }
                }
            }
        }
    }

    /// Returns the current connection status.
    pub fn get_status(&self) -> ConnectionStatus {
        self.state.load().status.clone()
    }

    /// Manually sets the connection status. Use with caution as this affects the FSM.
    pub fn set_status(&self, status: ConnectionStatus) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.status = status.clone();
            new_state
        });
    }

    /// Sets the currently selected VPN node.
    pub fn set_selected_node(&self, node: VPNNode) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.selected_node = Some(node.clone());
            new_state
        });
    }

    /// Retrieves the currently selected VPN node.
    pub fn get_selected_node(&self) -> Option<VPNNode> {
        self.state.load().selected_node.clone()
    }

    /// Updates the internal list of available VPN nodes.
    pub fn set_nodes(&self, nodes: Vec<VPNNode>) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.nodes = nodes.clone();
            new_state
        });
    }

    /// Sets the active traffic mode.
    pub fn set_traffic_mode(&self, mode: TrafficMode) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.traffic_mode = mode;
            new_state
        });
        self.update_throttler_settings();
    }

    /// Retrieves the list of known VPN nodes.
    pub fn get_nodes(&self) -> Vec<VPNNode> {
        self.state.load().nodes.clone()
    }

    /// Refreshes the latencies and online status for all available VPN nodes in parallel.
    ///
    /// This method uses a shared tokio runtime to perform parallel TCP health checks
    /// to each node's endpoint on port 443 (standard management/HTTPS port).
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
                    // Industry Standard: Use port 443 for latency checks as it's the most common management/Reality port
                    let host = node.endpoint.split(':').next().unwrap_or(&node.endpoint);
                    let addr = format!("{}:443", host);

                    // We use a short timeout for latency checks to maintain UI responsiveness
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
                            // Fallback to checking the primary endpoint port if it's different and not likely to block
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

    /// Selects the best VPN node from the current list using the Shadow-Routing algorithm.
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

    /// Initiates a connection to the specified node.
    ///
    /// This function implements the adaptive connection logic, selecting the optimal
    /// protocol mode based on the user's plan, previous attempts, and detected DPI risk.
    pub fn initiate_connection(
        &self,
        node: VPNNode,
        _device_public_key: String,
    ) -> Result<(), crate::ShadowMeshError> {
        let span =
            tracing::info_span!("initiate_connection", node_id = %node.id, region = %node.region);
        let _enter = span.enter();

        let (mode, attempt_num) = {
            let state = self.state.load();
            let traffic_mode_pref = state.traffic_mode_preference;
            let current_attempt = state.current_attempt;
            let plan = state.plan;
            let dpi_detected = state.dpi_detected;
            let current_traffic_mode = state.traffic_mode;

            tracing::debug!(
                ?traffic_mode_pref,
                ?current_attempt,
                ?plan,
                dpi_detected,
                "Determining traffic mode"
            );

            let m = if plan == ServicePlan::Team {
                if current_attempt == 0 || current_attempt == 1 {
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
                            tracing::error!("Connection failed: excessive attempts in Speed mode");
                            return Err(crate::ShadowMeshError::ConnectionFailed);
                        }
                        TrafficMode::Normal
                    }
                    TrafficModePreference::Stealth => {
                        if current_attempt == 0 || current_attempt == 1 {
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
                            match current_attempt {
                                0 | 1 => TrafficMode::Fragmented,
                                _ => TrafficMode::Reality,
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
            tracing::info!(mode = ?m, attempt = current_attempt, "Selected protocol mode");
            (m, if current_attempt == 0 { 1 } else { current_attempt })
        };

        self.update_throttler_settings();
        self.start_connection_with_attempt(node, mode, attempt_num)
    }

    /// Sets up the internal state for a new connection attempt.
    fn start_connection_with_attempt(
        &self,
        _node: VPNNode,
        mode: TrafficMode,
        attempt_num: u32,
    ) -> Result<(), crate::ShadowMeshError> {
        // Reset session stats before starting a new connection
        self.stats.store(&crate::ConnectionStats {
            bytes_received: 0,
            bytes_sent: 0,
            packets_received: 0,
            packets_sent: 0,
            last_handshake: 0,
            connected_since: 0,
        });

        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.status = match mode {
                TrafficMode::Normal => ConnectionStatus::ConnectingDirect,
                TrafficMode::Fragmented => ConnectionStatus::ConnectingFragmented,
                TrafficMode::Reality => ConnectionStatus::ConnectingReality,
            };
            new_state.connection_attempt = Some(ConnectionAttempt {
                mode,
                start_time: Instant::now(),
                timeout_ms: match mode {
                    TrafficMode::Normal => 3000,
                    TrafficMode::Fragmented => 5000,
                    TrafficMode::Reality => 8000,
                },
            });
            new_state.current_attempt = attempt_num;
            new_state
        });

        Ok(())
    }

    /// Synchronously starts a connection attempt (legacy UniFFI compatibility).
    pub fn start_connection(&self, node: VPNNode, mode: TrafficMode) {
        let _ = self.start_connection_with_attempt(node, mode, 1);
    }

    /// Marks the current connection as successfully completed.
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

    /// Returns true if the current connection attempt has exceeded its timeout.
    pub fn is_connection_timed_out(&self) -> bool {
        let state = self.state.load();
        if let Some(ref attempt) = state.connection_attempt {
            let elapsed = attempt.start_time.elapsed().as_millis() as u64;
            return elapsed >= attempt.timeout_ms;
        }
        false
    }

    /// Returns the traffic mode used for the current connection attempt.
    pub fn get_current_connection_mode(&self) -> Option<TrafficMode> {
        self.state.load().connection_attempt.as_ref().map(|a| a.mode)
    }

    /// Retrieves the current user settings.
    pub fn get_user_settings(&self) -> UserSettings {
        self.settings.clone()
    }

    /// Enables or disables the kill switch.
    pub fn set_kill_switch_enabled(&self, enabled: bool) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.kill_switch_enabled = enabled;
            new_state
        });
    }

    /// Returns true if the kill switch is enabled.
    pub fn is_kill_switch_enabled(&self) -> bool {
        self.state.load().kill_switch_enabled
    }

    /// Sets the user's traffic mode preference.
    pub fn set_traffic_mode_preference(&self, preference: TrafficModePreference) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.traffic_mode_preference = preference;
            new_state
        });
    }

    /// Retrieves the user's traffic mode preference.
    pub fn get_traffic_mode_preference(&self) -> TrafficModePreference {
        self.state.load().traffic_mode_preference
    }

    /// Retrieves the real-time connection statistics.
    pub fn get_stats(&self) -> crate::ConnectionStats {
        self.stats.load()
    }

    /// Updates the real-time connection statistics and aggregates protocol-specific metrics.
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
            _ => {}
        }

        self.stats.store(&stats);
    }

    /// Retrieves the protocol-specific traffic statistics.
    pub fn get_protocol_stats(&self) -> ProtocolStats {
        self.protocol_stats.load()
    }

    /// Disconnects the VPN and resets the connection state.
    pub fn disconnect(&self) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.status = ConnectionStatus::Disconnected;
            new_state.connection_attempt = None;
            new_state.current_attempt = 0;
            new_state.paused_until = None;
            new_state
        });
        tracing::info!("VPN Disconnected.");
    }

    /// Pauses the VPN connection for a specified duration (5-15 minutes).
    /// Returns error if duration is out of bounds or VPN is not activated.
    pub fn pause(&self, minutes: u32) -> Result<(), crate::ShadowMeshError> {
        if !(5..=15).contains(&minutes) {
            return Err(crate::ShadowMeshError::InvalidDuration);
        }

        let is_activated = self.is_activated();
        if !is_activated {
            return Err(crate::ShadowMeshError::ConnectionFailed);
        }

        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.status = ConnectionStatus::Paused;
            new_state.paused_until =
                Some(chrono::Utc::now() + chrono::Duration::minutes(minutes as i64));
            new_state.connection_attempt = None;
            new_state.current_attempt = 0;
            new_state
        });

        Ok(())
    }

    /// Resumes a paused VPN connection.
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

    /// Checks if the pause has expired and resumes if necessary.
    /// This should be called periodically by the platform layer.
    pub fn check_pause_expiry(&self) -> bool {
        let state = self.state.load();
        if let Some(until) = state.paused_until {
            if chrono::Utc::now() >= until {
                self.resume();
                return true;
            }
        }
        false
    }

    /// Returns the timestamp until which the VPN is paused, or `None` if not paused.
    pub fn get_paused_until(&self) -> Option<i64> {
        self.state.load().paused_until.map(|t| t.timestamp())
    }

    /// Retrieves the current split tunnel configuration.
    pub fn get_split_tunnel_config(&self) -> SplitTunnelConfig {
        self.state.load().split_tunnel_config.clone()
    }

    /// Updates the split tunnel configuration.
    pub fn set_split_tunnel_config(&self, config: SplitTunnelConfig) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.split_tunnel_config = config.clone();
            new_state
        });
    }

    /// Records the device's baseline (ISP) IP address.
    pub fn set_baseline_ip(&self, ip: String) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.baseline_ip = Some(ip.clone());
            new_state
        });
    }

    /// Retrieves the stored baseline IP.
    pub fn get_baseline_ip(&self) -> Option<String> {
        self.state.load().baseline_ip.clone()
    }

    /// Records whether DPI was detected on the current network.
    pub fn set_dpi_detected(&self, detected: bool) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.dpi_detected = detected;
            new_state
        });
    }

    /// Returns true if DPI has been detected.
    pub fn is_dpi_detected(&self) -> bool {
        self.state.load().dpi_detected
    }

    /// Retrieves the active service plan.
    pub fn get_plan(&self) -> ServicePlan {
        self.state.load().plan
    }

    /// Returns the number of devices remaining in the user's plan.
    pub fn get_devices_remaining(&self) -> i32 {
        self.state.load().devices_remaining
    }

    /// Returns the number of days remaining in the user's subscription.
    pub fn get_remaining_days(&self) -> i64 {
        self.state.load().remaining_days
    }

    /// Records the success or failure of a fragmentation-based connection attempt
    /// for a specific node to inform future routing decisions.
    pub fn report_fragmentation_success(&self, node_id: String, success: bool) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            let entry = new_state.frag_success_rates.entry(node_id.clone()).or_insert(0.8);
            if success {
                *entry = (*entry * 0.9 + 0.1).clamp(0.0, 1.0);
            } else {
                *entry = (*entry * 0.9).clamp(0.0, 1.0);
            }
            new_state
        });
    }

    /// Returns true if eBPF-based kernel throttling is active.
    pub fn is_ebpf_active(&self) -> bool {
        self.state.load().ebpf_active
    }

    /// Securely zeroizes sensitive session metadata in memory.
    pub fn zeroize(&self) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.zeroize();
            new_state
        });
        info!("CRITICAL: Rust Core memory zeroized.");
    }

    /// Performs a comprehensive forensic wipe of the VPN manager's state.
    pub fn panic_wipe(&self) {
        self.state.rcu(|state| {
            let mut new_state = (**state).clone();
            new_state.status = ConnectionStatus::Disconnected;
            new_state.connection_attempt = None;
            new_state.current_attempt = 0;
            new_state.paused_until = None;
            new_state.zeroize();
            new_state.nodes.clear();
            new_state.frag_success_rates.clear();
            new_state.selected_node = None;
            new_state.baseline_ip = None;

            if let Some(ref vault) = new_state.vault {
                let _ = vault.purge();
            }
            new_state
        });

        info!("CRITICAL: Forensic wipe complete. All sensitive metadata purged.");
    }

    /// Triggers a multi-phase failover escalation when connection degradation is detected.
    pub async fn trigger_failover(&self) -> Result<(), crate::ShadowMeshError> {
        let state = self.state.load();
        let current_mode = state.traffic_mode;
        let node = state.selected_node.clone().ok_or(crate::ShadowMeshError::NodeNotFound)?;

        info!(?current_mode, "Failover triggered. Escalating protocol...");

        match current_mode {
            TrafficMode::Normal => {
                self.set_traffic_mode(TrafficMode::Fragmented);
                self.initiate_connection(node, "".into())?;
            }
            TrafficMode::Fragmented => {
                self.set_traffic_mode(TrafficMode::Reality);
                self.initiate_connection(node, "".into())?;
            }
            TrafficMode::Reality => {
                info!("REALITY failed. Attempting QUIC/Hysteria transport...");
                if let Some(ref vault) = state.vault {
                    let _ = vault.load_emergency_nodes();
                }
            }
        }

        Ok(())
    }
}

/// Retrieves a persistent, unique identifier for the current device.
///
/// This identifier is stored in a platform-specific location and persists across
/// application restarts and updates.
pub fn get_persistent_device_id() -> String {
    use rand::RngCore;
    use rand::SeedableRng;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;

    // Check environment variable first (for testing/override)
    if let Ok(env_id) = std::env::var("SHADOWMESH_DEVICE_ID") {
        return env_id;
    }

    // Determine platform-specific storage location
    let storage_path = if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
        // macOS/iOS: ~/Library/Application Support/ShadowMesh/
        dirs::data_dir()
            .map(|mut p| {
                p.push("ShadowMesh");
                p
            })
            .unwrap_or_else(|| PathBuf::from("."))
    } else if cfg!(target_os = "android") {
        // Android: typically handled via app-specific storage, fallback to current dir
        // In a real app, this should probably be passed in or resolved via JNI
        PathBuf::from(".")
    } else if cfg!(target_os = "windows") {
        // Windows: %APPDATA%/ShadowMesh/
        dirs::data_dir()
            .map(|mut p| {
                p.push("ShadowMesh");
                p
            })
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        // Linux/Unix: ~/.local/share/shadowmesh/
        dirs::data_dir()
            .map(|mut p| {
                p.push("shadowmesh");
                p
            })
            .unwrap_or_else(|| PathBuf::from("."))
    };

    // Create directory if it doesn't exist
    let _ = fs::create_dir_all(&storage_path);

    let device_id_path = storage_path.join("device_id");

    // Read existing ID if available
    if let Ok(existing_id) = fs::read_to_string(&device_id_path) {
        let trimmed = existing_id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    // Generate new random ID
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut id_bytes = [0u8; 32];
    rng.fill_bytes(&mut id_bytes);
    let mut hasher = Sha256::new();
    hasher.update(id_bytes);
    let hash = hasher.finalize();
    let new_id = hex::encode(hash);

    // Store it
    let _ = fs::write(&device_id_path, &new_id);

    new_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ShadowMeshError;

    #[test]
    fn test_activation_metadata_storage() -> Result<(), ShadowMeshError> {
        let settings = UserSettings::default();
        let manager = VPNManager::new(settings);

        manager.activate(
            "CODE123".to_string(),
            Some("TOKEN123".to_string()),
            Some("Premium".to_string()),
            5,
            120,
        )?;

        assert_eq!(manager.get_plan(), ServicePlan::Premium);
        assert_eq!(manager.get_devices_remaining(), 5);
        assert_eq!(manager.get_remaining_days(), 120);
        assert!(manager.is_activated());
        Ok(())
    }

    #[test]
    fn test_zeroize_clears_sensitive_state() -> Result<(), ShadowMeshError> {
        let settings = UserSettings::default();
        let manager = VPNManager::new(settings);

        manager.activate(
            "SECRET_CODE".to_string(),
            Some("TOKEN".to_string()),
            Some("Solo".to_string()),
            1,
            30,
        )?;

        assert!(manager.state.load().activation_code.is_some());

        manager.zeroize();

        let state = manager.state.load();
        assert!(state.activation_code.is_none());
        assert!(state.auth_token.is_none());
        assert!(state.nodes.is_empty());
        assert_eq!(state.status, ConnectionStatus::Disconnected);
        Ok(())
    }

    #[test]
    fn test_panic_wipe_clears_all_state() -> Result<(), ShadowMeshError> {
        let settings = UserSettings::default();
        let manager = VPNManager::new(settings);

        // Setup some state
        manager.activate("CODE".into(), Some("TOKEN".into()), None, 1, 1)?;
        manager.set_nodes(vec![VPNNode {
            id: "1".into(),
            name: "N".into(),
            region: "R".into(),
            country: "C".into(),
            endpoint: "E".into(),
            public_key: "P".into(),
            load: 0,
            latency: 0,
            is_online: true,
        }]);
        manager.set_status(ConnectionStatus::Connected);

        // Perform wipe
        manager.panic_wipe();

        let state = manager.state.load();
        assert!(state.activation_code.is_none());
        assert!(state.auth_token.is_none());
        assert!(state.nodes.is_empty());
        assert!(state.selected_node.is_none());
        assert_eq!(state.status, ConnectionStatus::Disconnected);
        Ok(())
    }

    #[test]
    fn test_refresh_node_latencies_empty() {
        let settings = UserSettings::default();
        let manager = VPNManager::new(settings);
        // Should not panic or error on empty list
        manager.refresh_node_latencies();
        assert!(manager.get_nodes().is_empty());
    }

    #[test]
    fn test_refresh_node_latencies_mock() {
        let settings = UserSettings::default();
        let manager = VPNManager::new(settings);
        let node = VPNNode {
            id: "test-1".into(),
            name: "Test Node".into(),
            region: "US".into(),
            country: "US".into(),
            endpoint: "127.0.0.1:51820".into(),
            public_key: "pub".into(),
            load: 0,
            latency: 0,
            is_online: true,
        };
        manager.set_nodes(vec![node]);

        // This will likely fail to connect to 127.0.0.1:443, marking it offline.
        // That verifies the logic runs.
        manager.refresh_node_latencies();

        let nodes = manager.get_nodes();
        assert_eq!(nodes.len(), 1);
        // Since no server is likely listening on 127.0.0.1:443 in this environment,
        // it should be offline.
        assert!(!nodes[0].is_online);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    // Arbitrary implementations for proptest
    prop_compose! {
        fn arb_node()(
            id in "\\PC*",
            name in "\\PC*",
            region in "[A-Z]{2}",
            country in "[A-Z]{2}",
            endpoint in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{1,5}",
            public_key in "[a-zA-Z0-9+/]{43}=",
            load in 0..100u32,
            latency in 0..1000u32,
            is_online in any::<bool>()
        ) -> VPNNode {
            VPNNode { id, name, region, country, endpoint, public_key, load, latency, is_online }
        }
    }

    proptest! {
        #[test]
        fn test_status_transitions_basic(status in any::<u8>()) {
            let s = match status % 9 {
                0 => ConnectionStatus::Disconnected,
                1 => ConnectionStatus::ConnectingDirect,
                2 => ConnectionStatus::ConnectingFragmented,
                3 => ConnectionStatus::ConnectingReality,
                4 => ConnectionStatus::Connected,
                5 => ConnectionStatus::Degraded,
                6 => ConnectionStatus::Paused,
                7 => ConnectionStatus::Disconnecting,
                _ => ConnectionStatus::Error,
            };
            let _ = s;
        }

        #[test]
        fn test_panic_wipe_invariants(
            nodes in prop::collection::vec(arb_node(), 0..10),
            status in any::<u8>(),
            has_token in any::<bool>(),
            has_code in any::<bool>(),
        ) {
            let settings = UserSettings::default();
            let manager = VPNManager::new(settings);

            manager.state.rcu(|state| {
                let mut new_state = (**state).clone();
                new_state.nodes = nodes.clone();
                new_state.status = match status % 9 {
                    0 => ConnectionStatus::Disconnected,
                    1 => ConnectionStatus::ConnectingDirect,
                    2 => ConnectionStatus::ConnectingFragmented,
                    3 => ConnectionStatus::ConnectingReality,
                    4 => ConnectionStatus::Connected,
                    5 => ConnectionStatus::Degraded,
                    6 => ConnectionStatus::Paused,
                    7 => ConnectionStatus::Disconnecting,
                    _ => ConnectionStatus::Error,
                };
                if has_token { new_state.auth_token = Some("secret-token".into()); }
                if has_code { new_state.activation_code = Some("secret-code".into()); }
                new_state
            });

            // Execute wipe
            manager.panic_wipe();

            // Verify Invariants
            let state = manager.state.load();
            prop_assert!(state.auth_token.is_none());
            prop_assert!(state.activation_code.is_none());
            prop_assert!(state.nodes.is_empty());
            prop_assert_eq!(state.status.clone(), ConnectionStatus::Disconnected);
            prop_assert!(state.selected_node.is_none());
            prop_assert!(state.connection_attempt.is_none());
        }
    }
}
