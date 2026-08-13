//! ShadowMesh Client Core
//!
//! A high-performance, security-focused VPN library written in Rust.
//! It serves as the cross-platform engine for both Mobile (Android/iOS) and Desktop clients.
//!
//! ### Full-Stack Control Plane Mapping (`server-rust`)
//! - [`ApiClient::activate_device`](crate::api_client::ApiClient::activate_device) -> `POST /api/v1/auth/activate`
//! - [`ApiClient::send_heartbeat`](crate::api_client::ApiClient::send_heartbeat) -> `POST /api/v1/session/heartbeat`
//! - [`ApiClient::fetch_nodes`](crate::api_client::ApiClient::fetch_nodes) -> `GET /api/v1/nodes`
//! - [`ApiClient::report_network`](crate::api_client::ApiClient::report_network) -> `POST /api/v1/telemetry/report`

#![allow(clippy::empty_line_after_doc_comments)]
#![deny(missing_docs)]
#![forbid(unsafe_op_in_unsafe_fn)]

use std::sync::Arc;
use zeroize::Zeroize;

// --- Global Allocator Configuration ---
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
// ---------------------------------------

/// Anti-tampering and signature verification components.
pub mod anti_tamper;
/// API client for interacting with the ShadowMesh control plane.
pub mod api_client;
/// User and system configuration management.
pub mod config;
/// Packet fragmentation and DPI evasion logic.
pub mod fragment;
/// System-level kill-switch management.
pub mod kill_switch;
/// Networking utilities and detector.
pub mod network;
/// Secure in-memory node caching.
pub mod node_cache;
/// Proof-of-Work (PoW) solver for adaptive friction.
pub mod pow;
/// Internal protocol definitions.
pub mod protocol;
/// REALITY protocol and cryptographic pairing routines.
pub mod reality;
/// Secure forensic-resistant logging.
pub mod security_logger;
/// Smart routing and node selection algorithm.
pub mod shadow_router;
/// Network speed testing infrastructure.
pub mod speed_test;
/// Traffic mode and preference management.
pub mod traffic_modes;
/// Network transport implementations.
pub mod transport;
/// Sovereignty Vault for resilient failover.
pub mod vault;
/// Core VPN lifecycle and state management.
pub mod vpn_manager;

pub use crate::anti_tamper::{AntiTamperChecker, AntiTamperConfig};
pub use crate::api_client::{
    ActivationChallenge, ActivationRequest, ActivationResponse, ApiClient, ApiErrorResponse,
    HealthStatus, HeartbeatRequest, HeartbeatResponse, IdentityInfo, ServerNetworkReport,
};
pub use crate::config::UserSettings;
pub use crate::kill_switch::{KillSwitchEvent, KillSwitchManager, KillSwitchState};
pub use crate::network::detector::{NetworkDetector, NetworkReport, NetworkType};
pub use crate::network::leak_guard::{LeakGuard, SecurityEnforcer};
pub use crate::network::throttler::BandwidthThrottler;
pub use crate::node_cache::NodeCache;
pub use crate::security_logger::{
    scrub_pii, SecurityEvent, SecurityEventLogger, SecurityEventType,
};
pub use crate::speed_test::{SpeedTest, SpeedTestResult};
pub use crate::traffic_modes::{TrafficAnalytics, TrafficPreferences};
pub use crate::vpn_manager::{
    get_persistent_device_id, ConnectionStatus, ProtocolStats, ServicePlan, SplitTunnelConfig,
    SplitTunnelMode, TrafficMode, TrafficModePreference, VPNManager,
};

pub use crate::reality::{
    compute_dh_public_key, compute_dh_shared_secret, derive_session_token, generate_dh_private_key,
    generate_short_id as generate_reality_short_id,
};

/// Parse a VLESS+REALITY URI string into a `RealityConfig`.
pub fn parse_reality_vless_uri(uri: String) -> Option<RealityConfig> {
    RealityConfig::from_vless_uri(&uri)
}

/// Normalizes an activation code by removing dashes and converting to uppercase.
pub fn normalize_activation_code(raw: String) -> Option<String> {
    let normalized = raw.replace('-', "").to_uppercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// Returns the default user settings.
pub fn get_default_user_settings() -> UserSettings {
    UserSettings::default()
}

/// Creates a new security logger.
pub fn create_security_logger(
    device_id: String,
    app_version: String,
    storage_dir: String,
) -> Result<Arc<SecurityEventLogger>, ShadowMeshError> {
    SecurityEventLogger::new(device_id, app_version, storage_dir).map(Arc::new)
}

/// Creates a new VPN manager.
pub fn create_vpn_manager(settings: UserSettings) -> Result<Arc<VPNManager>, ShadowMeshError> {
    Ok(Arc::new(VPNManager::new(settings)))
}

/// Creates a new API client.
pub fn create_api_client(base_url: String) -> Result<Arc<ApiClient>, ShadowMeshError> {
    Ok(Arc::new(ApiClient::new(base_url)?))
}

/// Creates a new API client with certificate pins.
pub fn create_api_client_with_pins(
    base_url: String,
    pinned_hashes: Vec<String>,
) -> Result<Arc<ApiClient>, ShadowMeshError> {
    Ok(Arc::new(ApiClient::with_pins(base_url, pinned_hashes)?))
}

/// Creates a new node cache.
pub fn create_node_cache(
    max_size: u32,
    ttl_seconds: u32,
) -> Result<Arc<NodeCache>, ShadowMeshError> {
    Ok(Arc::new(NodeCache::new(max_size as usize, ttl_seconds as u64)))
}

/// Creates a new kill switch manager.
pub fn create_kill_switch_manager() -> Result<Arc<KillSwitchManager>, ShadowMeshError> {
    Ok(Arc::new(KillSwitchManager::new()))
}

/// Creates a new speed test.
pub fn create_speed_test(api_client: Arc<ApiClient>) -> Arc<SpeedTest> {
    Arc::new(SpeedTest::new(api_client))
}

/// Creates a new network detector.
pub fn create_network_detector(
    api_client: Arc<ApiClient>,
    manager: Option<Arc<VPNManager>>,
) -> Arc<NetworkDetector> {
    Arc::new(NetworkDetector::new(api_client, manager))
}

/// Creates a new traffic analytics instance.
pub fn create_traffic_analytics(
) -> Result<Arc<crate::traffic_modes::TrafficAnalytics>, ShadowMeshError> {
    Ok(Arc::new(crate::traffic_modes::TrafficAnalytics::default()))
}

/// Creates default traffic preferences.
pub fn create_traffic_preferences() -> TrafficPreferences {
    TrafficPreferences {
        data_limit_mb: None,
        prioritize_wifi: true,
        restrict_background_data: false,
        mode_preference: TrafficModePreference::Auto,
    }
}

/// Returns a set of mock nodes for testing.
pub fn get_mock_nodes() -> Vec<VPNNode> {
    vec![VPNNode {
        id: "mock-1".into(),
        name: "Mock Node 1".into(),
        region: "US".into(),
        country: "US".into(),
        endpoint: "1.1.1.1:51820".into(),
        public_key: "mock-pub-key-1".into(),
        load: 10,
        latency: 50,
        is_online: true,
    }]
}

/// Placeholder for decrypting QR pairing payload.
pub fn decrypt_qr_pairing_payload(ciphertext: Vec<u8>, pin: String) -> Vec<u8> {
    crate::reality::decrypt_qr_payload(&ciphertext, &pin)
}

/// Placeholder for encrypting QR pairing payload.
pub fn encrypt_qr_pairing_payload(plaintext: Vec<u8>, pin: String) -> Vec<u8> {
    crate::reality::encrypt_qr_payload(&plaintext, &pin)
}

/// Selects the best VPN node.
pub fn shadow_route_best_node(nodes: Vec<VPNNode>) -> Option<VPNNode> {
    crate::shadow_router::shadow_route_best_node(&nodes).cloned()
}

/// Returns the preferred traffic mode for a region.
pub fn preferred_traffic_mode_for_region(region_code: String) -> String {
    format!("{:?}", crate::shadow_router::preferred_mode_for_region(&region_code))
}

/// Returns the MTU for Quantum Tunneling.
pub fn get_quantum_mtu() -> u32 {
    576
}

/// Returns the TCP MSS for Quantum Tunneling.
pub fn get_quantum_tcp_mss() -> u32 {
    536
}

uniffi::include_scaffolding!("shadowmesh");

/// Core error types for the ShadowMesh library.
/// Automatically scrubs PII in Display implementation to prevent leaks in logs.
#[derive(Debug, thiserror::Error)]
pub enum ShadowMeshError {
    /// Adaptive friction (PoW) is required by the server.
    AdaptiveFrictionRequired(String),
    /// Failed to generate cryptographic keys.
    KeyGenerationFailed,
    /// PoW solver timed out.
    PowTimeout,
    /// Connection initiation failed.
    ConnectionFailed,
    /// Authentication failure.
    Unauthorized(String),
    /// Access to the resource is forbidden.
    Forbidden(String),
    /// The current session has been frozen by an administrator.
    SessionFrozen,
    /// The requested resource was not found.
    NotFound(String),
    /// The server is currently overloaded.
    TooManyRequests(String),
    /// The specified node was not found.
    NodeNotFound,
    /// A system IO error occurred.
    IoError(String),
    /// Failed to parse or serialize JSON.
    JsonError(String),
    /// An invalid duration was provided.
    InvalidDuration,
    /// An internal server error occurred.
    ServerError(String),
    /// Kernel-level socket tuning failed.
    SocketTuningFailed,
    /// DNS resolution failed.
    DnsResolutionError,
    /// An unspecified error occurred.
    Other(String),
    /// Error from the shared common crate.
    Common(String),
}

impl std::fmt::Display for ShadowMeshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            ShadowMeshError::AdaptiveFrictionRequired(s) => {
                format!("Adaptive friction (PoW) required: {}", s)
            }
            ShadowMeshError::KeyGenerationFailed => "Key generation failed".to_string(),
            ShadowMeshError::PowTimeout => "PoW solving timed out".to_string(),
            ShadowMeshError::ConnectionFailed => "Connection failed".to_string(),
            ShadowMeshError::Unauthorized(s) => format!("Authentication failed: {}", s),
            ShadowMeshError::Forbidden(s) => format!("Forbidden: {}", s),
            ShadowMeshError::SessionFrozen => "Session frozen by admin".to_string(),
            ShadowMeshError::NotFound(s) => format!("Resource not found: {}", s),
            ShadowMeshError::TooManyRequests(s) => format!("Server overloaded: {}", s),
            ShadowMeshError::NodeNotFound => "Node not found".to_string(),
            ShadowMeshError::IoError(s) => format!("IO error: {}", s),
            ShadowMeshError::JsonError(s) => format!("JSON error: {}", s),
            ShadowMeshError::InvalidDuration => "Invalid duration".to_string(),
            ShadowMeshError::ServerError(s) => format!("Internal server error: {}", s),
            ShadowMeshError::SocketTuningFailed => "Socket tuning failed".to_string(),
            ShadowMeshError::DnsResolutionError => "DNS resolution error".to_string(),
            ShadowMeshError::Other(s) => format!("Other error: {}", s),
            ShadowMeshError::Common(s) => format!("Common error: {}", s),
        };
        write!(f, "{}", scrub_pii(&msg))
    }
}

impl From<shadowmesh_common::CommonError> for ShadowMeshError {
    fn from(err: shadowmesh_common::CommonError) -> Self {
        ShadowMeshError::Common(err.to_string())
    }
}

impl From<std::io::Error> for ShadowMeshError {
    fn from(err: std::io::Error) -> Self {
        ShadowMeshError::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for ShadowMeshError {
    fn from(err: serde_json::Error) -> Self {
        ShadowMeshError::JsonError(err.to_string())
    }
}

impl From<reqwest::Error> for ShadowMeshError {
    fn from(err: reqwest::Error) -> Self {
        ShadowMeshError::Other(err.to_string())
    }
}

/// Represents a VPN node in the ShadowMesh network.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Zeroize)]
pub struct VPNNode {
    /// Unique identifier for the node.
    pub id: String,
    /// Display name of the node.
    pub name: String,
    /// Region where the node is located.
    pub region: String,
    /// ISO country code.
    pub country: String,
    /// Network endpoint (IP:Port).
    pub endpoint: String,
    /// Node's WireGuard public key.
    pub public_key: String,
    /// Current server load (0-100).
    pub load: u32,
    /// Measured latency in milliseconds.
    #[zeroize(skip)]
    pub latency: u32,
    /// Whether the node is currently reachable.
    #[serde(default)]
    #[zeroize(skip)]
    pub is_online: bool,
}

/// Final WireGuard configuration for the tunnel.
#[derive(Clone, serde::Serialize, serde::Deserialize, Zeroize)]
pub struct VPNConfig {
    /// Local private key (optional if managed externally).
    pub private_key: Option<String>,
    /// Server's public key.
    #[serde(rename = "server_public_key")]
    pub public_key: String,
    /// Local IP address assigned to the tunnel.
    #[serde(rename = "assigned_ip")]
    pub address: String,
    /// Server's endpoint address.
    pub endpoint: String,
    /// DNS server addresses.
    pub dns: String,
    /// Maximum Transmission Unit (MTU).
    #[zeroize(skip)]
    pub mtu: u32,
    /// Current traffic mode (e.g., "normal", "fragmented").
    pub traffic_mode: String,
    /// REALITY protocol configuration (if applicable).
    pub reality_config: Option<RealityConfig>,
}

/// Configuration for the VLESS+REALITY protocol extension.
#[derive(Clone, serde::Serialize, serde::Deserialize, Zeroize)]
pub struct RealityConfig {
    /// IP address of the REALITY gateway.
    pub server_ip: String,
    /// Port of the REALITY gateway.
    #[zeroize(skip)]
    pub port: u32,
    /// UUID for VLESS authentication.
    pub uuid: String,
    /// REALITY public key.
    pub public_key: String,
    /// REALITY short ID.
    pub short_id: String,
    /// SNI target used for masquerading.
    pub sni_target: String,
    /// Browser fingerprint to emulate (optional).
    pub fingerprint: Option<String>,
}

impl std::fmt::Debug for VPNConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VPNConfig")
            .field("private_key", &self.private_key.as_ref().map(|_| "[REDACTED]"))
            .field("public_key", &self.public_key)
            .field("address", &self.address)
            .field("endpoint", &self.endpoint)
            .field("dns", &self.dns)
            .field("mtu", &self.mtu)
            .field("traffic_mode", &self.traffic_mode)
            .field("reality_config", &self.reality_config)
            .finish()
    }
}

impl std::fmt::Debug for RealityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityConfig")
            .field("server_ip", &self.server_ip)
            .field("port", &self.port)
            .field("uuid", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .field("short_id", &self.short_id)
            .field("sni_target", &self.sni_target)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

/// Tunnel connection statistics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Zeroize)]
pub struct ConnectionStats {
    /// Total bytes received.
    #[zeroize(skip)]
    pub bytes_received: u64,
    /// Total bytes sent.
    #[zeroize(skip)]
    pub bytes_sent: u64,
    /// Total packets received.
    #[zeroize(skip)]
    pub packets_received: u64,
    /// Total packets sent.
    #[zeroize(skip)]
    pub packets_sent: u64,
    /// Timestamp of the last successful handshake.
    #[zeroize(skip)]
    pub last_handshake: i64,
    /// Timestamp when the connection was established.
    #[zeroize(skip)]
    pub connected_since: i64,
}

/// A Proof-of-Work challenge issued by the server.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PoWChallenge {
    /// The raw challenge string.
    pub challenge: String,
    /// The required number of leading zero bits.
    pub difficulty: u32,
}

/// A solved Proof-of-Work solution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PoWSolution {
    /// The original challenge string.
    pub challenge: String,
    /// The solution string found by the solver.
    pub solution: String,
}

/// Solves a Proof-of-Work challenge using the optimized bit-check algorithm.
/// Returns a solution that the server can verify to grant access to protected endpoints.
pub fn solve_pow(challenge: PoWChallenge) -> Result<PoWSolution, ShadowMeshError> {
    let (challenge_out, solution) =
        crate::pow::solve_pow(challenge.challenge.clone(), challenge.difficulty)?;
    Ok(PoWSolution { challenge: challenge_out, solution })
}

/// Generates a new X25519 keypair for WireGuard tunnels.
/// Returns a vector where \[0\] is the base64 PrivateKey and \[1\] is the base64 PublicKey.
pub fn generate_wireguard_keys() -> Result<Vec<String>, ShadowMeshError> {
    use base64::prelude::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);

    let private_key_b64 = BASE64_STANDARD.encode(secret.to_bytes());
    let public_key_b64 = BASE64_STANDARD.encode(public.as_bytes());

    Ok(vec![private_key_b64, public_key_b64])
}

/// Validates if a string is a correctly formatted base64 X25519 public key.
pub fn validate_wireguard_key(key_b64: String) -> bool {
    use base64::prelude::*;
    if let Ok(decoded) = BASE64_STANDARD.decode(key_b64) {
        return decoded.len() == 32;
    }
    false
}

/// Parses a raw WireGuard configuration file and extracts the peer and interface metadata.
/// Includes support for custom ShadowMesh 'TrafficMode' metadata in comments.
pub fn parse_wireguard_config(config_str: String) -> Result<VPNConfig, ShadowMeshError> {
    // This is for local config parsing (e.g. from file)
    // Needs to match internal VPNConfig fields if we want to reuse it
    let mut private_key = String::new();
    let mut public_key = String::new();
    let mut address = String::new();
    let mut endpoint = String::new();
    let mut dns = String::new();
    let mut mtu = 1420;
    let mut traffic_mode = "normal".to_string();

    for line in config_str.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            if line.contains("TrafficMode") {
                if let Some(mode) = line.split(':').nth(1) {
                    traffic_mode = mode.trim().to_string();
                }
            }
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim();
            match key.as_str() {
                "privatekey" => private_key = value.to_string(),
                "publickey" => public_key = value.to_string(),
                "address" => address = value.to_string(),
                "endpoint" => endpoint = value.to_string(),
                "dns" => dns = value.to_string(),
                "mtu" => mtu = value.parse().unwrap_or(1420),
                _ => {}
            }
        }
    }

    Ok(VPNConfig {
        private_key: Some(private_key),
        public_key,
        address,
        endpoint,
        dns,
        mtu,
        traffic_mode,
        reality_config: None,
    })
}
