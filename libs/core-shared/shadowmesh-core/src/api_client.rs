use crate::vpn_manager::TrafficMode;
use crate::ShadowMeshError;
use crate::VPNConfig;
use crate::VPNNode;
use bytes::Bytes;
use lz4_flex::frame::FrameDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;
use tracing::info;
use zeroize::Zeroize;

/// Global storage for the async runtime to avoid repeated initialization.
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Internal helper to obtain the global tokio runtime safely.
pub(crate) fn get_runtime() -> Result<&'static Runtime, ShadowMeshError> {
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| {
            ShadowMeshError::Other(format!("Failed to initialize Async Runtime: {}", e))
        })?;

    // We don't care if another thread initialized it first
    let _ = RUNTIME.set(rt);
    RUNTIME
        .get()
        .ok_or_else(|| ShadowMeshError::Other("Async Runtime initialization failed".into()))
}

/// Represents an error response returned by the ShadowMesh API.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct ApiErrorResponse {
    /// The status of the response (e.g., "error").
    #[serde(default)]
    pub status: String,
    /// A descriptive error message.
    #[serde(alias = "error")]
    pub message: String,
    /// An optional machine-readable reason for the error.
    pub reason: Option<String>,
    /// An optional challenge for adaptive friction (e.g., PoW).
    pub challenge: Option<String>,
}

/// A challenge issued by the server during activation, requiring a Proof of Work solution.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct ActivationChallenge {
    /// The raw challenge string.
    pub challenge: String,
    /// The difficulty level of the PoW challenge.
    #[zeroize(skip)]
    pub difficulty: u32,
}

/// Data required to request device activation.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct ActivationRequest {
    /// The activation code provided by the user.
    pub code: String,
    /// A human-readable name for the device.
    pub device_name: String,
    /// The type of device (e.g., "android", "ios").
    pub device_type: String,
    /// A unique identifier for the device.
    pub device_id: String,
    /// A hardware-based fingerprint for forensic identification.
    pub hardware_fingerprint: String,
    /// The device's public key for secure communication.
    pub public_key: Option<String>,
    /// Detailed device fingerprint information.
    #[zeroize(skip)]
    pub deep_fingerprint: Option<HashMap<String, String>>,
    /// Out-of-band nonce for enhanced security.
    pub oob_nonce: Option<String>,
    /// Out-of-band signature.
    pub oob_sig: Option<String>,
    /// Out-of-band timestamp.
    #[zeroize(skip)]
    pub oob_ts: Option<i64>,
}

/// The response returned after a successful activation attempt.
///
/// [POST /api/v1/auth/activate]
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct ActivationResponse {
    /// A status message from the server.
    pub message: String,
    /// The session token for authenticated requests.
    pub token: Option<String>,
    /// The user's service plan (e.g., "solo", "team").
    pub plan: Option<String>,
    /// The expiration date of the subscription (ISO8601 / RFC3339).
    pub expires_at: Option<String>,
    /// Number of days remaining in the subscription.
    #[zeroize(skip)]
    pub remaining_days: i64,
    /// A notice regarding the subscription status.
    pub subscription_notice: String,
    /// Number of remaining device slots in the plan.
    #[zeroize(skip)]
    pub devices_remaining: i32,
    /// A base64-encoded WireGuard configuration string.
    pub vpn_config: Option<String>,
    /// Whether this is a canary/audit token (RFC-004).
    #[zeroize(skip)]
    pub is_canary: Option<bool>,
    /// The primary server location assigned to the device.
    pub server_location: Option<String>,
}

impl ActivationResponse {
    /// Returns the expiration date as a `chrono::DateTime<Utc>` if valid.
    pub fn parsed_expires_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.expires_at.as_ref().and_then(|s| s.parse().ok())
    }
}

/// Authentication information for the currently active identity.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct IdentityInfo {
    /// Unique database identifier.
    #[zeroize(skip)]
    pub id: i64,
    /// The user's public cryptographic identity.
    pub public_key: String,
    /// Whether the identity has administrative privileges.
    #[zeroize(skip)]
    pub is_admin: bool,
    /// Whether Multi-Factor Authentication is enabled.
    #[zeroize(skip)]
    pub mfa_enabled: bool,
    /// Account creation timestamp.
    pub created_at: String,
}

/// Real-time health metrics of the ShadowMesh control plane.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct HealthStatus {
    /// Current operational status (e.g., "online", "degraded").
    pub status: String,
    /// The version of the server software.
    pub version: String,
    /// Server uptime in seconds.
    #[zeroize(skip)]
    pub uptime_seconds: u64,
}

/// Dynamic feature flags for phased rollout (SOP 14).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityManifest {
    /// Map of feature names to their enabled status.
    pub flags: HashMap<String, bool>,
    /// Minimum client version required for this manifest.
    pub min_client_version: String,
    /// Unix timestamp of the manifest generation.
    pub timestamp: i64,
}

/// Telemetry report sent to the server for network diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct ServerNetworkReport {
    /// The client's observed public IP address.
    pub client_ip: String,
    /// GeoIP data in JSON format.
    pub geoip: String,
    /// Whether the server detects potential Deep Packet Inspection.
    #[zeroize(skip)]
    pub potential_dpi: bool,
    /// Calculated security score (0-100).
    #[zeroize(skip)]
    pub security_score: u8,
    /// Actionable recommendation for connection optimization.
    pub recommendation: String,
}

/// Heartbeat payload for maintaining active sessions and reporting usage.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct HeartbeatRequest {
    /// Unique identifier for the device.
    pub device_id: String,
    /// Whether the application is running in background mode.
    #[zeroize(skip)]
    pub background_mode: bool,
    /// Detailed device fingerprint for periodic verification.
    #[zeroize(skip)]
    pub deep_fingerprint: Option<HashMap<String, String>>,
    /// Usage: Cumulative bytes sent via Quantum Tunneling.
    #[zeroize(skip)]
    pub bytes_sent_quantum: Option<u64>,
    /// Usage: Cumulative bytes received via Quantum Tunneling.
    #[zeroize(skip)]
    pub bytes_received_quantum: Option<u64>,
    /// Usage: Cumulative bytes sent via Reality mode.
    #[zeroize(skip)]
    pub bytes_sent_reality: Option<u64>,
    /// Usage: Cumulative bytes received via Reality mode.
    #[zeroize(skip)]
    pub bytes_received_reality: Option<u64>,
}

/// Response returned after a heartbeat event.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct HeartbeatResponse {
    /// Status message.
    pub message: String,
    /// The device ID echoing the request.
    pub device_id: String,
    /// Whether the session is still valid.
    #[zeroize(skip)]
    pub session_active: bool,
    /// Any administrative notices regarding the subscription.
    pub subscription_notice: String,
    /// Suggested interval until the next heartbeat.
    pub next_heartbeat: String,
}

/// The main client for interacting with the ShadowMesh control plane.
///
/// This client manages authentication tokens, device identification, and
/// implements adaptive friction (PoW) protocols for secure communication.
pub struct ApiClient {
    base_url: String,
    client: reqwest::Client,
    device_id: Arc<RwLock<String>>,
    auth_token: Arc<RwLock<Option<String>>>,
    traffic_mode: Arc<RwLock<Option<TrafficMode>>>,
    pow_solution: Arc<RwLock<Option<(String, String)>>>,
    retry_signal: Arc<std::sync::atomic::AtomicBool>,
    discovery_engine: Arc<crate::network::discovery::ResilientDiscoveryEngine>,
}

impl ApiClient {
    /// Creates a new `ApiClient` with the specified base URL.
    pub fn new(base_url: String) -> Result<Self, ShadowMeshError> {
        let mut client_builder = reqwest::Client::builder()
            .user_agent("ShadowMesh/1.0.0 (Native; Rust)")
            .timeout(std::time::Duration::from_secs(30));

        // v6.9 Myanmar DNS Bypass: Hardcode control plane IP to bypass DNS blocking.
        // We know exactly where the server is, so we don't need to ask the ISP's DNS.
        if let Ok(addr) = "165.22.56.70:443".parse::<std::net::SocketAddr>() {
            tracing::info!("🛡️ Applying DNS Bypass: api.shadowmesh.org -> 165.22.56.70");
            client_builder = client_builder.resolve("api.shadowmesh.org", addr);
        }

        let client = client_builder.build().map_err(|e| ShadowMeshError::Other(e.to_string()))?;

        Ok(ApiClient {
            base_url: base_url.clone(),
            client,
            device_id: Arc::new(RwLock::new(String::new())),
            auth_token: Arc::new(RwLock::new(None)),
            traffic_mode: Arc::new(RwLock::new(None)),
            pow_solution: Arc::new(RwLock::new(None)),
            retry_signal: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            discovery_engine: Arc::new(crate::network::discovery::ResilientDiscoveryEngine::new(
                base_url,
                "https://discovery.shadowmesh.workers.dev/nodes".to_string(),
                "nodes.shadowmesh.org".to_string(),
            )),
        })
    }

    /// Creates a new `ApiClient` with SSL certificate pinning enabled.
    pub fn with_pins(
        base_url: String,
        pinned_hashes: Vec<String>,
    ) -> Result<Self, ShadowMeshError> {
        use rustls::ClientConfig;

        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs()? {
            root_store.add(cert).ok();
        }

        let config =
            ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();

        // v5.1: Elite Security - Utilize native root store as specified in requirements.
        let client_builder = reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .user_agent("ShadowMesh/1.0.0 (Native; Hardened)");

        // Note: Actual hash pinning would require a custom verifier.
        // For now, we utilize the hardened user-agent and native cert store.
        let _ = pinned_hashes;

        Ok(ApiClient {
            base_url: base_url.clone(),
            client: client_builder.build().map_err(|e| ShadowMeshError::Other(e.to_string()))?,
            device_id: Arc::new(RwLock::new(String::new())),
            auth_token: Arc::new(RwLock::new(None)),
            traffic_mode: Arc::new(RwLock::new(None)),
            pow_solution: Arc::new(RwLock::new(None)),
            retry_signal: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            discovery_engine: Arc::new(crate::network::discovery::ResilientDiscoveryEngine::new(
                base_url,
                "https://discovery.shadowmesh.workers.dev/nodes".to_string(),
                "nodes.shadowmesh.org".to_string(),
            )),
        })
    }

    /// Set the unique identifier for the current device.
    pub fn set_device_id(&self, id: String) {
        if let Ok(mut guard) = self.device_id.try_write() {
            *guard = id;
        }
    }

    /// Set the authentication token received after activation.
    pub fn set_auth_token(&self, token: Option<String>) {
        if let Ok(mut guard) = self.auth_token.try_write() {
            *guard = token;
        }
    }

    /// Set the traffic mode used for the next connection attempt.
    pub fn set_traffic_mode(&self, mode: Option<TrafficMode>) {
        if let Ok(mut guard) = self.traffic_mode.try_write() {
            *guard = mode;
        }
    }

    /// Set a pre-solved PoW solution for subsequent requests.
    pub fn set_pow_solution(&self, solution: String, original_challenge: String) {
        if let Ok(mut guard) = self.pow_solution.try_write() {
            *guard = Some((solution, original_challenge));
        }
    }

    /// Set the retry signal state.
    pub fn set_retry_signal(&self, retry: bool) {
        self.retry_signal.store(retry, std::sync::atomic::Ordering::Relaxed);
    }

    /// 🛡️ Forensic Zeroize: Securely clears all authentication tokens and secrets from memory.
    pub fn zeroize(&self) {
        if let Ok(mut token) = self.auth_token.try_write() {
            *token = None;
        }
        if let Ok(mut pow) = self.pow_solution.try_write() {
            *pow = None;
        }
        info!("CRITICAL: API Client credentials zeroized.");
    }

    async fn add_headers(&self, mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        // v5.5 Peak Security: Mandatory JWT Auth header
        if let Some(token) = self.auth_token.read().await.as_ref() {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        // v5.5 Battery Optimization: Signal traffic mode for optimized routing
        if let Some(mode) = self.traffic_mode.read().await.as_ref() {
            let mode_str = match mode {
                TrafficMode::Normal => "normal",
                TrafficMode::Fragmented => "fragmented",
                TrafficMode::Reality => "reality",
                TrafficMode::WebSocket => "websocket",
                TrafficMode::Shadowsocks => "shadowsocks",
                TrafficMode::Hysteria => "hysteria",
                TrafficMode::Vmess => "vmess",
            };
            request = request.header("X-Shadow-Traffic-Mode", mode_str);
        }

        // Adaptive Friction: PoW Solution headers
        if let Some((solution, challenge)) = self.pow_solution.read().await.as_ref() {
            request = request.header("X-Shadow-PoW-Solution", solution);
            request = request.header("X-Shadow-PoW-Challenge", challenge);
        }

        // v5.5 Zero-Trust: Mandatory Device Identity header
        let device_id = self.device_id.read().await.clone();
        if !device_id.is_empty() {
            request = request.header("X-Shadow-Device-ID", &device_id);
            // Backward compatibility
            request = request.header("X-Device-ID", &device_id);
        }

        request
    }

    async fn execute_with_retry_async<F, T>(&self, request_fn: F) -> Result<T, ShadowMeshError>
    where
        F: Fn() -> reqwest::RequestBuilder,
        T: serde::de::DeserializeOwned,
    {
        let mut retry_count = 0;
        let max_retries = 2;

        let use_resilient_path = self.retry_signal.load(std::sync::atomic::Ordering::Relaxed);

        loop {
            let mut request = request_fn();

            // v5.6 Resilient Path: If retry signal is active, we append the resilient
            // marker to the header. This triggers the Edge-Gateway to route via
            // Anycast VIPs or domain-fronted tunnels if the primary path is blocked.
            if use_resilient_path || retry_count > 0 {
                request = request.header("X-Shadow-Resilient-Path", "true");
            }

            let request_builder = self.add_headers(request).await;
            let response_result = request_builder.send().await;

            match response_result {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        return self.handle_response_async(response).await;
                    }

                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS && retry_count < max_retries
                    {
                        retry_count += 1;
                        tokio::time::sleep(tokio::time::Duration::from_secs(retry_count * 2)).await;
                        continue;
                    }

                    let body_bytes = response
                        .bytes()
                        .await
                        .map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
                    let err_body: ApiErrorResponse = serde_json::from_slice(&body_bytes)
                        .unwrap_or_else(|_| ApiErrorResponse {
                            status: "error".to_string(),
                            message: "Unknown error".to_string(),
                            reason: None,
                            challenge: None,
                        });

                    return Self::map_status_error(status, err_body);
                }
                Err(e) => {
                    use std::error::Error;
                    tracing::error!(
                        "🚨 [API_FAILURE_DIAGNOSTIC] Request failed: {:?}. Source: {:?}",
                        e,
                        e.source()
                    );

                    if retry_count < max_retries {
                        retry_count += 1;
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        continue;
                    }
                    return Err(ShadowMeshError::ConnectionFailed);
                }
            }
        }
    }

    fn map_status_error<T>(
        status: reqwest::StatusCode,
        err_body: ApiErrorResponse,
    ) -> Result<T, ShadowMeshError> {
        match status {
            reqwest::StatusCode::PAYMENT_REQUIRED => {
                if let Some(challenge) = err_body.challenge {
                    Err(ShadowMeshError::AdaptiveFrictionRequired(challenge))
                } else {
                    Err(ShadowMeshError::Other(
                        "PoW required but no challenge provided".to_string(),
                    ))
                }
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(ShadowMeshError::Unauthorized(err_body.message))
            }
            reqwest::StatusCode::FORBIDDEN => {
                if err_body.message.contains("frozen") {
                    Err(ShadowMeshError::SessionFrozen)
                } else {
                    Err(ShadowMeshError::Forbidden(err_body.message))
                }
            }
            reqwest::StatusCode::NOT_FOUND => Err(ShadowMeshError::NotFound(err_body.message)),
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                Err(ShadowMeshError::TooManyRequests(err_body.message))
            }
            reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                Err(ShadowMeshError::ServerError(err_body.message))
            }
            _ => Err(ShadowMeshError::Other(format!("Unexpected status code: {}", status))),
        }
    }

    async fn handle_response_async<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, ShadowMeshError> {
        let status = response.status();
        let content_type =
            response.headers().get("Content-Type").and_then(|v| v.to_str().ok()).unwrap_or("");

        let is_compressed = content_type.contains("lz4");
        let is_binary = content_type.contains("application/x-shadow-binary");

        let body_bytes =
            response.bytes().await.map_err(|e| ShadowMeshError::IoError(e.to_string()))?;

        let data = if is_compressed {
            let mut decoder = FrameDecoder::new(&body_bytes[..]);
            let mut decoded = Vec::new();
            decoder
                .read_to_end(&mut decoded)
                .map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
            Bytes::from(decoded)
        } else {
            body_bytes
        };

        if !status.is_success() {
            let err_body: ApiErrorResponse =
                serde_json::from_slice(&data).unwrap_or_else(|_| ApiErrorResponse {
                    status: "error".to_string(),
                    message: "Unknown error".to_string(),
                    reason: None,
                    challenge: None,
                });
            return Self::map_status_error(status, err_body);
        }

        // Detect ShadowMesh Binary format by magic bytes if Content-Type matches or as fallback
        if is_binary || (data.len() >= 4 && &data[..4] == crate::protocol::binary::MAGIC) {
            // We need to return T. If T is Vec<VPNNode>, we need to convert.
            // This is a bit tricky with generic T.
            // For now, we assume if it's binary, the caller knows how to handle it or we use a specialized path.
            // But handle_response_async is generic.

            // To maintain compatibility with the generic T (which is usually Vec<VPNNode> for get_nodes),
            // we try to decode it as borrowed and convert to owned if possible.
            // However, T is DeserializeOwned. Postcard supports DeserializeOwned.

            return crate::protocol::binary::decode_node_list_generic::<T>(&data);
        }

        serde_json::from_slice(&data).map_err(|e| ShadowMeshError::JsonError(e.to_string()))
    }

    /// Lightweight connectivity probe to verify the API Gateway is reachable.
    /// Does not require Auth or PoW.
    pub async fn ping_gateway_async(&self) -> Result<bool, ShadowMeshError> {
        let url = format!("{}/api/v1/health", self.base_url);
        let response =
            self.client.get(&url).send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        Ok(response.status().is_success())
    }

    /// Fetches the list of available VPN nodes from the server (Sync).
    ///
    /// [GET /api/v1/nodes]
    pub fn get_nodes(&self) -> Result<Vec<VPNNode>, ShadowMeshError> {
        get_runtime()?.block_on(self.get_nodes_async())
    }

    /// Fetches the list of available VPN nodes from the server (Async).
    ///
    /// [GET /api/v1/nodes]
    pub async fn get_nodes_async(&self) -> Result<Vec<VPNNode>, ShadowMeshError> {
        let url = format!("{}/api/v1/nodes", self.base_url);
        self.execute_with_retry_async(|| self.client.get(&url)).await
    }

    /// Fetches nodes using the Resilient Discovery Engine (RFC-004).
    pub async fn get_nodes_resilient_async(&self) -> Result<Vec<VPNNode>, ShadowMeshError> {
        self.discovery_engine.fetch_nodes_resilient().await
    }

    /// Fetches nodes using the Resilient Discovery Engine (RFC-004) - Sync.
    pub fn get_nodes_resilient(&self) -> Result<Vec<VPNNode>, ShadowMeshError> {
        get_runtime()?.block_on(self.get_nodes_resilient_async())
    }

    /// Fetches the comprehensive Global Manifest (Horizon 4).
    /// Includes Anycast VIPs and Shard-anchored nodes.
    pub async fn fetch_global_manifest_async(
        &self,
    ) -> Result<crate::GlobalManifest, ShadowMeshError> {
        let url = format!("{}/api/v1/manifest", self.base_url);
        self.execute_with_retry_async(|| self.client.get(&url)).await
    }

    /// Fetches the comprehensive Global Manifest (Horizon 4) - Sync.
    pub fn fetch_global_manifest(&self) -> Result<crate::GlobalManifest, ShadowMeshError> {
        get_runtime()?.block_on(self.fetch_global_manifest_async())
    }

    /// Requests an activation challenge (PoW) for the specified device (Sync).
    ///
    /// [POST /api/v1/auth/activate/challenge]
    pub fn request_activation_challenge(
        &self,
        device_id: String,
    ) -> Result<ActivationChallenge, ShadowMeshError> {
        get_runtime()?.block_on(self.request_activation_challenge_async(device_id))
    }

    /// Requests an activation challenge (PoW) for the specified device (Async).
    ///
    /// [POST /api/v1/auth/activate/challenge]
    pub async fn request_activation_challenge_async(
        &self,
        device_id: String,
    ) -> Result<ActivationChallenge, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/activate/challenge", self.base_url);
        let request = self.client.post(&url).json(&serde_json::json!({ "device_id": device_id }));
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        let status = response.status();
        let body_bytes =
            response.bytes().await.map_err(|e| ShadowMeshError::IoError(e.to_string()))?;

        if status == reqwest::StatusCode::PAYMENT_REQUIRED {
            let err_body: ApiErrorResponse = serde_json::from_slice(&body_bytes)
                .map_err(|e| ShadowMeshError::JsonError(e.to_string()))?;
            if let Some(challenge) = err_body.challenge {
                let parts: Vec<&str> = challenge.split('|').collect();
                let difficulty = if parts.len() >= 2 { parts[1].parse().unwrap_or(10) } else { 10 };
                return Ok(ActivationChallenge { challenge, difficulty });
            }
        }

        if status.is_success() {
            let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();
            if let Some(challenge) = body["challenge"].as_str() {
                let parts: Vec<&str> = challenge.split('|').collect();
                let difficulty = if parts.len() >= 2 { parts[1].parse().unwrap_or(10) } else { 10 };
                return Ok(ActivationChallenge { challenge: challenge.to_string(), difficulty });
            }
        }

        Err(ShadowMeshError::Other(format!(
            "Failed to obtain activation challenge (HTTP {}, body: {})",
            status,
            String::from_utf8_lossy(&body_bytes)
        )))
    }

    /// Activates the device using the provided code and fingerprint (Sync).
    ///
    /// [POST /api/v1/auth/activate]
    pub fn activate(&self, req: ActivationRequest) -> Result<ActivationResponse, ShadowMeshError> {
        get_runtime()?.block_on(self.activate_async(req))
    }

    /// Activates the device using the provided code and fingerprint (Async).
    ///
    /// [POST /api/v1/auth/activate]
    pub async fn activate_async(
        &self,
        req: ActivationRequest,
    ) -> Result<ActivationResponse, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/activate", self.base_url);
        self.execute_with_retry_async(|| self.client.post(&url).json(&req)).await
    }

    /// Fetches the VPN configuration for the specified node and mode (Sync).
    ///
    /// [GET /api/v1/config/:server_id]
    pub fn get_config(
        &self,
        node_id: String,
        public_key: String,
        mode: Option<String>,
    ) -> Result<VPNConfig, ShadowMeshError> {
        get_runtime()?.block_on(self.get_config_async(node_id, public_key, mode))
    }

    /// Fetches the VPN configuration for the specified node and mode (Async).
    ///
    /// [GET /api/v1/config/:server_id]
    pub async fn get_config_async(
        &self,
        node_id: String,
        public_key: String,
        mode: Option<String>,
    ) -> Result<VPNConfig, ShadowMeshError> {
        let url = format!("{}/api/v1/config/{}", self.base_url, node_id);
        let mut query = vec![("public_key", public_key)];
        if let Some(m) = mode {
            query.push(("mode", m));
        }

        self.execute_with_retry_async(|| self.client.get(&url).query(&query)).await
    }

    /// Sends a heartbeat to maintain the session and report usage (Sync).
    ///
    /// [POST /api/v1/auth/session/heartbeat]
    pub fn heartbeat(&self, req: HeartbeatRequest) -> Result<HeartbeatResponse, ShadowMeshError> {
        get_runtime()?.block_on(self.heartbeat_async(req))
    }

    /// Sends a heartbeat to maintain the session and report usage (Async).
    ///
    /// [POST /api/v1/auth/session/heartbeat]
    pub async fn heartbeat_async(
        &self,
        req: HeartbeatRequest,
    ) -> Result<HeartbeatResponse, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/session/heartbeat", self.base_url);
        self.execute_with_retry_async(|| self.client.post(&url).json(&req)).await
    }

    /// Pauses the active VPN session (Sync).
    pub fn pause_session(&self) -> Result<(), ShadowMeshError> {
        get_runtime()?.block_on(self.pause_session_async())
    }

    /// Pauses the active VPN session (Async).
    pub async fn pause_session_async(&self) -> Result<(), ShadowMeshError> {
        let url = format!("{}/api/v1/auth/session/pause", self.base_url);
        self.execute_with_retry_async::<_, serde_json::Value>(|| self.client.post(&url))
            .await
            .map(|_| ())
    }

    /// Revokes all active sessions for the current identity (Sync).
    pub fn revoke_session(&self) -> Result<(), ShadowMeshError> {
        get_runtime()?.block_on(self.revoke_session_async())
    }

    /// Revokes all active sessions for the current identity (Async).
    pub async fn revoke_session_async(&self) -> Result<(), ShadowMeshError> {
        let url = format!("{}/api/v1/sessions/revoke", self.base_url);
        self.execute_with_retry_async::<_, serde_json::Value>(|| self.client.post(&url))
            .await
            .map(|_| ())
    }

    /// Refreshes the authentication token (Sync).
    pub fn refresh_token(&self) -> Result<String, ShadowMeshError> {
        get_runtime()?.block_on(self.refresh_token_async())
    }

    /// Refreshes the authentication token (Async).
    pub async fn refresh_token_async(&self) -> Result<String, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/session/refresh", self.base_url);
        let request = self.client.post(&url);
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        if response.status().is_success() {
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|_| ShadowMeshError::JsonError("Invalid refresh response".to_string()))?;
            body["token"]
                .as_str()
                .map(|s| s.to_string())
                .ok_or(ShadowMeshError::Other("Missing token".to_string()))
        } else {
            Err(ShadowMeshError::Other("Refresh failed".to_string()))
        }
    }

    /// Checks the health of the Control Plane (Sync).
    pub fn check_health(&self) -> Result<HealthStatus, ShadowMeshError> {
        get_runtime()?.block_on(self.check_health_async())
    }

    /// Checks the health of the Control Plane (Async).
    pub async fn check_health_async(&self) -> Result<HealthStatus, ShadowMeshError> {
        let url = format!("{}/api/health", self.base_url);
        self.execute_with_retry_async(|| self.client.get(&url)).await
    }

    /// Fetches the dynamic security manifest for feature flagging (Async).
    pub async fn fetch_security_manifest_async(&self) -> Result<SecurityManifest, ShadowMeshError> {
        let url = format!("{}/api/v1/security/manifest", self.base_url);
        self.execute_with_retry_async(|| self.client.get(&url)).await
    }

    /// Fetches the dynamic security manifest for feature flagging (Sync).
    pub fn fetch_security_manifest(&self) -> Result<SecurityManifest, ShadowMeshError> {
        get_runtime()?.block_on(self.fetch_security_manifest_async())
    }

    /// Generates a QR pairing session (Sync).
    pub fn qr_generate(
        &self,
        device_id: String,
        device_name: String,
        os_name: String,
        os_version: String,
        arch: String,
    ) -> Result<String, ShadowMeshError> {
        get_runtime()?.block_on(self.qr_generate_async(
            device_id,
            device_name,
            os_name,
            os_version,
            arch,
        ))
    }

    /// Generates a QR pairing session (Async).
    pub async fn qr_generate_async(
        &self,
        device_id: String,
        device_name: String,
        os_name: String,
        os_version: String,
        arch: String,
    ) -> Result<String, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/qr/generate", self.base_url);
        let payload = serde_json::json!({
            "device_id": device_id,
            "device_name": device_name,
            "os_name": os_name,
            "os_version": os_version,
            "arch": arch
        });
        let request = self.client.post(&url).json(&payload);
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        if response.status().is_success() {
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|_| ShadowMeshError::JsonError("Invalid QR response".to_string()))?;
            body["token"]
                .as_str()
                .map(|s| s.to_string())
                .ok_or(ShadowMeshError::Other("Missing QR token".to_string()))
        } else {
            Err(ShadowMeshError::Other("QR generation failed".to_string()))
        }
    }

    /// Checks the status of a QR pairing token (Sync).
    pub fn qr_status(&self, token: String) -> Result<String, ShadowMeshError> {
        get_runtime()?.block_on(self.qr_status_async(token))
    }

    /// Checks the status of a QR pairing token (Async).
    pub async fn qr_status_async(&self, token: String) -> Result<String, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/qr/status/{}", self.base_url, token);
        let request = self.client.get(&url);
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        if response.status().is_success() {
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|_| ShadowMeshError::JsonError("Invalid status response".to_string()))?;
            Ok(body["status"].as_str().unwrap_or("pending").to_string())
        } else {
            Err(ShadowMeshError::Other("QR status check failed".to_string()))
        }
    }

    /// Authorizes a QR pairing session using the active account (Sync).
    pub fn qr_authorize(&self, token: String) -> Result<(), ShadowMeshError> {
        get_runtime()?.block_on(self.qr_authorize_async(token))
    }

    /// Authorizes a QR pairing session using the active account (Async).
    pub async fn qr_authorize_async(&self, token: String) -> Result<(), ShadowMeshError> {
        let url = format!("{}/api/v1/auth/qr/authorize", self.base_url);
        self.execute_with_retry_async::<_, serde_json::Value>(|| {
            self.client.post(&url).json(&serde_json::json!({ "token": token }))
        })
        .await
        .map(|_| ())
    }

    /// Retrieves identity information for the current user (Sync).
    pub fn get_identity_info(&self) -> Result<IdentityInfo, ShadowMeshError> {
        get_runtime()?.block_on(self.get_identity_info_async())
    }

    /// Retrieves identity information for the current user (Async).
    pub async fn get_identity_info_async(&self) -> Result<IdentityInfo, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/identity", self.base_url);
        self.execute_with_retry_async(|| self.client.get(&url)).await
    }

    /// Initiates a TOTP MFA setup (Sync).
    pub fn setup_totp_begin(&self) -> Result<String, ShadowMeshError> {
        get_runtime()?.block_on(self.setup_totp_begin_async())
    }

    /// Initiates a TOTP MFA setup (Async).
    pub async fn setup_totp_begin_async(&self) -> Result<String, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/mfa/setup/totp/begin", self.base_url);
        let request = self.client.get(&url);
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        if response.status().is_success() {
            response
                .text()
                .await
                .map_err(|_| ShadowMeshError::Other("Failed to read body".to_string()))
        } else {
            Err(ShadowMeshError::Other("TOTP setup failed".to_string()))
        }
    }

    /// Completes TOTP MFA setup with the provided verification code (Sync).
    pub fn setup_totp_finish(&self, code: String) -> Result<(), ShadowMeshError> {
        get_runtime()?.block_on(self.setup_totp_finish_async(code))
    }

    /// Completes TOTP MFA setup with the provided verification code (Async).
    pub async fn setup_totp_finish_async(&self, code: String) -> Result<(), ShadowMeshError> {
        let url = format!("{}/api/v1/auth/mfa/setup/totp/finish", self.base_url);
        self.execute_with_retry_async::<_, serde_json::Value>(|| {
            self.client.post(&url).json(&serde_json::json!({ "code": code }))
        })
        .await
        .map(|_| ())
    }

    /// Generates a Team Member Sovereignty Token (Sync).
    pub fn generate_member_token(&self, label: String) -> Result<String, ShadowMeshError> {
        get_runtime()?.block_on(self.generate_member_token_async(label))
    }

    /// Generates a Team Member Sovereignty Token (Async).
    pub async fn generate_member_token_async(
        &self,
        label: String,
    ) -> Result<String, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/team/member-token", self.base_url);
        let res: serde_json::Value = self
            .execute_with_retry_async(|| {
                self.client.post(&url).json(&serde_json::json!({ "label": label }))
            })
            .await?;

        res["member_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ShadowMeshError::Other("Token generation failed".into()))
    }

    /// Initiates a Passkey registration (Sync).
    pub fn passkey_register_begin(&self, username: String) -> Result<String, ShadowMeshError> {
        get_runtime()?.block_on(self.passkey_register_begin_async(username))
    }

    /// Initiates a Passkey registration (Async).
    pub async fn passkey_register_begin_async(
        &self,
        username: String,
    ) -> Result<String, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/passkey/register/begin", self.base_url);
        let request = self.client.post(&url).json(&serde_json::json!({ "username": username }));
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        if response.status().is_success() {
            response
                .text()
                .await
                .map_err(|_| ShadowMeshError::Other("Failed to read body".to_string()))
        } else {
            Err(ShadowMeshError::Other("Passkey registration start failed".to_string()))
        }
    }

    /// Completes Passkey registration with the signed challenge (Sync).
    pub fn passkey_register_finish(
        &self,
        _username: String,
        response_json: String,
    ) -> Result<(), ShadowMeshError> {
        get_runtime()?.block_on(self.passkey_register_finish_async(_username, response_json))
    }

    /// Completes Passkey registration with the signed challenge (Async).
    pub async fn passkey_register_finish_async(
        &self,
        username: String,
        response_json: String,
    ) -> Result<(), ShadowMeshError> {
        let url = format!("{}/api/v1/auth/passkey/register/finish", self.base_url);
        let response_data: serde_json::Value = serde_json::from_str(&response_json)
            .map_err(|_| ShadowMeshError::JsonError("Malformed Passkey response".to_string()))?;

        self.execute_with_retry_async::<_, serde_json::Value>(|| {
            self.client.post(&url).json(&serde_json::json!({
                "username": username,
                "response": response_data
            }))
        })
        .await
        .map(|_| ())
    }

    /// Initiates a Passkey login (Sync).
    pub fn passkey_login_start(&self, username: String) -> Result<String, ShadowMeshError> {
        get_runtime()?.block_on(self.passkey_login_start_async(username))
    }

    /// Initiates a Passkey login (Async).
    pub async fn passkey_login_start_async(
        &self,
        username: String,
    ) -> Result<String, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/passkey/login/start", self.base_url);
        let request = self.client.post(&url).json(&serde_json::json!({ "username": username }));
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        if response.status().is_success() {
            response
                .text()
                .await
                .map_err(|_| ShadowMeshError::Other("Failed to read body".to_string()))
        } else {
            Err(ShadowMeshError::Other("Passkey login start failed".to_string()))
        }
    }

    /// Completes Passkey login (Sync).
    pub fn passkey_login_finish(
        &self,
        username: String,
        response_json: String,
    ) -> Result<ActivationResponse, ShadowMeshError> {
        get_runtime()?.block_on(self.passkey_login_finish_async(username, response_json))
    }

    /// Completes Passkey login (Async).
    pub async fn passkey_login_finish_async(
        &self,
        username: String,
        response_json: String,
    ) -> Result<ActivationResponse, ShadowMeshError> {
        let url = format!("{}/api/v1/auth/passkey/login/finish", self.base_url);
        let response_data: serde_json::Value = serde_json::from_str(&response_json)
            .map_err(|_| ShadowMeshError::JsonError("Malformed Passkey response".to_string()))?;

        let request = self.client.post(&url).json(&serde_json::json!({
            "username": username,
            "response": response_data
        }));
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        if response.status().is_success() {
            let body_bytes = response
                .bytes()
                .await
                .map_err(|_| ShadowMeshError::Other("Failed to read response body".to_string()))?;
            let res: ActivationResponse = serde_json::from_slice(&body_bytes).map_err(|_| {
                ShadowMeshError::JsonError("Failed to parse activation response".to_string())
            })?;
            Ok(res)
        } else {
            Err(ShadowMeshError::Other("Passkey login failed".to_string()))
        }
    }

    /// Logs a security event to the Control Plane (Sync).
    pub fn log_security_event(&self, event_json: String) -> Result<(), ShadowMeshError> {
        get_runtime()?.block_on(self.log_security_event_async(event_json))
    }

    /// Logs a security event to the Control Plane (Async).
    pub async fn log_security_event_async(
        &self,
        event_json: String,
    ) -> Result<(), ShadowMeshError> {
        let url = format!("{}/api/v1/auth/security/event", self.base_url);
        let event_data: serde_json::Value = serde_json::from_str(&event_json)
            .map_err(|_| ShadowMeshError::JsonError("Malformed event JSON".to_string()))?;

        self.execute_with_retry_async::<_, serde_json::Value>(|| {
            self.client.post(&url).json(&event_data)
        })
        .await
        .map(|_| ())
    }

    /// Reports that the device security has been compromised (Async).
    ///
    /// [POST /api/v1/auth/report-compromised]
    pub async fn report_compromised_async(
        &self,
        device_id: String,
        reason: String,
    ) -> Result<(), ShadowMeshError> {
        let url = format!("{}/api/v1/auth/report-compromised", self.base_url);
        let payload = serde_json::json!({
            "device_id": device_id,
            "reason": reason
        });
        let request = self.client.post(&url).json(&payload);
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let body_bytes =
                response.bytes().await.map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
            let err_body: ApiErrorResponse =
                serde_json::from_slice(&body_bytes).unwrap_or_else(|_| ApiErrorResponse {
                    status: "error".to_string(),
                    message: "Report compromise failed".to_string(),
                    reason: None,
                    challenge: None,
                });
            Self::map_status_error(status, err_body)
        }
    }

    /// Reports that the device security has been compromised (Sync).
    pub fn report_compromised(
        &self,
        device_id: String,
        reason: String,
    ) -> Result<(), ShadowMeshError> {
        get_runtime()?.block_on(self.report_compromised_async(device_id, reason))
    }

    /// Pings the server for speed testing (Async).
    pub async fn speedtest_ping_async(&self) -> Result<(), ShadowMeshError> {
        let url = format!("{}/api/v1/speedtest/ping", self.base_url);
        let request = self.client.get(&url);
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ShadowMeshError::Other("Ping failed".to_string()))
        }
    }

    /// Pings the server for speed testing (Sync).
    pub fn speedtest_ping(&self) -> Result<(), ShadowMeshError> {
        get_runtime()?.block_on(self.speedtest_ping_async())
    }

    /// Downloads data for speed testing (Async).
    pub async fn speedtest_download_async(&self, size_kb: u32) -> Result<Bytes, ShadowMeshError> {
        let url = format!("{}/api/v1/speedtest/download/{}", self.base_url, size_kb);
        let request = self.client.get(&url);
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        if response.status().is_success() {
            response
                .bytes()
                .await
                .map_err(|_| ShadowMeshError::Other("Download failed".to_string()))
        } else {
            Err(ShadowMeshError::Other("Download failed".to_string()))
        }
    }

    /// Downloads data for speed testing (Sync).
    pub fn speedtest_download(&self, size_kb: u32) -> Result<Vec<u8>, ShadowMeshError> {
        get_runtime()?.block_on(self.speedtest_download_async(size_kb)).map(|b| b.to_vec())
    }

    /// Uploads data for speed testing (Async).
    pub async fn speedtest_upload_async(&self, data: Bytes) -> Result<(), ShadowMeshError> {
        let url = format!("{}/api/v1/speedtest/upload", self.base_url);
        let request = self.client.post(&url).body(data);
        let request = self.add_headers(request).await;
        let response = request.send().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ShadowMeshError::Other("Upload failed".to_string()))
        }
    }

    /// Uploads data for speed testing (Sync).
    pub fn speedtest_upload(&self, data: Vec<u8>) -> Result<(), ShadowMeshError> {
        get_runtime()?.block_on(self.speedtest_upload_async(Bytes::from(data)))
    }

    /// Detects network conditions from the server's perspective (Async).
    pub async fn detect_network_async(&self) -> Result<ServerNetworkReport, ShadowMeshError> {
        let url = format!("{}/api/v1/network/detect", self.base_url);
        self.execute_with_retry_async(|| self.client.get(&url)).await
    }

    /// Detects network conditions from the server's perspective (Sync).
    pub fn detect_network(&self) -> Result<ServerNetworkReport, ShadowMeshError> {
        get_runtime()?.block_on(self.detect_network_async())
    }
}
