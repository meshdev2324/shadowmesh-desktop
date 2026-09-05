use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use zeroize::Zeroize;

#[cfg(unix)]
pub const SOCKET_PATH: &str = "/tmp/shadowmesh_integration.sock";
#[cfg(windows)]
pub const SOCKET_PATH: &str = r"\\.\pipe\shadowmesh";

pub const CONFIG_DIR: &str = if cfg!(windows) {
    r"C:\ProgramData\ShadowMesh"
} else {
    #[cfg(debug_assertions)]
    {
        "./daemon_logs"
    }
    #[cfg(not(debug_assertions))]
    {
        "/var/lib/shadowmesh"
    }
};
pub const CONFIG_FILE: &str = "config.json";

// --- IPC Protocol Types (Gold Standard Zero-Copy) ---

/// Strongly-typed actions supported by the ShadowMesh Daemon IPC.
/// Using Cow<'a, str> for zero-copy deserialization where possible.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case", tag = "action", content = "args")]
pub enum VpnAction<'a> {
    GetVersion,
    Ping,
    Status,
    GetLogs,
    GetIdentity,
    ListNodes,

    Activate { code: Cow<'a, str> },
    Connect { node_id: Cow<'a, str>, mode: Option<Cow<'a, str>> },
    Disconnect,
    Pause { minutes: u32 },
    Resume,

    GetDiagnostics,

    SetKillSwitch { enabled: bool },
    SetAutoConnect { enabled: bool },
    SetDnsOverHttps { enabled: bool },
    SetTrafficPreference { preference: Cow<'a, str> },
    SetSplitTunnel { enabled: bool, mode: Cow<'a, str>, apps: Vec<Cow<'a, str>> },
    SetDeviceLabel { label: Cow<'a, str> },

    SecureToken { op: SecureTokenOp<'a> },
    QrAuth { op: QrAuthOp<'a> },

    Obfuscation { action: Cow<'a, str>, config: Option<Cow<'a, str>> },
    SmartFallback { enabled: bool },

    DuressPin { action: Cow<'a, str>, hash: Option<Cow<'a, str>> },
    PanicWipe,
    Camouflage { enabled: bool },
    Shutdown,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case", tag = "op")]
pub enum SecureTokenOp<'a> {
    Get { key: Cow<'a, str> },
    Set { key: Cow<'a, str>, value: Cow<'a, str> },
    Remove { key: Cow<'a, str> },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case", tag = "op")]
pub enum QrAuthOp<'a> {
    Generate,
    CheckStatus { token: Cow<'a, str> },
}

#[derive(thiserror::Error, Debug)]
pub enum IpcError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Payload too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

/// Structured response data for IPC calls.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum VpnResponseData {
    Version { version: String, os: String, arch: String, features: Vec<String> },
    Status(serde_json::Value),
    Nodes(Vec<shadowmesh_core::VPNNode>),
    Identity(shadowmesh_core::IdentityInfo),
    Token(String),
    QrToken { token: String },
    Logs(Vec<String>),
    Generic(serde_json::Value),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VpnCommand<'a> {
    #[serde(flatten, borrow)]
    pub action: VpnAction<'a>,
    pub token: Cow<'a, str>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VpnResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<VpnResponseData>,
}

// --- Daemon State & Persistent Config ---

#[derive(Default, Serialize, Deserialize, Clone, Zeroize)]
pub struct DaemonConfig {
    pub auth_token: Option<String>,
    pub activation_code: Option<String>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub enrollment_token: Option<String>,
    pub selected_node_id: Option<String>,
    pub device_label: Option<String>,
    #[zeroize(skip)]
    pub traffic_mode: String,
    #[zeroize(skip)]
    pub plan_name: String,
    #[zeroize(skip)]
    pub devices_remaining: i32,
    #[zeroize(skip)]
    pub remaining_days: i64,
    #[zeroize(skip)]
    pub kill_switch: bool,
    #[zeroize(skip)]
    pub auto_connect: bool,
    #[zeroize(skip)]
    pub dns_over_https: bool,
    pub duress_pin_hash: Option<String>,
    #[zeroize(skip)]
    pub obfuscation_enabled: bool,
    #[zeroize(skip)]
    pub smart_fallback_enabled: bool,
}
