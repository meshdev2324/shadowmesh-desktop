// =============================================================================
// ShadowMesh Desktop - Type Definitions
// Electron API Type Declarations
// =============================================================================

export interface ServerNode {
  id: string;
  name: string;
  location: string;
  country_code: string;
  public_ip: string;
  flag: string;
  ping: number;
}

/**
 * VPN Connection Configuration
 */
export interface VPNConfig {
  endpoint: string;
  privateKey: string;
  publicKey: string;
  address: string;
  dns: string;
  mtu?: number;
  mode?: "standard" | "fragmented" | "reality";
}

/**
 * VPN Connection State (FSM - matches mobile)
 */
export type VPNConnectionState =
  | "disconnected"
  | "connecting_direct" // Attempt 1: Direct (3s timeout)
  | "connecting_fragmented" // Attempt 2: DPI bypass (5s timeout)
  | "connecting_reality" // Attempt 3: TLS camouflage (8s timeout)
  | "connected"
  | "error";

/**
 * VPN Status Response
 */
export interface VPNStatus {
  connected: boolean;
  state: VPNConnectionState;
  currentAttempt?: number; // 1, 2, or 3
  details?: string;
  error?: string;
  device_label?: string;
  plan?: string;
}

/**
 * Obfuscation/Stealth Mode Configuration
 */
export interface ObfuscationConfig {
  enabled: boolean;
  method?: "shadowsocks" | "udp2raw";
  mode?: "vpn" | "tproxy" | "tun";
  server_ip: string;
  local_port: number;
  remote_port: number;
  password?: string;
  key?: string;
  tls_host?: string;
  tls_path?: string;
}

/**
 * Sing-box VLESS+REALITY Configuration
 */
export interface SingBoxConfig {
  enabled: boolean;
  server_ip: string;
  server_port: number;
  uuid: string;
  flow: "xtls-rprx-vision" | (string & { _?: never });
  public_key: string;
  short_id: string;
  server_name: string;
  fingerprint: "chrome" | "firefox" | "safari" | "edge" | (string & { _?: never });
  local_socks_port: number;
  local_http_port: number;
  wg_endpoint?: string;
}

/**
 * Obfuscation Status Response
 */
export interface ObfuscationStatus {
  running: boolean;
  supervised?: boolean;
  method?: string;
  active_profile?: string;
  restart_count?: number;
  last_error?: string;
  last_heartbeat?: string;
  child_pid?: number;
  supervisor_pid?: number;
}

/**
 * Sing-box Status Response
 */
export interface SingBoxStatus {
  running: boolean;
  supervised?: boolean;
  protocol?: "vless-reality" | (string & { _?: never });
  restart_count?: number;
  last_error?: string;
  last_handshake?: string;
  last_latency_ms?: number;
  started_at?: string;
  child_pid?: number;
  supervisor_pid?: number;
  active_fallback?: boolean;
}

/**
 * Smart Fallback Configuration
 */
export interface SmartFallbackConfig {
  enabled: boolean;
  wg_config_path: string;
  singbox_config_path: string;
  check_interval_sec: number;
  handshake_timeout_sec: number;
  auto_switch: boolean;
  current_mode: "wireguard" | "singbox";
}

/**
 * Rust Daemon Version Response
 */
export interface HelperVersion {
  version: string;
  os: string;
  arch: string;
  features: string[];
}

/**
 * Passkey Authentication Response
 */
export interface PasskeyAuthResponse {
  success: boolean;
  message?: string;
  error?: string;
  credential?: unknown;
}

/**
 * Server/Latency Test Result
 */
export interface LatencyResult {
  host: string;
  latency: number; // ms, 999 = timeout/error
}

/**
 * Identity Information
 */
export interface IdentityInfo {
  device_id: string;
  session_id: string;
  plan: string;
  expires_at: number | null;
  device_label?: string;
  username?: string;
  email?: string;
  device_limit?: number;
  devices_active?: number;
}

/**
 * Speed Test Result
 */
export interface SpeedTestResult {
  download_bps: number;
  upload_bps: number;
  latency_ms: number;
  jitter_ms: number;
}

/**
 * Traffic Stats & Daemon Status Info
 */
export interface TrafficStats {
  connected: boolean;
  status: string;
  recv_bps: number;
  sent_bps: number;
  total_recv: number;
  total_sent: number;
  totalBytes: number;
  monthlyBytes: number;
  plan?: string;
  traffic_mode?: string;
}

/**
 * Auto Updater Info
 */
export interface UpdateInfo {
  version: string;
  releaseDate?: string;
  releaseNotes?: string;
}

/**
 * Download Progress Info
 */
export interface DownloadProgress {
  bytesPerSecond: number;
  percent: number;
  total?: number;
  transferred?: number;
}

/**
 * Security Event Type (matches Rust enum)
 */
export type SecurityEventType =
  | "KillSwitchStateChange"
  | "JailbreakRootDetected"
  | "CertificateValidationFailed"
  | "TamperingAlert"
  | "PanicInitiated"
  | "LoginAttempt"
  | "Logout";

/**
 * Security Event Record (matches Rust struct)
 */
export interface SecurityEvent {
  timestamp: number;
  device_id: string;
  app_version: string;
  event_type: SecurityEventType;
  details: string;
  success: boolean;
}

/**
 * Network Type (matches Rust enum)
 */
export type NetworkType = "WiFi" | "Ethernet" | "Cellular" | "Bluetooth" | "Unknown";

/**
 * Network Report (matches Rust struct)
 */
export interface NetworkReport {
  network_type: NetworkType;
  local_ip: string | null;
  gateway: string | null;
  dns_servers: string[];
  signal_strength: number | null;
  ssid: string | null;
  is_vpn_active: boolean;
  is_connected?: boolean;
  dpi_detected?: boolean;
  latency_ms?: number;
  server_report?: {
    geoip: string;
    recommendation: string;
  };
  packet_loss?: number;
}

/**
 * Electron API exposed via contextBridge
 * Available on window.electronAPI
 */
export interface ElectronAPI {
  // Version & System
  getNativeVersion: () => Promise<HelperVersion | string>;
  getMachineId: () => Promise<string>;
  startPasskeyAuth: () => Promise<PasskeyAuthResponse>;

  // Window Control
  closeApp: () => void;
  minimizeApp: () => void;

  // VPN Control
  connectVPN: (
    config: VPNConfig | string | { serverId: string; mode: "standard" | "fragmented" | "reality" },
  ) => Promise<{ success: boolean; error?: string }>;
  disconnectVPN: () => Promise<{ success: boolean; error?: string }>;
  getVPNStatus: () => Promise<VPNStatus>;

  // Obfuscation (Legacy Shadowsocks/UDP2RAW)
  startObfuscation: (
    config: ObfuscationConfig,
  ) => Promise<{ success: boolean; error?: string }>;
  stopObfuscation: () => Promise<{ success: boolean; error?: string }>;
  getObfuscationStatus: () => Promise<ObfuscationStatus>;

  // Sing-box (VLESS+REALITY)
  startSingBox: (
    config: SingBoxConfig,
  ) => Promise<{ success: boolean; error?: string }>;
  stopSingBox: () => Promise<{ success: boolean; error?: string }>;
  getSingBoxStatus: () => Promise<SingBoxStatus>;
  testSingBox: () => Promise<{
    success: boolean;
    latency?: number;
    error?: string;
  }>;

  // Smart Fallback (Auto DPI Bypass)
  enableSmartFallback: (
    config: SmartFallbackConfig,
  ) => Promise<{ success: boolean; error?: string }>;
  disableSmartFallback: () => Promise<{ success: boolean; error?: string }>;
  getSmartFallbackStatus: () => Promise<SmartFallbackConfig>;

  // Network Testing
  pingServer: (host: string) => Promise<number>;

  // Core Functions
  generateKeys: () => Promise<string[]>;
  solvePoW: (challenge: string, difficulty: number) => Promise<string>;
  getBestNode: (nodes: ServerNode[]) => Promise<ServerNode | null>;
  getPreferredMode: (region: string) => Promise<string>;

  // V3.6: Kill-Switch - Block internet if VPN disconnects unexpectedly
  enableKillSwitch: () => Promise<{ success: boolean; error?: string }>;
  disableKillSwitch: () => Promise<{ success: boolean; error?: string }>;

  // V3.6: Panic Wipe - Forensic resistance emergency trigger
  panicWipe: (options?: {
    silent?: boolean;
    reason?: string;
  }) => Promise<{ success: boolean; error?: string }>;

  // V3.8: Duress PIN Management
  setDuressPin: (pinHash: string) => Promise<boolean>;
  getDuressPin: () => Promise<string | null>;

  // V3.10: Traffic & Activity
  getTrafficStats: () => Promise<TrafficStats>;
  getSecurityEvents: () => Promise<SecurityEvent[]>;
  run_helper?: (options: { args: string[] }) => Promise<string>;
  getLogs: () => Promise<string[]>;
  getIdentityInfo: () => Promise<IdentityInfo>;
  logout: () => Promise<void>;
  getNetworkReport: () => Promise<NetworkReport>;
  runFullSpeedTest: () => Promise<SpeedTestResult>;
  setSplitTunnel: (config: { enabled: boolean; mode: "include" | "exclude"; apps: string[] }) => Promise<{ success: boolean; error?: string }>;

  // V3.11: Reality & Quantum Params
  encryptPairingData: (plaintext: number[], pin: string) => Promise<number[]>;
  decryptPairingData: (ciphertext: number[], pin: string) => Promise<number[]>;
  getQuantumParams: () => Promise<{ mtu: number; tcp_mss: number }>;
  verifyCoreIntegrity: () => Promise<boolean>;

  // V3.9: Camouflage Mode
  enableCamouflage: () => Promise<boolean>;
  disableCamouflage: () => Promise<boolean>;
  getCamouflageStatus: () => Promise<boolean>;
  onCamouflageToggled: (callback: (enabled: boolean) => void) => void;

  // V3.12: OS Citizenship
  setAutostart: (enabled: boolean) => Promise<void>;
  onDeepLinkReceived: (callback: (token: string) => void) => void;
  onTriggerConnect: (callback: (nodeId: string) => void) => void;

  // Event Listeners
  onVPNStatusChanged: (callback: (status: { connected: boolean; state: string }) => void) => void;
  onTrafficStatsChanged?: (callback: (stats: TrafficStats) => void) => void;
  onDaemonStatusChanged?: (callback: (online: boolean) => void) => void;
  onObfuscationStatusChanged: (
    callback: (status: ObfuscationStatus) => void,
  ) => void;
  onSingBoxStatusChanged: (callback: (status: SingBoxStatus) => void) => void;
  onUpdateAvailable: (callback: (info: UpdateInfo) => void) => void;
  onUpdateDownloaded: (callback: (info: UpdateInfo) => void) => void;
  onDownloadProgress: (callback: (percent: number) => void) => void;

  // Secure Storage
  setSecureToken: (key: string, value: string) => Promise<boolean>;
  getSecureToken: (key: string) => Promise<string | null>;
  removeSecureToken: (key: string) => Promise<boolean>;
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}

export {};
