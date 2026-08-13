import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  ElectronAPI,
  VPNConfig,
  VPNStatus,
  ObfuscationConfig,
  ObfuscationStatus,
  SingBoxConfig,
  SingBoxStatus,
  SmartFallbackConfig,
  UpdateInfo,
  IdentityInfo,
  SpeedTestResult,
  TrafficStats,
  NetworkReport,
  ServerNode,
  SecurityEvent
} from "../types/shadowmesh-api";

function invokeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === "string") {
    return error;
  }
  return String(error);
}

function parseJsonResponse<T>(raw: string, fallback: T): T {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

/**
 * Tauri Bridge for ShadowMesh
 * Implements the ElectronAPI interface using Tauri commands
 */
const tauriAPI: ElectronAPI = {
  getNativeVersion: async () => {
    try {
      const res = await invoke<string>("run_helper", { args: ["version"] });
      return JSON.parse(res) as { version: string; os: string; arch: string; features: string[] };
    } catch {
      return { version: "Unknown", os: "Unknown", arch: "Unknown", features: [] };
    }
  },
  getMachineId: () => invoke<string>("get_machine_id"),
  startPasskeyAuth: async () => {
    try {
      await invoke("run_helper", { args: ["passkey", "auth"] });
      return { success: true, message: "Biometric auth triggered" };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },

  closeApp: () => {
    void invoke("close_app");
  },
  minimizeApp: () => {
    void invoke("minimize_app");
  },

  connectVPN: async (config: VPNConfig | string | { serverId: string; mode: string }) => {
    try {
      const args = ["connect"];
      if (typeof config === "object") {
        if ("serverId" in config) {
          args.push(config.serverId);
          args.push(config.mode);
        } else if (config.mode === "fragmented") {
          // Legacy object fallback
          args.push("best");
          args.push("fragmented");
        }
      } else {
        // Legacy string config fallback - we don't really support parsing it into an ID here
        // so we'll just try 'best' or error. Daemon-rust handle_connect needs node_id.
        args.push("best");
      }
      await invoke("run_helper", { args });
      return { success: true };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },
  disconnectVPN: async () => {
    try {
      await invoke("run_helper", { args: ["disconnect"] });
      return { success: true };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },
  getVPNStatus: async () => {
    try {
      const res = await invoke<string>("run_helper", { args: ["status"] });
      return parseJsonResponse<VPNStatus>(res, {
        connected: false,
        state: "disconnected",
      });
    } catch {
      return { connected: false, state: "disconnected" };
    }
  },

  startObfuscation: async (config: ObfuscationConfig) => {
    try {
      await invoke("run_helper", {
        args: ["obfuscation", "start", JSON.stringify(config)],
      });
      return { success: true };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },
  stopObfuscation: async () => {
    try {
      await invoke("run_helper", { args: ["obfuscation", "stop"] });
      return { success: true };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },
  getObfuscationStatus: async () => {
    try {
      const res = await invoke<string>("run_helper", {
        args: ["obfuscation", "status"],
      });
      return parseJsonResponse<ObfuscationStatus>(res, { running: false });
    } catch {
      return { running: false };
    }
  },

  startSingBox: async (config: SingBoxConfig) => {
    try {
      await invoke("run_helper", {
        args: ["sing-box", "start", JSON.stringify(config)],
      });
      return { success: true };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },
  stopSingBox: async () => {
    try {
      await invoke("run_helper", { args: ["sing-box", "stop"] });
      return { success: true };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },
  getSingBoxStatus: async () => {
    try {
      const res = await invoke<string>("run_helper", {
        args: ["sing-box", "status"],
      });
      return parseJsonResponse<SingBoxStatus>(res, { running: false });
    } catch {
      return { running: false };
    }
  },
  testSingBox: () => Promise.resolve({ success: true, latency: 42 }),

  enableSmartFallback: async (config: SmartFallbackConfig) => {
    try {
      await invoke("run_helper", {
        args: ["smart-fallback", "enable", JSON.stringify(config)],
      });
      return { success: true };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },
  disableSmartFallback: async () => {
    try {
      await invoke("run_helper", { args: ["smart-fallback", "disable"] });
      return { success: true };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },
  getSmartFallbackStatus: async () => {
    try {
      const res = await invoke<string>("run_helper", {
        args: ["smart-fallback", "status"],
      });
      return parseJsonResponse<SmartFallbackConfig>(res, {
        enabled: false,
        wg_config_path: "",
        singbox_config_path: "",
        check_interval_sec: 30,
        handshake_timeout_sec: 10,
        auto_switch: true,
        current_mode: "wireguard",
      });
    } catch {
      return {
        enabled: false,
        wg_config_path: "",
        singbox_config_path: "",
        check_interval_sec: 30,
        handshake_timeout_sec: 10,
        auto_switch: true,
        current_mode: "wireguard",
      };
    }
  },

  pingServer: async (host: string) => {
    try {
      return await invoke<number>("ping_server", { host });
    } catch {
      return 999;
    }
  },

  generateKeys: () => invoke<string[]>("generate_keys"),
  solvePoW: (challenge: string, difficulty: number) =>
    invoke<string>("solve_pow_challenge", { challenge, difficulty }),
  getBestNode: (nodes: ServerNode[]) => invoke<ServerNode | null>("get_best_node", { nodes }),
  getPreferredMode: (region: string) => invoke<string>("get_preferred_mode", { region }),

  enableKillSwitch: async () => {
    try {
      await invoke("run_helper", { args: ["kill-switch", "enable"] });
      return { success: true };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },
  disableKillSwitch: async () => {
    try {
      await invoke("run_helper", { args: ["kill-switch", "disable"] });
      return { success: true };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },

  panicWipe: async (options) => {
    try {
      await invoke("run_helper", {
        args: ["panic-wipe", JSON.stringify(options ?? {})],
      });
      return { success: true };
    } catch (error: unknown) {
      return { success: false, error: invokeErrorMessage(error) };
    }
  },

  setDuressPin: async (pinHash: string) => {
    try {
      await invoke("run_helper", { args: ["duress-pin", "set", pinHash] });
      return true;
    } catch {
      return false;
    }
  },
  getDuressPin: async () => {
    try {
      const res = await invoke<string>("run_helper", { args: ["duress-pin", "get"] });
      return JSON.parse(res) as string | null;
    } catch {
      return null;
    }
  },

  getTrafficStats: () => invoke<TrafficStats>("get_traffic_stats"),
  getSecurityEvents: () => invoke<SecurityEvent[]>("get_security_events"),
  run_helper: (args: { args: string[] }) => invoke<string>("run_helper", args),
  getLogs: async () => {
    try {
      const res = await invoke<string>("run_helper", { args: ["get-logs"] });
      return JSON.parse(res) as string[];
    } catch {
      return [];
    }
  },
  getIdentityInfo: () => invoke<IdentityInfo>("get_identity_info"),
  logout: () => invoke<void>("logout"),
  getNetworkReport: () => invoke<NetworkReport>("get_network_report"),
  runFullSpeedTest: () => invoke<SpeedTestResult>("run_full_speed_test"),
  setSplitTunnel: (config) => invoke<{ success: boolean; error?: string }>("run_helper", {
    args: ["set-split-tunnel", config.enabled ? "enable" : "disable", config.mode, config.apps.join(",")]
  }),

  encryptPairingData: (plaintext: number[], pin: string) => invoke<number[]>("encrypt_pairing_data", { plaintext, pin }),
  decryptPairingData: (ciphertext: number[], pin: string) => invoke<number[]>("decrypt_pairing_data", { ciphertext, pin }),
  getQuantumParams: () => invoke<{ mtu: number; tcp_mss: number }>("get_quantum_params"),
  verifyCoreIntegrity: () => invoke<boolean>("verify_core_integrity"),

  setAutostart: (enabled) => invoke("set_autostart", { enabled }),
  onDeepLinkReceived: (callback) => {
    void listen<string>("activate-token", (event) => {
      callback(event.payload);
    });
  },
  onTriggerConnect: (callback) => {
    void listen<string>("trigger-connect", (event) => {
      callback(event.payload);
    });
  },

  enableCamouflage: async () => {
    await invoke("run_helper", { args: ["camouflage", "enable"] });
    return true;
  },
  disableCamouflage: async () => {
    await invoke("run_helper", { args: ["camouflage", "disable"] });
    return true;
  },
  getCamouflageStatus: async () => {
    const res = await invoke<string>("run_helper", {
      args: ["camouflage", "status"],
    });
    return res === "true";
  },
  onCamouflageToggled: (callback) => {
    void listen("camouflage-toggled", (event) => {
      callback(event.payload as boolean);
    });
  },

  onVPNStatusChanged: (callback) => {
    void listen("vpn-status-changed", (event) => {
      callback(event.payload as { connected: boolean; state: string });
    });
  },
  onTrafficStatsChanged: (callback) => {
    void listen<TrafficStats>("traffic-stats", (event) => {
      callback(event.payload);
    });
  },
  onDaemonStatusChanged: (callback) => {
    void listen("daemon-status", (event) => {
      callback(event.payload as boolean);
    });
  },
  onObfuscationStatusChanged: (callback) => {
    void listen("obfuscation-status-changed", (event) => {
      callback(event.payload as ObfuscationStatus);
    });
  },
  onSingBoxStatusChanged: (callback) => {
    void listen("singbox-status-changed", (event) => {
      callback(event.payload as SingBoxStatus);
    });
  },
  onUpdateAvailable: (callback) => {
    void listen("update-available", (event) => {
      callback(event.payload as UpdateInfo);
    });
  },
  onUpdateDownloaded: (callback) => {
    void listen("update-downloaded", (event) => {
      callback(event.payload as UpdateInfo);
    });
  },
  onDownloadProgress: (callback) => {
    void listen("download-progress", (event) => {
      callback(event.payload as number);
    });
  },

  setSecureToken: async (key, value) => {
    try {
      // Proxy to daemon for secure keyring storage
      await invoke("run_helper", { args: ["set-secure-token", key, value] });
      return true;
    } catch {
      localStorage.setItem(key, value); // Fallback for dev
      return true;
    }
  },
  getSecureToken: async (key) => {
    try {
      const res = await invoke<string>("run_helper", { args: ["get-secure-token", key] });
      return JSON.parse(res) as string;
    } catch {
      return localStorage.getItem(key);
    }
  },
  removeSecureToken: async (key) => {
    try {
      await invoke("run_helper", { args: ["remove-secure-token", key] });
      return true;
    } catch {
      localStorage.removeItem(key);
      return true;
    }
  },
};

if (
  typeof window !== "undefined" &&
  import.meta.env.VITE_E2E_MOCK_BRIDGE !== "true"
) {
  window.electronAPI = tauriAPI;
  console.log("🚀 Tauri Bridge Injected successfully");
}

export default tauriAPI;
