/**
 * desktop/src/main/auth.ts
 *
 * Gather premium hardware and OS metrics from the Desktop environment
 * to provide rich context to mobile devices when a login is authorized.
 */

import { invoke } from "@tauri-apps/api/core";

export interface DesktopDeviceInfo {
  deviceId: string;
  deviceName: string;
  osName: string;
  osVersion: string;
  arch: string;
  timestamp: number;
}

/**
 * Capture Desktop hardware and operating system metrics.
 * Safely falls back to navigator info if Tauri APIs are unavailable.
 */
export async function getDesktopDeviceInfo(): Promise<DesktopDeviceInfo> {
  let deviceId = "unknown-desktop";
  let deviceName = "Unknown Desktop";
  let osName = "Unknown OS";
  let osVersion = "Unknown Version";
  let arch = "unknown";

  try {
    // 1. Retrieve unique persistent hardware machine ID
    deviceId = await invoke<string>("get_machine_id").catch(() => "unknown-desktop");

    // 2. Fetch native OS/system metrics via Tauri commands or helper
    const versionRes = await invoke<string>("run_helper", { args: ["version"] }).catch(() => "");
    if (versionRes) {
      // Parse potential version metrics from the Rust Daemon (e.g. "ShadowMesh Daemon v4.1.0-linux-amd64")
      const parts = versionRes.split("-");
      if (parts.length >= 2) {
        osName = parts[1];
      }
      if (parts.length >= 3) {
        arch = parts[2];
      }
    }
  } catch (e) {
    console.warn("Tauri context not available. Falling back to browser/navigator properties.", e);
  }

  // Browser/Navigator Fallbacks
  if (typeof navigator !== "undefined") {
    if (osName === "Unknown OS") {
      if (navigator.userAgent.indexOf("Win") !== -1) osName = "Windows";
      else if (navigator.userAgent.indexOf("Mac") !== -1) osName = "macOS";
      else if (navigator.userAgent.indexOf("Linux") !== -1) osName = "Linux";
    }

    if (deviceName === "Unknown Desktop") {
      deviceName = `${osName} Device`;
    }
  }

  return {
    deviceId,
    deviceName,
    osName,
    osVersion,
    arch,
    timestamp: Date.now(),
  };
}

/**
 * Standardize full request payload sent to the /api/v1/auth/qr/generate endpoint.
 */
export async function prepareQRGeneratePayload() {
  const info = await getDesktopDeviceInfo();
  return {
    device_id: info.deviceId,
    device_name: info.deviceName,
    os_name: info.osName,
    os_version: info.osVersion,
    arch: info.arch,
    timestamp: info.timestamp,
  };
}

/**
 * Generate a transient anonymous pub/sub topic ID by hashing the user's public key (SHA-256).
 */
export async function generateNotifyHash(publicKey: string): Promise<string> {
  if (!publicKey) return "";
  const encoder = new TextEncoder();
  const data = encoder.encode(publicKey);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Desktop publishes a "Login Event" to the hashed topic.
 */
export async function publishLoginEvent(publicKey: string) {
  try {
    const info = await getDesktopDeviceInfo();
    const topicId = await generateNotifyHash(publicKey);
    if (!topicId) return;

    const apiBaseUrl = (typeof process !== "undefined" && process.env?.VITE_API_URL) || "http://localhost:8080";
    const endpoint = `${apiBaseUrl}/api/v1/pubsub/publish/${topicId}`;

    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        event: "desktop_login",
        device_id: info.deviceId,
        device_name: info.deviceName,
        os_name: info.osName,
        os_version: info.osVersion,
        arch: info.arch,
        timestamp: Math.floor(Date.now() / 1000),
      }),
    });

    if (!response.ok) {
      console.error("Failed to publish login event to transient topic:", response.statusText);
    } else {
      console.log("🚀 Secure OOB login event published to hashed topic:", topicId);
    }
  } catch (err) {
    console.error("Error publishing login event:", err);
  }
}

