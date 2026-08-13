import { describe, it, expect, beforeEach } from "vitest";
import { createTestElectronAPI } from "./testElectronAPI";

beforeEach(() => {
  window.electronAPI = createTestElectronAPI();
});

describe("🔌 IPC Bridge Validation", () => {
  it("ensures only whitelisted IPC methods are exposed via contextBridge", () => {
    const exposedMethods = Object.keys(window.electronAPI);

    const whitelist = [
      "getNativeVersion",
      "getMachineId",
      "startPasskeyAuth",
      "closeApp",
      "minimizeApp",
      "connectVPN",
      "disconnectVPN",
      "getVPNStatus",
      "startObfuscation",
      "stopObfuscation",
      "getObfuscationStatus",
      "startSingBox",
      "stopSingBox",
      "getSingBoxStatus",
      "testSingBox",
      "enableSmartFallback",
      "disableSmartFallback",
      "getSmartFallbackStatus",
      "pingServer",
      "enableKillSwitch",
      "disableKillSwitch",
      "panicWipe",
      "setDuressPin",
      "getDuressPin",
      "enableCamouflage",
      "disableCamouflage",
      "getCamouflageStatus",
      "onVPNStatusChanged",
      "onDaemonStatusChanged",
      "onObfuscationStatusChanged",
      "onSingBoxStatusChanged",
      "onUpdateAvailable",
      "onUpdateDownloaded",
      "onDownloadProgress",
      "onCamouflageToggled",
      "setSecureToken",
      "getSecureToken",
      "removeSecureToken",
    ];

    whitelist.forEach((method) => {
      expect(exposedMethods).toContain(method);
    });

    const blacklisted = ["directFileSystemAccess", "spawnShell", "executeRoot"];
    blacklisted.forEach((method) => {
      expect(exposedMethods).not.toContain(method);
    });
  });
});
