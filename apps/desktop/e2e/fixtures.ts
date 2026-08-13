import { expect, type Page } from "@playwright/test";

/** Injects a browser-safe ElectronAPI mock before the renderer loads (Tauri E2E). */
export async function installElectronAPIMock(
  page: Page,
  options?: { authenticated?: boolean },
): Promise<void> {
  // Mock common API endpoints for CI stability (Deterministic Responses)
  await page.route("**/api/servers/ping", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        {
          id: "us-east-1",
          name: "US-East-1",
          country_code: "US",
          public_ip: "127.0.0.1",
          load: 10,
        },
      ]),
    });
  });

  await page.route("**/api/v1/auth/activate", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        message: "Activation successful",
        token: "e2e-test-token",
        code_info: {
          code: "E2E-TEST-CODE",
          type: "Solo",
          expires_at: "2030-01-01T00:00:00Z",
        },
      }),
    });
  });

  // Expose a test-only API to trigger forensic screen directly from tests
  try {
    await page.exposeFunction("__test_triggerForensic", () => {
      return page.evaluate(() => {
        window.dispatchEvent(new CustomEvent("TEST_TRIGGER_FORENSIC"));
      });
    });
  } catch (err: any) {
    // Playwright throws when the function is already registered; safe to ignore.
    if (!/already registered/.test(String(err))) throw err;
  }

  await page.addInitScript(({ authenticated }) => {
    const storage = new Map<string, string>();
    if (authenticated) {
      storage.set("vpn_desktop_token", "e2e-desktop-token");
      storage.set("vpn_activation_code", "ABCDE12345FGHIJKLMNOPQRST");
    }
    let camouflageCallback: ((enabled: boolean) => void) | undefined;
    let camouflageEnabled = false;
    let statsCallback: ((stats: any) => void) | undefined;

    window.electronAPI = {
      getNativeVersion: async () => "1.0.0-e2e",
      getMachineId: async () => "e2e-desktop-machine-id",
      startPasskeyAuth: async () => ({
        success: true,
        message: "Biometric auth triggered",
      }),
      closeApp: () => undefined,
      minimizeApp: () => undefined,
      connectVPN: async () => ({ success: true }),
      disconnectVPN: async () => ({ success: true }),
      getVPNStatus: async () => ({ connected: false, state: "disconnected" }),
      startObfuscation: async () => ({ success: true }),
      stopObfuscation: async () => ({ success: true }),
      getObfuscationStatus: async () => ({ running: false }),
      startSingBox: async () => ({ success: true }),
      stopSingBox: async () => ({ success: true }),
      getSingBoxStatus: async () => ({ running: false }),
      testSingBox: async () => ({ success: true, latency: 42 }),
      enableSmartFallback: async () => ({ success: true }),
      disableSmartFallback: async () => ({ success: true }),
      getSmartFallbackStatus: async () => ({
        enabled: false,
        wg_config_path: "",
        singbox_config_path: "",
        check_interval_sec: 30,
        handshake_timeout_sec: 10,
        auto_switch: true,
        current_mode: "wireguard",
      }),
      pingServer: async () => 10,
      generateKeys: async () => ["priv", "pub"],
      solvePoW: async () => "solution",
      getBestNode: async (nodes) => nodes[0] ?? null,
      getPreferredMode: async () => "speed",
      setSplitTunnel: async () => ({ success: true }),
      enableKillSwitch: async () => ({ success: true }),
      disableKillSwitch: async () => ({ success: true }),
      panicWipe: async () => {
        window.dispatchEvent(new CustomEvent("TEST_TRIGGER_FORENSIC"));
        return { success: true };
      },
      setDuressPin: async (pinHash: string) => {
        if (pinHash) {
          storage.set("duress_pin", pinHash);
        } else {
          storage.delete("duress_pin");
        }
        return true;
      },
      getDuressPin: async () => storage.get("duress_pin") ?? null,
      getTrafficStats: async () => ({
        connected: false,
        status: "disconnected",
        recv_bps: 0,
        sent_bps: 0,
        total_recv: 0,
        total_sent: 0,
        totalBytes: 1024 * 1024 * 50,
        monthlyBytes: 1024 * 1024 * 10
      }),
      getSecurityEvents: async () => [],
      getLogs: async () => [],
      getIdentityInfo: async () => ({
        device_id: "e2e-device",
        session_id: "e2e-session",
        plan: "Solo",
        expires_at: null,
      }),
      logout: async () => undefined,
      getNetworkReport: async () => ({
        network_type: "WiFi",
        local_ip: null,
        gateway: null,
        dns_servers: [],
        signal_strength: null,
        ssid: null,
        is_vpn_active: false,
      }),
      runFullSpeedTest: async () => ({
        download_bps: 10000000,
        upload_bps: 5000000,
        latency_ms: 20,
        jitter_ms: 2,
      }),
      encryptPairingData: async (p) => p,
      decryptPairingData: async (c) => c,
      getQuantumParams: async () => ({ mtu: 1420, tcp_mss: 1380 }),
      verifyCoreIntegrity: async () => true,
      setAutostart: async () => undefined,
      onDeepLinkReceived: () => undefined,
      onTriggerConnect: () => undefined,
      enableCamouflage: async () => {
        camouflageEnabled = true;
        camouflageCallback?.(true);
        return true;
      },
      disableCamouflage: async () => {
        camouflageEnabled = false;
        camouflageCallback?.(false);
        return true;
      },
      getCamouflageStatus: async () => camouflageEnabled,
      onCamouflageToggled: (callback) => {
        camouflageCallback = callback;
      },
      onVPNStatusChanged: () => undefined,
      onTrafficStatsChanged: (callback) => {
        statsCallback = callback;
        // Shadow-Mesh Telemetry: Emit dummy stats periodically for E2E visibility
        setInterval(() => {
          statsCallback?.({
            connected: true,
            status: "connected",
            recv_bps: 1024 * 1024 * 1.2, // 1.2 MB/s
            sent_bps: 1024 * 512,
            total_recv: 1024 * 1024 * 100,
            total_sent: 1024 * 1024 * 20,
            traffic_mode: "reality",
            plan: "Solo"
          });
        }, 1000);
      },
      onDaemonStatusChanged: () => undefined,
      onObfuscationStatusChanged: () => undefined,
      onSingBoxStatusChanged: () => undefined,
      onUpdateAvailable: () => undefined,
      onUpdateDownloaded: () => undefined,
      onDownloadProgress: () => undefined,
      run_helper: async (args: { args: string[] }) => {
        if (args.args[0] === "activate") {
          return JSON.stringify({
            message: "Activation successful",
            token: "e2e-test-token",
            code_info: { code: args.args[1] || "TEST-CODE" }
          });
        }
        return JSON.stringify({});
      },
      setSecureToken: async (key, value) => {
        storage.set(key, value);
        return true;
      },
      getSecureToken: async (key) => storage.get(key) ?? null,
      removeSecureToken: async (key) => {
        storage.delete(key);
        return true;
      },
    };
  }, { authenticated: options?.authenticated ?? false });
}

export async function gotoAuthenticatedDesktop(page: Page): Promise<void> {
  await installElectronAPIMock(page, { authenticated: true });
  await page.goto("/");

  // Wait for the app to settle
  await page.waitForLoadState("networkidle");

  // Resilience: If somehow we are stuck on activation despite being "authenticated" in mock
  const activationInput = page.getByPlaceholder(/XXXXX-XXXXX/i);
  const vpnTab = page.getByTestId("dash-tab-vpn");

  // Race between activation input and dashboard mount
  await Promise.race([
    activationInput.waitFor({ state: "visible", timeout: 10000 }).catch(() => {}),
    vpnTab.waitFor({ state: "visible", timeout: 10000 }).catch(() => {})
  ]);

  if (await activationInput.isVisible()) {
    await activationInput.fill("E2E-AUTH-BYPASS-CODE-2026");
    await page.getByRole("button", { name: /Verify & Connect/i }).click();
  }

  // Final guard: Ensure we are on the dashboard
  await expect(vpnTab).toBeVisible({ timeout: 20000 });
}

export async function gotoDesktopApp(page: Page): Promise<void> {
  await installElectronAPIMock(page);
  await page.goto("/");
  await page.waitForLoadState("networkidle");
  await expect(page.getByRole("heading", { name: /ShadowMesh/i })).toBeVisible({ timeout: 20000 });
}
