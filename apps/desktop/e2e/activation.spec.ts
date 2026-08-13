import { test, expect } from "@playwright/test";
import { gotoDesktopApp, installElectronAPIMock } from "./fixtures";

test.describe("🔐 Desktop Activation Flow (Big-Tech Grade)", () => {
  test("successfully activates with valid code and navigates to VPN dashboard", async ({ page }) => {
    await installElectronAPIMock(page, { authenticated: false });
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // 1. Verify initial activation state (ZPII Identity Core)
    await expect(page.getByText(/Secure Identity Core/i)).toBeVisible();

    // 2. Input valid code (25-character format)
    const input = page.getByPlaceholder(/XXXXX-XXXXX/i);
    await input.waitFor({ state: "visible" });
    await input.fill("UVPN-TEST-CODE-2026-ALPHA-01");

    // 3. Trigger activation
    const activateBtn = page.getByRole("button", { name: /Verify & Connect/i });
    await activateBtn.click();

    // 4. Verify success feedback
    await expect(page.getByText(/Successful/i).first()).toBeVisible({ timeout: 10000 });

    // 5. Verify navigation to VPN dashboard
    await expect(page.getByTestId("dash-tab-vpn")).toBeVisible({ timeout: 15000 });
    await expect(page.getByText(/Not Connected/i)).toBeVisible();
  });

  test("handles network failures during activation with retry feedback", async ({ page }) => {
    await installElectronAPIMock(page, { authenticated: false });

    // Mock a failure for the activation IPC call
    await page.addInitScript(() => {
       window.electronAPI.run_helper = async (args: { args: string[] }) => {
         if (args.args[0] === "activate") {
            throw new Error("Network Timeout: Control Plane Unreachable");
         }
         return JSON.stringify({});
       };
    });

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const input = page.getByPlaceholder(/XXXXX-XXXXX/i);
    await input.waitFor({ state: "visible" });
    await input.fill("FAIL-CODE-TEST-INVALID-01");

    await page.getByRole("button", { name: /Verify & Connect/i }).click();

    // Verify error display
    await expect(page.getByText(/Network Timeout/i)).toBeVisible({ timeout: 10000 });
  });

  test("full connection lifecycle: select node and establish tunnel", async ({ page }) => {
    // Start already authenticated
    await installElectronAPIMock(page, { authenticated: true });
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // 1. Ensure we are on VPN dashboard
    const vpnTab = page.getByTestId("dash-tab-vpn");
    await expect(vpnTab).toBeVisible();

    // 2. Open Location Selection via the Active Gateway card
    await page.getByTestId("active-gateway-card").click();

    // Shadow-Mesh Robustness: Wait for the server list to populate and node to appear
    const nodeItem = page.getByText(/US-East-1/i).first();
    await expect(nodeItem).toBeVisible({ timeout: 30000 });
    await nodeItem.click();

    // 4. Trigger Connect
    const connectBtn = page.getByTestId("vpn-toggle-button");
    await connectBtn.click();

    // 5. Verify connection state
    // Shadow-Mesh Robustness: Use anchored regex and wait for telemetry-driven updates
    await expect(connectBtn).toContainText(/^Protected$/i, { timeout: 45000 });

    // Explicitly wait for MB/s stats to appear (driven by mocked telemetry in fixtures.ts)
    const downloadStat = page.getByTestId("vpn-stat-download");
    await expect(downloadStat).toContainText(/MB\/s/i, { timeout: 30000 });
  });
});
