import { test, expect } from "@playwright/test";
import { gotoDesktopApp } from "./fixtures";

test.describe("Camouflage Mode E2E", () => {
  test("should toggle decoy layout and hide VPN elements", async ({ page }) => {
    await gotoDesktopApp(page);

    await expect(page.getByRole("heading", { name: /ShadowMesh/i })).toBeVisible();
    await expect(page.getByText("Calculator")).not.toBeVisible();

    await page.evaluate(() => {
      void window.electronAPI.enableCamouflage();
    });

    await expect(page.getByText("Calculator")).toBeVisible();
    await expect(page.getByRole("heading", { name: "SHADOWMESH" })).not.toBeVisible();

    await page.getByRole("button", { name: "7", exact: true }).click();
    await page.getByRole("button", { name: "+", exact: true }).click();
    await page.getByRole("button", { name: "5", exact: true }).click();
    await page.getByRole("button", { name: "=", exact: true }).click();
    await expect(page.getByTestId("calculator-display")).toHaveText("12");

    await page.evaluate(() => {
      void window.electronAPI.disableCamouflage();
    });

    await expect(page.getByRole("heading", { name: /ShadowMesh/i })).toBeVisible();
    await expect(page.getByText("Calculator")).not.toBeVisible();
  });
});
