import { test, expect } from "@playwright/test";
import { gotoDesktopApp } from "./fixtures";

test.describe("ShadowMesh Desktop E2E", () => {
  test("should show the login screen", async ({ page }) => {
    await gotoDesktopApp(page);
    await expect(page.getByRole("heading", { name: "ShadowMesh" })).toBeVisible();
    await expect(page.getByText(/Secure Identity Core/i)).toBeVisible();
  });

  test("should switch between login tabs reliably", async ({ page }) => {
    await gotoDesktopApp(page);

    await page.getByRole("button", { name: "Passkey" }).click();
    await expect(page.getByText("Biometric Login")).toBeVisible();

    await page.getByRole("button", { name: "Scan QR" }).click();
    await expect(page.getByText("Scan with your mobile app")).toBeVisible();

    await page.getByRole("button", { name: "Activation" }).click();
    await expect(
      page.getByPlaceholder(/XXXXX-XXXXX/i),
    ).toBeVisible();
  });

  test("should handle activation code input correctly", async ({ page }) => {
    await gotoDesktopApp(page);

    const input = page.getByPlaceholder(/XXXXX-XXXXX/i);
    await input.fill("ABCDE12345FGHIJ");
    // Formatted value: ABCDE-12345-FGHIJ
    await expect(input).toHaveValue("ABCDE-12345-FGHIJ");

    await expect(page.getByRole("button", { name: /Verify & Connect/i })).toBeEnabled();
  });

  test("should display correctly on different screen sizes", async ({
    page,
    viewport,
  }) => {
    await gotoDesktopApp(page);

    const loginCard = page.getByTestId("login-card");
    await expect(loginCard).toBeVisible();

    const bbox = await loginCard.boundingBox();
    expect(bbox).not.toBeNull();
    if (bbox && viewport) {
      expect(bbox.x + bbox.width).toBeLessThanOrEqual(viewport.width);
      expect(bbox.y + bbox.height).toBeLessThanOrEqual(viewport.height);
    }
  });
});
