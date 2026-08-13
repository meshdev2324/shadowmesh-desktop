import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: process.env.CI ? 300 * 1000 : 60 * 1000,
  expect: {
    timeout: process.env.CI ? 30000 : 10000,
  },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI ? "line" : "html",
  use: {
    baseURL: "http://localhost:5174",
    trace: "on-first-retry",
  },
  projects: process.env.CI
    ? [
        {
          name: "renderer-1080p",
          use: {
            ...devices["Desktop Chrome"],
            viewport: { width: 1920, height: 1080 },
          },
        },
      ]
    : [
        {
          name: "renderer-1080p",
          use: {
            ...devices["Desktop Chrome"],
            viewport: { width: 1920, height: 1080 },
          },
        },
        {
          name: "renderer-768p",
          use: {
            ...devices["Desktop Chrome"],
            viewport: { width: 1366, height: 768 },
          },
        },
        {
          name: "renderer-900p",
          use: {
            ...devices["Desktop Chrome"],
            viewport: { width: 1440, height: 900 },
          },
        },
      ],
  webServer: {
    command: process.env.CI ? "npm run preview:e2e" : "npm run serve:e2e",
    url: "http://localhost:5174",
    reuseExistingServer: !process.env.CI,
    timeout: 180000,
  },
});
