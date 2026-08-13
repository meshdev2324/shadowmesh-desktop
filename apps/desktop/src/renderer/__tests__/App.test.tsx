import React from "react";
import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import App from "../App";
import { createTestElectronAPI } from "./testElectronAPI";

describe("ShadowMesh Professional UI", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Mock the window.electronAPI with all required functions
    window.electronAPI = createTestElectronAPI({
      getSecureToken: vi.fn().mockImplementation((key: string) => {
        if (key === "vpn_desktop_token") return Promise.resolve("mock-token");
        if (key === "vpn_activation_code") return Promise.resolve("UVPN-TEST-CODE");
        return Promise.resolve(null);
      }),
    });
  });

  it("renders the main dashboard with professional branding", async () => {
    render(<App />);

    // Wait for authentication and dashboard to load
    await screen.findByText(/System Integrity Verified/i, {}, { timeout: 5000 });

    // Check for professional branding
    expect(screen.getByText(/Shadow/i)).toBeInTheDocument();
    expect(screen.getByText(/Mesh/i)).toBeInTheDocument();
  });

  it("displays security status badges correctly", async () => {
    render(<App />);

    // Status badges should be visible
    const serverStatus = await screen.findByText(/Not Connected/i);
    expect(serverStatus).toBeInTheDocument();
  });

  it("triggers VPN toggle with proper state updates", async () => {
    render(<App />);

    const connectBtn = await screen.findByTestId("vpn-toggle-button");
    expect(connectBtn).toBeInTheDocument();

    act(() => {
      fireEvent.click(connectBtn);
    });

    // Should show connecting state
    await waitFor(() => {
      expect(screen.getByText(/Disconnected\.\.\./i)).toBeInTheDocument();
    });
  });

  it("navigates between VPN and Security tabs", async () => {
    render(<App />);

    const securityTab = await screen.findByRole("button", { name: /Security/i });
    act(() => {
      fireEvent.click(securityTab);
    });

    // Should show feature titles
    await expect(screen.findByText(/Network Kill Switch/i)).resolves.toBeInTheDocument();
    await expect(screen.findByText(/Stealth Obfuscation/i)).resolves.toBeInTheDocument();
  });

  it("opens panic wipe confirmation modal", async () => {
    render(<App />);

    // Navigate to Security
    const securityTab = await screen.findByRole("button", { name: /Security/i });
    act(() => {
      fireEvent.click(securityTab);
    });

    // Click panic button
    const panicBtn = await screen.findByText(/Panic Protocol/i);
    act(() => {
      fireEvent.click(panicBtn);
    });

    // Confirmation should appear
    await expect(screen.findByText(/Emergency Purge/i)).resolves.toBeInTheDocument();
  });
});
