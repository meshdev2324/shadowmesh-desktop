import React from "react";
import { render, screen, fireEvent, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import App from "../App";
import { createTestElectronAPI } from "./testElectronAPI";

describe("🔥 Panic Wipe Protocol", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.electronAPI = createTestElectronAPI({
      getSecureToken: vi.fn().mockImplementation((key: string) => {
        if (key === "vpn_desktop_token") return Promise.resolve("mock-token");
        return Promise.resolve(null);
      }),
    });
  });

  it("invokes the Forensic Wipe protocol via UI interaction", async () => {
    render(<App />);
    
    // Wait for Dashboard to hydrate and show (Big Tech Grade: Wait for specific elements)
    await screen.findByText(/System Integrity Verified/i, {}, { timeout: 5000 });
    
    // Navigate to Security tab
    const securityTab = await screen.findByRole("button", { name: /Security/i });
    act(() => {
      fireEvent.click(securityTab);
    });

    // Click Panic Protocol
    const panicBtn = await screen.findByText(/Panic Protocol/i);
    act(() => {
      fireEvent.click(panicBtn);
    });

    // Stage 1: Confirm Destruction
    const confirmBtn = await screen.findByRole("button", { name: /Confirm Destruction/i });
    act(() => {
      fireEvent.click(confirmBtn);
    });

    // Stage 2: DEPLOY PANIC NOW
    const deployBtn = await screen.findByRole("button", { name: /DEPLOY PANIC NOW/i });
    act(() => {
      fireEvent.click(deployBtn);
    });

    // Verify IPC call to core
    expect(window.electronAPI.panicWipe).toHaveBeenCalled();
  });
});
