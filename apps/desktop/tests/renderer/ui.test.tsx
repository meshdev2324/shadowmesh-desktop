import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import App from "../../src/renderer/App";
import "@testing-library/jest-dom/vitest";

// Mock the Electron window.electronAPI object (bridge)
const mockElectron = {
  connectVPN: vi.fn().mockResolvedValue({ success: true }),
  disconnectVPN: vi.fn().mockResolvedValue({ success: true }),
  pingServer: vi.fn().mockResolvedValue(25),
  getSecureToken: vi.fn().mockResolvedValue("mock-token"),
  setSecureToken: vi.fn().mockResolvedValue(true),
  removeSecureToken: vi.fn().mockResolvedValue(true),
  onVPNStatusChanged: vi.fn(),
  onObfuscationStatusChanged: vi.fn(),
  onCamouflageToggled: vi.fn(),
  getCamouflageStatus: vi.fn().mockResolvedValue(false),
  enableCamouflage: vi.fn().mockResolvedValue(true),
  disableCamouflage: vi.fn().mockResolvedValue(true),
  getNativeVersion: vi.fn().mockResolvedValue("3.9.0"),
  getDuressPin: vi.fn().mockResolvedValue(null),
};

(window as any).electronAPI = mockElectron;

describe("Desktop Renderer UI (Electron)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the main dashboard correctly", async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/Ready to Secure/i)).toBeInTheDocument();
    });
  });

  it("triggers VPN connection when connect button is clicked", async () => {
    mockElectron.connectVPN = vi.fn().mockResolvedValue({ success: true });
    
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/Ready to Secure/i)).toBeInTheDocument();
    });

    // The connect button
    const connectButton = screen.getByTestId("vpn-toggle-button");
    fireEvent.click(connectButton);

    await waitFor(() => {
      expect(mockElectron.connectVPN).toHaveBeenCalled();
    });
  });

  it("displays Quantum Tunneling status in connection options", async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/Features/i)).toBeInTheDocument();
    });

    const featuresTab = screen.getByText(/Features/i);
    fireEvent.click(featuresTab);

    await waitFor(() => {
      expect(screen.getByText(/Quantum Tunneling/i)).toBeInTheDocument();
    });
  });

  it("handles camouflage mode toggle", async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/Features/i)).toBeInTheDocument();
    });

    const featuresTab = screen.getByText(/Features/i);
    fireEvent.click(featuresTab);

    // Find the enable button within Camouflage section
    await waitFor(() => {
      expect(screen.getByText(/Enable Camouflage/i)).toBeInTheDocument();
    });

    const enableButton = screen.getByRole("button", { name: /Enable/i });
    fireEvent.click(enableButton);

    await waitFor(() => {
      expect(mockElectron.enableCamouflage).toHaveBeenCalled();
    });
  });
});
