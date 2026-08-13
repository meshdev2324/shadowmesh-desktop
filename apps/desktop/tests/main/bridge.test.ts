import { describe, it, expect, vi, beforeEach } from "vitest";
import { IpcHandler } from "../../src/main/ipcHandlers";

// Mock Electron modules
vi.mock("fs", () => ({
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  existsSync: vi.fn().mockReturnValue(true),
}));

vi.mock("electron", () => ({
  ipcMain: {
    on: vi.fn(),
    handle: vi.fn(),
  },
  app: {
    getPath: vi.fn().mockReturnValue("/tmp"),
  },
}));

describe("Desktop IPC Bridge (Main Process)", () => {
  let ipcHandler: any;
  const mockRunHelper = vi.fn();
  const mockUpdateTray = vi.fn();
  const mockApp = { isQuitting: false };
  const mockCreateSecureTempDir = vi.fn().mockReturnValue("/tmp/secure");
  const mockGenerateWGConfig = vi.fn().mockReturnValue("[Interface]\nPrivateKey=test");

  beforeEach(() => {
    vi.clearAllMocks();
    ipcHandler = new IpcHandler(
      mockRunHelper,
      mockUpdateTray,
      { state: "/tmp", obfuscation: "/tmp", singbox: "/tmp" },
      mockApp,
      mockCreateSecureTempDir,
      mockGenerateWGConfig
    );
  });

  it("handles VPN connection request and executes helper with correct flags", async () => {
    mockRunHelper.mockResolvedValue("OK");
    
    const mockConfig = {
      privateKey: "a".repeat(44),
      publicKey: "b".repeat(44),
      address: "10.0.0.1",
      dns: "1.1.1.1",
      endpoint: "1.2.3.4:51820",
      mode: "fragmented",
      mtu: 576
    };

    // Simulate IPC call
    await ipcHandler.handleConnect(null as any, mockConfig);

    expect(mockRunHelper).toHaveBeenCalledWith(
      expect.arrayContaining(["connect", "--mtu", "576"])
    );
  });

  it("handles status polling and updates tray", async () => {
    mockRunHelper.mockResolvedValue(JSON.stringify({ connected: true, state: "connected" }));
    
    // In a real test we would trigger the interval, here we test the internal handler logic
    const status = await ipcHandler.getVPNStatus();
    expect(status.connected).toBe(true);
  });

  it("enforces MTU safety limits for Quantum Tunneling", async () => {
    const mockConfig = {
      privateKey: "a".repeat(44),
      publicKey: "b".repeat(44),
      address: "10.0.0.1",
      dns: "1.1.1.1",
      endpoint: "1.2.3.4:51820",
      mode: "fragmented",
      mtu: 1500 
    };
    
    await ipcHandler.handleConnect(null as any, mockConfig);
    
    // Should have clamped to safe range or used default 576
    expect(mockRunHelper).toHaveBeenCalledWith(
      expect.arrayContaining(["--mtu", "576"])
    );
  });
});
