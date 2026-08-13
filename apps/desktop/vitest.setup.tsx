import "@testing-library/jest-dom/vitest";
import "@testing-library/jest-dom";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";
import React from "react";

// Run cleanup after each test case
afterEach(() => {
  cleanup();
});

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => {
      store[key] = value.toString();
    },
    clear: () => {
      store = {};
    },
    removeItem: (key: string) => {
      delete store[key];
    },
    length: 0,
    key: (index: number) => "",
  };
})();

Object.defineProperty(window, "localStorage", {
  value: localStorageMock,
  writable: true
});

Object.defineProperty(window, "sessionStorage", {
  value: localStorageMock,
  writable: true
});

// Mock framer-motion to avoid animation issues and DOM attribute warnings in tests
vi.mock("framer-motion", () => ({
  motion: {
    div: React.forwardRef(({ children, whileHover, whileTap, layoutId, layout, transition, ...props }: any, ref) => (
      <div {...props} ref={ref}>
        {children}
      </div>
    )),
    button: React.forwardRef(({ children, whileHover, whileTap, layoutId, layout, transition, ...props }: any, ref) => (
      <button {...props} ref={ref}>
        {children}
      </button>
    )),
    span: React.forwardRef(({ children, whileHover, whileTap, layoutId, layout, transition, ...props }: any, ref) => (
      <span {...props} ref={ref}>
        {children}
      </span>
    )),
    header: React.forwardRef(({ children, whileHover, whileTap, layoutId, layout, transition, ...props }: any, ref) => (
      <header {...props} ref={ref}>
        {children}
      </header>
    )),
    p: React.forwardRef(({ children, whileHover, whileTap, layoutId, layout, transition, ...props }: any, ref) => (
      <p {...props} ref={ref}>
        {children}
      </p>
    )),
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
  useScroll: () => ({ scrollYProgress: { onChange: vi.fn() } }),
}));

// Mock Electron/Tauri window objects
Object.defineProperty(window, "electronAPI", {
  value: {
    getSecureToken: vi.fn().mockResolvedValue("mock-token"),
    setSecureToken: vi.fn().mockResolvedValue(true),
    removeSecureToken: vi.fn().mockResolvedValue(true),
    onVPNStatusChanged: vi.fn(),
    onDaemonStatusChanged: vi.fn(),
    onObfuscationStatusChanged: vi.fn(),
    onSingBoxStatusChanged: vi.fn(),
    onCamouflageToggled: vi.fn(),
    onDeepLinkReceived: vi.fn(),
    onTriggerConnect: vi.fn(),
    connectVPN: vi.fn().mockResolvedValue({ success: true }),
    disconnectVPN: vi.fn().mockResolvedValue({ success: true }),
    pingServer: vi.fn().mockResolvedValue(42),
    getMachineId: vi.fn().mockResolvedValue("test-machine-id"),
    getNativeVersion: vi.fn().mockResolvedValue("1.2.3"),
    startObfuscation: vi.fn().mockResolvedValue({ success: true }),
    stopObfuscation: vi.fn().mockResolvedValue({ success: true }),
    startSingBox: vi.fn().mockResolvedValue({ success: true }),
    stopSingBox: vi.fn().mockResolvedValue({ success: true }),
    panicWipe: vi.fn().mockResolvedValue({ success: true }),
    enableKillSwitch: vi.fn().mockResolvedValue({ success: true }),
    disableKillSwitch: vi.fn().mockResolvedValue({ success: true }),
    getVPNStatus: vi.fn().mockResolvedValue({ connected: false, state: "disconnected" }),
    verifyCoreIntegrity: vi.fn().mockResolvedValue(true),
    getBestNode: vi.fn().mockResolvedValue(null),
  },
  writable: true,
});

// Mock Tauri Window API
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    scaleFactor: vi.fn().mockResolvedValue(1),
    innerSize: vi.fn().mockResolvedValue({ width: 800, height: 600 }),
    setSize: vi.fn().mockResolvedValue(undefined),
    show: vi.fn().mockResolvedValue(undefined),
    setFocus: vi.fn().mockResolvedValue(undefined),
    minimize: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
  }),
  LogicalSize: class {
    width: number;
    height: number;
    constructor(width: number, height: number) {
      this.width = width;
      this.height = height;
    }
  },
}));
