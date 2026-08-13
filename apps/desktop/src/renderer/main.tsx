import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
if (import.meta.env.VITE_E2E_MOCK_BRIDGE !== "true") {
  void import("./tauri-bridge");
}

import type { ElectronAPI } from "../types";

// Extend global window with typed electronAPI
declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}

const rootElement = document.getElementById("root");
if (!rootElement) {
  console.error("[renderer] Root element not found!");
} else {
  try {
    createRoot(rootElement).render(
      <StrictMode>
        <App />
      </StrictMode>,
    );
    console.log("[renderer] React app mounted successfully");
  } catch (err) {
    console.error("[renderer] Failed to mount React app:", err);
  }
}
