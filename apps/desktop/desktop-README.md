# 🖥️ ShadowMesh Desktop (v5.2.0 — Tauri v2)

The **ShadowMesh Desktop App** provides a high-performance, security-hardened VPN client experience built with **Tauri v2** and **React 19**.

## 🚀 Architecture

ShadowMesh Desktop follows a secure, split-privilege architecture:

1.  **Unprivileged UI (React)**: The frontend runs in a sandboxed WebView, following a strict Content Security Policy (CSP).
2.  **Rust Backend (Tauri)**: The main Rust process (`src-tauri`) manages the application lifecycle and secure IPC.
3.  **Privileged Daemon (Rust)**: The `shadowmesh-daemon` sidecar (from `/daemon-rust`) handles system-level networking tasks like TUN/TAP interface management and firewall rules.
4.  **Shared Core**: Both the Tauri backend and the Daemon utilize the `shadowmesh-client-core` Rust library for protocol logic and security.

---

## ✨ Features

- **Performance**: Idle RAM usage <30MB thanks to system-native WebViews and Rust.
- **Security Hardening**:
  - **Zero-Trust IPC**: All commands between renderer and native backend are strictly vetted.
  - **Secure Storage**: Integration with OS-native keyrings for token management.
- **Forensic Resistance**:
  - **Camouflage Mode**: Mask the app as a system utility (e.g., Calculator).
  - **Duress PIN & Panic Wipe**: Instant, secure data destruction and session revocation.
- **Telegram-Style QR Sync**: Securely pair with your mobile app for instant, anonymous device onboarding.

## 🛠️ Tech Stack

| Layer            | Technology                       |
| :----------------|:---------------------------------|
| **Frontend**     | React 19 + TypeScript            |
| **Backend Core** | Rust (Tauri v2)                  |
| **Privileged Sidecar**| Rust (shadowmesh-daemon)     |
| **Styling**      | Tailwind CSS + Framer Motion     |

## 📦 Getting Started

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Run Development Mode**:
   ```bash
   npm run tauri dev
   ```

3. **Build Production Application**:
   ```bash
   npm run tauri build
   ```

---

_ShadowMesh: Sovereignty through technical excellence._
