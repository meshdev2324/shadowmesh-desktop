# 💻 ShadowMesh Desktop Agent Guide

## 🏗 Architectural Blueprint
- **Stack**: Tauri v2 + React 19 + TypeScript.
- **Backend**: The Rust side of Tauri (`src-tauri/src/lib.rs`) acts as a bridge to `shadowmesh-client-core`.
- **Daemon Sidecar**: Uses `shadowmesh-daemon` (from `/daemon-rust`) for privileged operations (TUN/TAP, firewall rules).
- **IPC**: Communication between UI and Daemon is secured via session tokens and validated in `lib.rs`.

## 🔐 Security Logic
- **Kill Switch**: Implemented in the Rust Daemon using system-level firewall rules (`nftables`, `WFP`, or `PF`).
- **Forensic Resistance**: Includes Camouflage Mode (decoy UI), Duress PIN, and Panic Wipe (RAM zeroing + disk cleanup).
- **Anonymity**: Minimizes machine-specific leaks. Uses WebAuthn for hardware-bound authentication.

## 🔄 Anti-Duplication
- Keep the React frontend "dumb". All state logic, crypto, and protocol handling MUST live in `shadowmesh-client-core`.
