# ⚙️ ShadowMesh Client-Core Agent Guide

## 🏗 Architectural Blueprint
- **Responsibility**: This is the engine for all clients. No UI logic allowed.
- **FFI**: UniFFI is used for bindings. All public-facing types must be defined in `src/shadowmesh.udl`.
- **Memory**: Ensure all cross-boundary objects are thread-safe (`Send + Sync`).

## 🔐 Security Logic
- **Protocol**: WireGuard and REALITY protocol logic lives here. Do not leak raw keys to the native UI layer; return opaque handles or encrypted blobs.
- **Errors**: Map all internal errors to the `ShadowMeshError` enum for unified handling in Swift/Kotlin.

## 🔄 Anti-Duplication
- If you are adding a feature that needs to be used by both Android and iOS, it **MUST** be implemented here in Rust.
