# ShadowMesh Core Dependency Policy

## Criteria for Selection
1. **License Compliance**: No GPL/AGPL dependencies. Prefer MIT/Apache-2.0.
2. **Maintenance**: Actively maintained with a clear security history.
3. **Safety**: Minimal use of `unsafe` in direct dependencies.
4. **Performance**: Optimized for async environments.

## Preferred Stack
- **Async Runtime**: `tokio` (Justified by `aya`, `tonic`, and high-performance requirements).
- **Event Bus**: `async-channel`.
- **Parsing**: `nom`, `bytes`.
- **Crypto**: `ring`, `aws-lc-rs`.
- **Errors**: `thiserror`, `anyhow`.
- **Observability**: `tracing`, `metrics`, `metrics-exporter-prometheus`.
- **CLI**: `clap` (feature-gated for standalone binary).

## Justifications
- **Tokio**: Required for `aya` (eBPF) and `tonic` (gRPC control plane). Provides mature multi-threaded executor for universal proxy load.
- **Tonic**: Standard for internal high-performance RPC and control plane integration.
- **Clap**: Industry standard for CLI argument parsing in systems tools.

## Prohibited
- Any crate with a viral copyleft license (GPL/AGPL).
- Unmaintained or "abandonware" crates.
