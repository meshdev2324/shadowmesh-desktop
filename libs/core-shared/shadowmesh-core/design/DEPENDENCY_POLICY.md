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


## Preferred Stack (continued — per `deny.toml`)

The following runtime dependencies are approved for `shadowmesh-core` and
appear in the crate's actual dependency graph; they were previously unnamed in
this policy, which understated what the license gate permits:
- **QUIC / TLS transport**: `quinn`, `quinn-proto`, `quinn-udp`, `rustls`,
  `rustls-pki-types`, `rustls-native-certs`, `rustls-platform-verifier`,
  `tokio-rustls`, `webpki-roots`, `rcgen`.
- **WireGuard**: `boringtun` (Noise_IKpsk2 crypto; MPL-2.0-compatible permissive).
- **TLS certificate parsing (REALITY)**: `x509-parser 0.16`.
- **HTTP / control plane**: `reqwest`, `hyper`, `tonic`, `tower`, `tower-http`,
  `axum`, `h2`.
- **PQ/low-level**: `x25519-dalek`, `ed25519-dalek`, `ring`, `aws-lc-rs`,
  `blake3`, `ml-kem` (where enabled).
- **Android NJI / uniffi**: `uniffi`.
- **Low-level networking**: `smoltcp`, `socket2`, `tun`, `libc`, `nix`.
- **Database / storage**: `rusqlite`, `sqlx` (where enabled).
- **Encoding**: `base64`, `hex`, `bincode`, `serde`, `serde_json`.

## Bans (per `deny.toml` `[bans]`)

- `openssl` — banned; use `aws-lc-rs` or `rustls`. `ring`'s `OpenSSL`
  license is permitted only as `ring`'s own code.
- `lazy_static` — **ban lifted (documented exception)**. It is MIT/Apache-2.0
  and remains a direct dependency of zero ShadowMesh code. It enters the graph
  only transitively through `x509-parser 0.16` (OID tables) and
  `tracing-subscriber/loom` (dev-only), neither of which publishes a
  `lazy_static`-free release we can move to without removing the x509 parsing
  that REALITY's temporary-certificate verification depends on. New *direct*
  uses of `lazy_static` in `shadowmesh-core` are discouraged; prefer
  `std::sync::OnceLock` / `std::sync::LazyLock`. Re-add the ban if an
  upgraded `x509-parser` ships without it.
- `multiple-versions` — warn (not error); several legitimately coexist.

## Prohibited

- Any crate with a viral copyleft license (GPL/AGPL/LGPL) in the *core*
  graph. Root configuration permits GPL-3.0-only only for the Slint desktop
  arm; `libs/core-shared/shadowmesh-core/deny.toml` does not.
- Unmaintained crates are denied (`unmaintained = "all"` in the core config),
  with the accepted-risk advisories listed in that file.
- Adding a crate to `deny.toml`'s allow lists requires editing this policy in
  the same change.
