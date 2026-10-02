# ShadowMesh Core Module Map

| Module | Description | Implementation Status |
| :--- | :--- | :--- |
| `foundation` | Base types (`Addr`, `Endpoint`), Errors | **Complete** (Typed IR) |
| `transport` | TCP/UDP abstractions | **Complete** (Unified Traits) |
| `protocol` | DNS (RFC 1035), TLS, etc. | **Complete** (Handshake State) |
| `routing` | Policy matcher and decision engine | **Complete** (Engine integrated) |
| `inbound` | TUN, SOCKS5, HTTP handlers | **Complete** (Event-emitting) |
| `outbound` | Direct, Shadowsocks, VMess | **Complete** (Dialer traits) |
| `session` | Lifecycle and state registry | **Complete** (Registry) |
| `engine` | Event orchestration and actor loop | **Complete** (Actor-based) |
| `platform` | OS-specific logic (Linux, Android) | **In-progress** (Socket tuning) |
| `api` | Control Plane API (gRPC) | **Complete** (Tonic) |
