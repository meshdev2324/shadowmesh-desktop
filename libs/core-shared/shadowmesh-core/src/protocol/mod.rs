//! Internal protocol definitions for ShadowMesh.

/// Binary serialization formats for high-performance node state synchronization.
pub mod binary;

/// RFC-012 G5 length-hiding padding — the shared wire contract every protocol
/// G5 names (Shadowsocks, VMess) is built on.
pub mod padding;

/// Shadowsocks 2022-edition key derivation (RFC-012 G1).
pub mod ss2022;

/// Shadowsocks AEAD protocol implementation.
pub mod shadowsocks;
pub mod ss2022_nonce;
pub mod ss2022_stream;
