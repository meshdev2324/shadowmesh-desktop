//! Internal protocol definitions for ShadowMesh.

/// Binary serialization formats for high-performance node state synchronization.
pub mod binary;

/// Shadowsocks 2022-edition key derivation (RFC-012 G1).
pub mod ss2022;

/// Shadowsocks AEAD protocol implementation.
pub mod shadowsocks;
