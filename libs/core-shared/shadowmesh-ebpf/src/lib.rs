#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32, // 1: Allow, 2: Block
    pub port: u16,
}

/// Configuration for the kernel-level Token Bucket throttler.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateLimitConfig {
    /// Maximum throughput in bytes per second.
    pub bytes_per_second: u64,
    /// Maximum burst size in bytes.
    pub max_burst: u64,
    /// Whether throttling is currently active.
    pub enabled: u32,
    pub _padding: u32,
}

/// Configuration for kernel-level DPI evasion heuristics.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DpiEvasionConfig {
    /// Enable kernel-level packet fragmentation (MTU manipulation).
    pub enable_fragmentation: u32,
    /// Target MTU for outgoing packets in this mode.
    pub target_mtu: u32,
    /// Percentage of packets to inject jitter (0-100).
    pub jitter_probability: u32,
    /// Max jitter delay in nanoseconds (requires bpf_timer if supported, or spinning).
    pub max_jitter_ns: u32,
}

/// Horizon 3 Phase 3: Kernel-Level Quantum-Resistant Authentication.
/// This structure tracks valid session keys for kernel-level verification.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QuantumSessionKey {
    /// SHA256 of the current session's PQC (ML-KEM) secret.
    pub session_hash: [u8; 32],
    /// HMAC-SHA256 truncated MAC key for packet authentication.
    pub mac_key: [u8; 32],
    /// Whether this key is currently active.
    pub is_active: u32,
    pub _padding: u32,
}

// Pod implementations for user-space Map compatibility
#[cfg(feature = "aya")]
unsafe impl aya::Pod for PacketLog {}
#[cfg(feature = "aya")]
unsafe impl aya::Pod for RateLimitConfig {}
#[cfg(feature = "aya")]
unsafe impl aya::Pod for DpiEvasionConfig {}
#[cfg(feature = "aya")]
unsafe impl aya::Pod for QuantumSessionKey {}
