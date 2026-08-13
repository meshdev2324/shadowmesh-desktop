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

// Pod implementations for user-space Map compatibility
#[cfg(feature = "aya")]
unsafe impl aya::Pod for PacketLog {}
#[cfg(feature = "aya")]
unsafe impl aya::Pod for RateLimitConfig {}
