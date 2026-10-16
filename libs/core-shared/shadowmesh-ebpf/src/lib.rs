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

/// Marker record for an activated device, keyed by masked source IP.
///
/// **This carries no credential.** The XDP program reads only `is_active`;
/// it never compares `session_hash` or `mac_key` against packet bytes, so the
/// kernel does not authenticate anything and cannot tell a genuine client from
/// a host that merely reused its address. The record means "this source has an
/// activated session", nothing more.
///
/// `session_hash` / `mac_key` are reserved for a future verifier. Userspace
/// writes all-zero placeholders for both today; do not read a zero value as
/// "unverified" and do not log a zero value as an authentication result.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QuantumSessionKey {
    /// Reserved: SHA256 of the session's PQC (ML-KEM) secret. Always zero
    /// today; unused by the XDP program.
    pub session_hash: [u8; 32],
    /// Reserved: HMAC-SHA256 truncated MAC key for packet authentication.
    /// Always zero today; unused by the XDP program.
    pub mac_key: [u8; 32],
    /// Whether this record is live. Non-zero means "activated device".
    pub is_active: u32,
    pub _padding: u32,
}

/// Per-source-IP volumetric accounting for the DDoS guard.
///
/// The counter is scoped to a window rather than cumulative. A cumulative
/// total can never come back down, so a single address that crosses the
/// threshold once is dropped forever (or until LRU eviction picks a different
/// victim) — which for a NAT'd client is one shared address for an entire
/// office or mobile carrier.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpRateWindow {
    /// Packets seen from this source inside the current window.
    pub packets: u64,
    /// `bpf_ktime_get_ns()` when the current window opened. The window resets
    /// on the first packet arriving more than the configured window length
    /// after this value.
    pub window_start_ns: u64,
}

/// Explicit policy switches for the XDP program.
///
/// Every field is zero-initialised, and zero means **monitor**: unrecognised
/// traffic is counted and passed, and the volumetric guard is inert. A drop
/// policy must be switched on deliberately, by userspace, for a named
/// interface — it is never inherited from a map's zero value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpPolicyConfig {
    /// When non-zero, UDP from a source with no live `QUANTUM_SESSIONS` record
    /// is `XDP_DROP`ped. **Blast radius:** the kernel has no credential to
    /// check, so this is "drop everything the activation path has not yet
    /// seen", not "drop impostors" — DNS, NTP, QUIC and WireGuard egress all
    /// match. Turning it on silently blackholes every host on a shared NAT.
    pub enforce_unrecognised_sessions: u32,
    /// When non-zero, packets beyond `volumetric_threshold` inside one window
    /// are `XDP_DROP`ped and counted in `GLOBAL_STATS[1]`. When zero the
    /// per-IP accounting still runs (it is observable) but nothing is dropped.
    pub volumetric_drop_enabled: u32,
    /// Packets permitted per source IP per window. Only read when
    /// `volumetric_drop_enabled` is set.
    pub volumetric_threshold: u64,
    /// Window length in nanoseconds. Also used when
    /// `volumetric_drop_enabled` is clear, so the observable rate stays
    /// meaningful. Callers should set this even in monitor mode.
    pub volumetric_window_ns: u64,
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
#[cfg(feature = "aya")]
unsafe impl aya::Pod for IpRateWindow {}
#[cfg(feature = "aya")]
unsafe impl aya::Pod for XdpPolicyConfig {}
