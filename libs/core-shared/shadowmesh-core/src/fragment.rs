use crate::network::throttler::BandwidthThrottler;
use crate::vpn_manager::TrafficMode;
use crate::ShadowMeshError;
use bytes::{Bytes, BytesMut};
use rand::Rng;
use std::future::Future;
use std::time::Duration;

// Quantum Tunneling (Packet Fragmentation) MTU constants per PROTOCOLS.md
/// The Maximum Transmission Unit (MTU) for Quantum Tunneling mode as per PROTOCOLS.md.
pub const QUANTUM_MTU: u32 = 576;
/// The TCP Maximum Segment Size (MSS) for Quantum Tunneling mode (MTU - 40 bytes).
pub const QUANTUM_TCP_MSS: u32 = 536; // MTU 576 - 40 bytes IP/TCP headers

/// Represents the connection phase to apply different fragmentation strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentationPhase {
    /// Initial handshake phase (TLS/REALITY Setup).
    /// Focuses on aggressive micro-fragmentation to obfuscate fingerprints.
    Handshake,
    /// High-volume data transfer phase.
    /// Focuses on high throughput and efficiency.
    Streaming,
}

/// Configuration for adaptive DPI-evasion fragmentation mode.
#[derive(Debug, Clone)]
pub struct FragmentationConfig {
    /// The current connection phase.
    pub phase: FragmentationPhase,
    /// Minimum size of a single fragment in bytes.
    pub min_size: usize,
    /// Maximum size of a single fragment in bytes.
    pub max_size: usize,
    /// Base delay between sending fragments.
    pub delay: Duration,
    /// Whether to apply randomized jitter to the delay.
    pub jitter_enabled: bool,
    /// Maximum additional jitter to add to the base delay.
    pub jitter_max: Duration,
    /// When true, enforces PROTOCOLS.md §1 Quantum Tunneling MTU values.
    pub quantum_mode: bool,
}

impl Default for FragmentationConfig {
    fn default() -> Self {
        Self::adaptive_streaming()
    }
}

impl FragmentationConfig {
    /// Creates a new fragmentation configuration.
    pub fn new(min_size: usize, max_size: usize, delay_ms: u64) -> Self {
        Self {
            phase: FragmentationPhase::Streaming,
            min_size,
            max_size,
            delay: Duration::from_millis(delay_ms),
            jitter_enabled: false,
            jitter_max: Duration::ZERO,
            quantum_mode: false,
        }
    }

    /// Strict Quantum Tunneling config — MTU 576 per PROTOCOLS.md §1.
    pub fn quantum() -> Self {
        Self {
            phase: FragmentationPhase::Streaming,
            min_size: 100,
            max_size: QUANTUM_MTU as usize,
            delay: Duration::from_millis(5),
            jitter_enabled: true,
            jitter_max: Duration::from_millis(15),
            quantum_mode: true,
        }
    }

    /// Adaptive configuration for Handshake phase to protect SNI.
    pub fn adaptive_handshake() -> Self {
        Self {
            phase: FragmentationPhase::Handshake,
            min_size: 100,
            max_size: 1400,
            delay: Duration::from_micros(500),
            jitter_enabled: true,
            jitter_max: Duration::from_micros(1500),
            quantum_mode: false,
        }
    }

    /// Adaptive configuration for Streaming phase for max throughput.
    pub fn adaptive_streaming() -> Self {
        Self {
            phase: FragmentationPhase::Streaming,
            min_size: 1200,
            max_size: 1420,
            delay: Duration::ZERO,
            jitter_enabled: false,
            jitter_max: Duration::ZERO,
            quantum_mode: false,
        }
    }

    /// Calculates the delay for the next fragment based on jitter settings.
    pub fn get_next_delay(&self) -> Duration {
        if !self.jitter_enabled || self.jitter_max.is_zero() {
            return self.delay;
        }
        // Deliberately a fast non-CSPRNG: this is obfuscation TIMING, not
        // secret material — and it runs per-fragment on the hot path where
        // SystemRandom syscalls would throttle throughput. Unpredictability
        // quality matters only for traffic-shape noise, which thread_rng
        // amply provides.
        let mut rng = rand::thread_rng();
        let jitter_micros = rng.gen_range(0..=self.jitter_max.as_micros() as u64);
        self.delay + Duration::from_micros(jitter_micros)
    }

    /// Returns the effective TUN MTU for this mode.
    pub fn effective_mtu(&self) -> u32 {
        if self.quantum_mode {
            QUANTUM_MTU
        } else {
            self.max_size as u32
        }
    }
}

/// Split `data` into random-sized fragments constrained by `config`.
/// Uses zero-copy slicing via the `bytes` crate for maximum performance.
///
/// This implementation is 100% Zero-Panic and uses defensive logic to ensure progress.
pub fn fragment_data(data: Bytes, config: &FragmentationConfig) -> Vec<Bytes> {
    if data.is_empty() {
        return Vec::new();
    }

    let mut fragments = Vec::new();
    let mut offset = 0;
    let mut rng = rand::thread_rng();

    while offset < data.len() {
        let remaining = data.len() - offset;

        // Use the configured sizes. Defensive clamping is handled below.
        let min = config.min_size;
        let max = config.max_size;

        // Guard: ensure effective ranges are valid for remaining data and make progress
        let effective_min = min.min(remaining).max(1);
        let effective_max = max.min(remaining).max(effective_min);

        let fragment_size = if effective_min >= effective_max {
            effective_max
        } else {
            rng.gen_range(effective_min..=effective_max)
        };

        // Zero-copy slice. Safe because fragment_size <= remaining.
        fragments.push(data.slice(offset..offset + fragment_size));
        offset += fragment_size;
    }

    fragments
}

/// Fragments `data` and throttles the sending process using the provided `throttler`.
///
/// This is an async helper designed for the Quantum Tunneling engine.
/// It applies both fragmentation and bandwidth limiting in a single loop.
///
/// # Errors
///
/// Returns `ShadowMeshError` if throttling or the `send_fn` fails.
pub async fn fragment_and_throttle<F, Fut>(
    data: Bytes,
    config: &FragmentationConfig,
    throttler: &BandwidthThrottler,
    mut send_fn: F,
) -> Result<(), ShadowMeshError>
where
    F: FnMut(Bytes) -> Fut,
    Fut: Future<Output = Result<(), ShadowMeshError>>,
{
    if data.is_empty() {
        return Ok(());
    }

    let fragments = fragment_data(data, config);
    for fragment in fragments {
        let size = fragment.len();

        // 1. Enforce bandwidth limit (User-space)
        // If the limit is set to 1Gbps (unlimited/safety cap) or kernel offload is active,
        // this call will return immediately or be skipped.
        // SOP 01: High-performance pacing for fragmented mode.
        throttler.throttle(size).await?;

        // 2. Send the fragment
        send_fn(fragment).await?;

        // 3. Apply optional inter-fragment delay from config
        let delay = config.get_next_delay();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    Ok(())
}

/// Reassemble received fragments back into a contiguous payload.
/// Uses `BytesMut` for efficient allocation.
pub fn reassemble_fragments(fragments: Vec<Bytes>) -> Bytes {
    let total_len = fragments.iter().map(|f| f.len()).sum();
    if total_len == 0 {
        return Bytes::new();
    }
    let mut buffer = BytesMut::with_capacity(total_len);
    for f in fragments {
        buffer.extend_from_slice(&f);
    }
    buffer.freeze()
}

/// Returns the recommended `FragmentationConfig` based on the active `TrafficMode`.
pub fn select_config_for_mode(mode: TrafficMode) -> FragmentationConfig {
    match mode {
        TrafficMode::Fragmented => FragmentationConfig::quantum(),
        _ => FragmentationConfig::adaptive_streaming(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_quantum_mtu_constants() {
        let cfg = FragmentationConfig::quantum();
        assert_eq!(cfg.effective_mtu(), 576, "Quantum MTU must be 576 per PROTOCOLS.md §1");
    }

    #[test]
    fn test_fragment_reassemble_roundtrip() {
        let original_data: Vec<u8> = (0..=255u8).collect();
        let original = Bytes::from(original_data.clone());
        let config = FragmentationConfig::adaptive_handshake();
        let fragments = fragment_data(original.clone(), &config);
        let reassembled = reassemble_fragments(fragments.clone());

        assert_eq!(reassembled, original, "Reassembled data must match original");
    }

    #[test]
    fn test_empty_fragmentation() {
        let data = Bytes::new();
        let config = FragmentationConfig::default();
        let fragments = fragment_data(data, &config);
        assert!(fragments.is_empty());
    }

    #[test]
    fn test_jitter_delay_range() {
        let mut cfg = FragmentationConfig::adaptive_handshake();
        cfg.delay = Duration::from_millis(10);
        cfg.jitter_max = Duration::from_millis(50);
        cfg.jitter_enabled = true;

        for _ in 0..100 {
            let delay = cfg.get_next_delay();
            assert!(delay >= Duration::from_millis(10) && delay <= Duration::from_millis(60));
        }
    }

    #[test]
    fn test_phase_aware_chunk_sizes() {
        let payload = Bytes::from(vec![0u8; 10000]);

        // Handshake should have many small fragments
        let handshake_cfg = FragmentationConfig::adaptive_handshake();
        let handshake_frags = fragment_data(payload.clone(), &handshake_cfg);
        assert!(
            handshake_frags.len() > 7,
            "Handshake should have more fragments due to randomization"
        );

        // Streaming should have fewer large fragments
        let streaming_cfg = FragmentationConfig::adaptive_streaming();
        let streaming_frags = fragment_data(payload.clone(), &streaming_cfg);
        assert!(
            streaming_frags.len() <= 10,
            "Streaming should have fewer fragments for throughput"
        );
    }

    #[tokio::test]
    async fn test_fragment_and_throttle() {
        let throttler = BandwidthThrottler::new(100_000); // 100 KB/s
        let config = FragmentationConfig::adaptive_handshake();
        let payload = Bytes::from(vec![0u8; 1000]); // 1KB

        let sent_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sent_bytes_clone = sent_bytes.clone();

        fragment_and_throttle(payload, &config, &throttler, move |frag| {
            let sent_bytes_inner = sent_bytes_clone.clone();
            async move {
                sent_bytes_inner.fetch_add(frag.len(), std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .expect("Fragment and throttle failed");

        assert_eq!(sent_bytes.load(std::sync::atomic::Ordering::SeqCst), 1000);
    }
}
