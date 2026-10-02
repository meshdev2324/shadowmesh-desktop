use crate::ShadowMeshError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// A high-performance, lock-free bandwidth throttler using a Token Bucket algorithm.
///
/// This implementation uses AtomicU64 and fixed-point math (precision of 1,000,000)
/// to ensure zero lock contention and maximum performance on multi-core devices.
///
/// SOP 01: Senior systems engineering with zero-panic and zero-allocation.
#[derive(Debug)]
pub struct BandwidthThrottler {
    /// Maximum number of tokens (microns) the bucket can hold.
    max_tokens: AtomicU64,
    /// Number of tokens currently in the bucket (microns).
    tokens: AtomicU64,
    /// Number of tokens added per second (microns).
    refill_rate: AtomicU64,
    /// Baseline instant to calculate nanoseconds from.
    start_time: Instant,
    /// Nanoseconds since `start_time` of the last refill.
    last_refill_ns: AtomicU64,
}

const MICRONS_PER_BYTE: u64 = 1_000_000;

impl Default for BandwidthThrottler {
    fn default() -> Self {
        // Default limit: 20 Mbps (2,621,440 bytes/s)
        Self::new(2_621_440)
    }
}

impl BandwidthThrottler {
    /// Creates a new `BandwidthThrottler` with the specified bytes per second limit.
    pub fn new(bytes_per_second: usize) -> Self {
        let rate = bytes_per_second as u64 * MICRONS_PER_BYTE;
        Self {
            max_tokens: AtomicU64::new(rate),
            tokens: AtomicU64::new(rate),
            refill_rate: AtomicU64::new(rate),
            start_time: Instant::now(),
            last_refill_ns: AtomicU64::new(0),
        }
    }

    /// Updates the rate limit (bytes per second).
    pub fn set_rate_limit(&self, bytes_per_second: usize) {
        let rate = bytes_per_second as u64 * MICRONS_PER_BYTE;
        self.refill_rate.store(rate, Ordering::Relaxed);
        self.max_tokens.store(rate, Ordering::Relaxed);

        // Clamp current tokens if they exceed new max
        let _ = self
            .tokens
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |curr| Some(curr.min(rate)));
    }

    /// Returns the current rate limit in bytes per second.
    pub fn get_rate_limit(&self) -> usize {
        (self.refill_rate.load(Ordering::Relaxed) / MICRONS_PER_BYTE) as usize
    }

    /// Consumes tokens from the bucket. If not enough tokens are available,
    /// it asynchronously waits until they are refilled.
    pub async fn throttle(&self, amount: usize) -> Result<(), ShadowMeshError> {
        if amount == 0 {
            return Ok(());
        }

        let amount_microns = amount as u64 * MICRONS_PER_BYTE;
        let refill_rate = self.refill_rate.load(Ordering::Relaxed);

        if refill_rate == 0 {
            return Ok(());
        }

        loop {
            self.refill();

            let current_tokens = self.tokens.load(Ordering::Acquire);
            if current_tokens >= amount_microns {
                match self.tokens.compare_exchange_weak(
                    current_tokens,
                    current_tokens - amount_microns,
                    Ordering::Release,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return Ok(()),
                    Err(_) => continue, // Raced with another thread, retry
                }
            }

            // Calculate wait time
            let missing = amount_microns - current_tokens;
            let wait_secs = missing as f64 / refill_rate as f64;
            let wait_duration = Duration::from_secs_f64(wait_secs);

            // Optimization: avoid extremely short sleeps
            let actual_wait = if wait_duration < Duration::from_micros(100) {
                Duration::from_micros(100)
            } else {
                wait_duration
            };

            sleep(actual_wait).await;
        }
    }

    /// Internal lock-free refill logic.
    fn refill(&self) {
        let now_ns = self.start_time.elapsed().as_nanos() as u64;
        let last_ns = self.last_refill_ns.load(Ordering::Acquire);

        if now_ns <= last_ns {
            return;
        }

        // Attempt to update the refill timestamp
        if self
            .last_refill_ns
            .compare_exchange_weak(last_ns, now_ns, Ordering::Release, Ordering::Relaxed)
            .is_err()
        {
            return; // Another thread already refilled
        }

        let elapsed_ns = now_ns - last_ns;
        let refill_rate = self.refill_rate.load(Ordering::Relaxed);
        let max_tokens = self.max_tokens.load(Ordering::Relaxed);

        // refill_rate is microns per second. nanoseconds / 1e9 = seconds.
        // refill_amount = (elapsed_ns * refill_rate) / 1,000,000,000
        let refill_amount = (elapsed_ns as u128 * refill_rate as u128 / 1_000_000_000) as u64;

        let _ = self.tokens.fetch_update(Ordering::Release, Ordering::Relaxed, |curr| {
            Some((curr + refill_amount).min(max_tokens))
        });
    }
}
