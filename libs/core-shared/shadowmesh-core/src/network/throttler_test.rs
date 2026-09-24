use super::throttler::BandwidthThrottler;
use std::time::Instant;

#[tokio::test]
async fn test_throttler_accuracy() {
    // Limit: 100 KB/s
    let throttler = BandwidthThrottler::new(100_000);

    let start = Instant::now();
    throttler.throttle(100_000).await.expect("First throttle failed");
    throttler.throttle(100_000).await.expect("Second throttle failed");
    let elapsed = start.elapsed();

    // Should take at least 1 second to consume 200KB at 100KB/s (minus 1s burst)
    assert!(
        elapsed.as_secs_f64() >= 0.9,
        "Throttler failed to enforce limit. Elapsed: {:?}",
        elapsed
    );
    assert!(elapsed.as_secs_f64() < 1.5, "Throttler waited too long. Elapsed: {:?}", elapsed);
}

#[tokio::test]
async fn test_throttler_burst_behavior() {
    let rate = 1000;
    let throttler = BandwidthThrottler::new(rate);

    let start = Instant::now();
    // Consume burst capacity (1s worth)
    for _ in 0..10 {
        throttler.throttle(100).await.expect("Chunk throttle failed");
    }

    // This should be fast as it fits in burst
    assert!(start.elapsed().as_millis() < 50);

    // This should trigger throttling
    throttler.throttle(500).await.expect("Throttled chunk failed");
    assert!(start.elapsed().as_millis() >= 450);
}

#[tokio::test]
async fn test_throttler_rate_limit_update() {
    let throttler = BandwidthThrottler::new(100_000);
    assert_eq!(throttler.get_rate_limit(), 100_000);

    throttler.set_rate_limit(500_000);
    assert_eq!(throttler.get_rate_limit(), 500_000);
}

#[tokio::test]
async fn test_throttler_zero_consumption() {
    let throttler = BandwidthThrottler::new(1000);
    throttler.throttle(0).await.expect("Zero throttle failed");
}

#[tokio::test]
async fn test_throttler_very_high_rate() {
    let throttler = BandwidthThrottler::new(1_000_000_000);
    let start = Instant::now();
    throttler.throttle(10_000_000).await.expect("High rate throttle failed");
    assert!(start.elapsed().as_millis() < 10);
}
