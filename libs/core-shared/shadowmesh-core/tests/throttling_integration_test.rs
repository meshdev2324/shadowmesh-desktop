use shadowmesh_core::network::throttler::BandwidthThrottler;
use std::time::Instant;
use tokio::time::Duration;

#[tokio::test]
async fn test_bandwidth_throttler_accuracy() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Setup: 100 KB/s limit
    let limit_kbps = 100;
    let limit_bps = limit_kbps * 1024;
    let throttler = BandwidthThrottler::new(limit_bps);

    // 2. Action: Try to consume 200 KB
    let amount_to_consume = 200 * 1024;
    let start = Instant::now();

    // First call shouldn't wait much as bucket starts full
    throttler.throttle(amount_to_consume / 2).await.unwrap();

    // Second call should trigger wait
    throttler.throttle(amount_to_consume / 2).await.unwrap();

    let elapsed = start.elapsed();

    // 3. Verify: 200 KB at 100 KB/s should take at least ~1 second (allowing for bucket burst)
    // bucket starts with limit_bps tokens.
    // 1st 100KB: instant (bucket empty)
    // 2nd 100KB: needs refill. 100KB / 100KB/s = 1s.

    println!("Elapsed for 200KB at 100KB/s: {:?}", elapsed);

    assert!(elapsed >= Duration::from_millis(900), "Throttling too fast: {:?}", elapsed);
    assert!(elapsed <= Duration::from_millis(2000), "Throttling too slow: {:?}", elapsed);
}

#[tokio::test]
async fn test_throttler_dynamic_update() {
    let throttler = BandwidthThrottler::new(100 * 1024); // 100 KB/s

    let start = Instant::now();
    throttler.throttle(100 * 1024).await.unwrap(); // Instant
    throttler.throttle(100 * 1024).await.unwrap(); // ~1s wait
    let first_wait = start.elapsed();
    assert!(first_wait >= Duration::from_millis(900));

    // Speed up to 1 MB/s
    throttler.set_rate_limit(1024 * 1024);

    let start2 = Instant::now();
    throttler.throttle(512 * 1024).await.unwrap(); // Should take ~0.5s or less if bucket refilled
    let second_wait = start2.elapsed();

    println!("Second wait with 1MB/s limit: {:?}", second_wait);
    assert!(second_wait < Duration::from_millis(600));
}
