use shadowmesh_core::transport::hysteria::{BrutalConfig, BrutalController};
use std::time::{Duration, Instant};

#[test]
fn test_brutal_pacer_stability() {
    // 1. Setup: 1 Mbps (125,000 bytes/s)
    let bps = 1_000_000 / 8;
    let mut pacer = BrutalController::new(BrutalConfig { up_bps: bps as u64 });

    let now = Instant::now();

    // 2. Action: Simulate sending 250 KB (should take ~2 seconds)
    let total_to_send = 250_000;
    let chunk_size = 10_000;
    let mut total_wait = Duration::ZERO;
    let mut sent = 0;

    while sent < total_to_send {
        let wait = pacer.on_transmit(now + total_wait, chunk_size as u64);
        total_wait += wait;
        sent += chunk_size;
    }

    // 3. Verify: Total wait should be approximately 2 seconds
    println!("Total wait for 250KB at 125KB/s: {:?}", total_wait);

    // Allow for small drift but ensure it's not bursting everything instantly.
    // Expected: 2.0s.
    assert!(
        total_wait >= Duration::from_millis(1900),
        "Pacing too loose (burst detected): {:?}",
        total_wait
    );
    assert!(
        total_wait <= Duration::from_millis(2200),
        "Pacing too tight (lag detected): {:?}",
        total_wait
    );
}
