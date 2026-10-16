use loom::sync::Arc;
use loom::sync::atomic::{AtomicBool, Ordering};
use loom::thread;

#[test]
fn test_pow_cancellation_loom() {
    loom::model(|| {
        let cancelled = Arc::new(AtomicBool::new(false));

        let cancelled_c1 = Arc::clone(&cancelled);
        let h1 = thread::spawn(move || {
            // Simulate worker 1 finding a solution
            cancelled_c1.store(true, Ordering::Relaxed);
        });

        let cancelled_c2 = Arc::clone(&cancelled);
        let h2 = thread::spawn(move || {
            // Simulate worker 2 checking for cancellation
            if !cancelled_c2.load(Ordering::Relaxed) {
                // Do work
            }
        });

        h1.join().unwrap();
        h2.join().unwrap();

        assert!(cancelled.load(Ordering::Relaxed));
    });
}
