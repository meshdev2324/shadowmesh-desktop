//! Per-call latency distribution and sustained throughput for the three
//! process-attribution configurations the backend default rests on.
//!
//! `proc_lookup_bench.rs` answers "which is fastest on average". It cannot
//! answer the question that actually decides the default, which is **"what does
//! a caller wait, and what does it cost the runtime while it waits"**:
//!
//! * `plain` -- [`ProcessSearcher::find_process_info_blocking`], called inline.
//!   The caller waits for the scan *and* the runtime worker is gone for the
//!   whole of it.
//! * `spawn_blocking` -- [`find_process_info_portable`], the shipped `portable`
//!   path. The caller waits for the scan plus a thread hop, and the runtime
//!   worker is free throughout.
//! * `uring` -- [`find_process_info_uring`], the bounded ring. The caller waits
//!   for the scan plus a queue hop, and the runtime worker is free throughout.
//!
//! All three run **in one process**, against the **same port**, with the memo
//! bypassed, so the only difference between two rows is the dispatch.
//!
//! # Why the percentiles and not the mean
//!
//! A mean hides the tail. `spawn_blocking` adds a park-and-wake to every call
//! and a mean of a few hundred microseconds does not say whether that park is
//! reliably cheap or occasionally parks behind a full blocking pool -- which is
//! exactly the failure a dispatcher would notice and an average would absorb.
//! p95 and p99 are reported for that reason, and so is max.
//!
//! # Why concurrency is on the x-axis
//!
//! The ring's throughput was measured flat from concurrency 1 to 64 because one
//! worker services every lookup (F22). That is a property of the *funnel*, and
//! it is invisible at concurrency 1: measured there, both offloaded configs look
//! identical to inline plus a hop. Concurrency 64 is where the decision is
//! actually made, because a dispatcher running inbound packets does not issue
//! one lookup at a time.
//!
//! # Reading a row
//!
//! `inline` at concurrency 64 is not a throughput number, it is a demonstration:
//! the runtime has `WORKER_THREADS` workers, every one of them is inside a
//! blocking syscall for the length of a lookup, and the throughput is bounded by
//! `WORKER_THREADS / scan_duration` no matter how many callers are queued.
//! That quotient **is** the executor-occupancy figure, measured rather than
//! argued.
//!
//! ```text
//! cargo bench -p shadowmesh-core --bench proc_lookup_latency
//! ```
//!
//! Tunables, all optional: `PROC_LAT_SECONDS` (default 4), `PROC_LAT_WARMUP_SECONDS`
//! (default 2), `PROC_LAT_WORKERS` (default: Tokio's own default, i.e. one per
//! core), `PROC_LAT_MISS` (set to `1` to measure a port nothing is bound to
//! instead of a hit).

use shadowmesh_core::engine::procfs::{
    find_process_info_portable, find_process_info_uring, ProcessSearcher,
};
use std::future::Future;
use std::net::TcpListener;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One measured configuration.
struct Config {
    name: &'static str,
    /// Calls the configuration, given the port under test.
    call: fn(u16) -> Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Config {
    const fn new(
        name: &'static str,
        call: fn(u16) -> Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Self {
        Self { name, call }
    }
}

/// Inline synchronous `portable`: the scan runs on whatever thread polls it.
///
/// The `async {}` wrapper is a promise with nothing in it, so
/// [`find_process_info_blocking`] -- which is synchronous -- executes on the
/// polling thread. That is not a trick to hide the cost; it is precisely the
/// configuration being measured.
fn inline(port: u16) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        std::hint::black_box(ProcessSearcher::find_process_info_blocking(port));
    })
}

/// The shipped `portable` path: `spawn_blocking` offload.
fn offloaded(port: u16) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        std::hint::black_box(find_process_info_portable(port).await);
    })
}

/// The bounded ring, on its own worker thread.
#[cfg(target_os = "linux")]
fn ring(port: u16) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        std::hint::black_box(find_process_info_uring(port).await);
    })
}

/// An optional tuning knob. A malformed value falls back to the default rather
/// than to zero: a benchmark that refuses to run because of a typo is worse
/// than one that runs with the number in the file.
fn env_u64(key: &str, default: u64) -> u64 {
    match std::env::var(key) {
        Ok(raw) => raw.trim().parse::<u64>().unwrap_or(default),
        Err(_) => default,
    }
}

/// Cap on retained samples per cell.
///
/// A cell runs for seconds at a rate in the hundreds per second, so this is
/// never reached in practice; it exists so a host fast enough to produce
/// hundreds of millions of samples allocates a bounded `Vec` rather than
/// exhausting the box the measurement is running on.
const MAX_SAMPLES: usize = 2_000_000;

#[derive(Default)]
struct Samples(Mutex<Vec<u64>>);

/// What one cell produced.
struct Cell {
    ops: u64,
    elapsed: Duration,
    nanos: Vec<u64>,
}

/// Run `call` at `concurrency` for `window`, timing every call from the instant
/// before it is issued to the instant after it is answered.
///
/// Timing the await rather than the work is deliberate: the number a caller
/// experiences is the whole round trip, and for an offloaded configuration the
/// queueing *is* the cost.
async fn measure(
    call: fn(u16) -> Pin<Box<dyn Future<Output = ()> + Send>>,
    port: u16,
    concurrency: usize,
    window: Duration,
) -> Cell {
    let sink = Arc::new(Samples::default());
    let deadline = Instant::now() + window;

    let tasks: Vec<_> = (0..concurrency)
        .map(|_| {
            let sink = Arc::clone(&sink);
            tokio::spawn(async move {
                let mut local: Vec<u64> = Vec::new();
                loop {
                    // Checked *before* the call, not after: a call issued before
                    // the deadline and finished after it still counts, and its
                    // overshoot is real time the caller spent.
                    if Instant::now() >= deadline {
                        break;
                    }
                    let started = Instant::now();
                    call(port).await;
                    local.push(started.elapsed().as_nanos() as u64);
                    if local.len() >= 4096 {
                        let mut guard = sink.0.lock().unwrap_or_else(|e| e.into_inner());
                        guard.append(&mut local);
                        if guard.len() >= MAX_SAMPLES {
                            break;
                        }
                    }
                }
                if !local.is_empty() {
                    let mut guard = sink.0.lock().unwrap_or_else(|e| e.into_inner());
                    guard.append(&mut local);
                }
            })
        })
        .collect();

    let started = Instant::now();
    for task in tasks {
        task.await.expect("a measurement task panicked; the configuration is broken");
    }
    let elapsed = started.elapsed();

    let mut nanos = Arc::try_unwrap(sink)
        .unwrap_or_else(|_| unreachable!("every task holds a clone"))
        .0
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    let ops = nanos.len() as u64;
    nanos.sort_unstable();
    Cell { ops, elapsed, nanos }
}

/// Nearest-rank percentile over an already-sorted slice.
///
/// Nearest rank rather than interpolation: the tail of this distribution is
/// discrete -- a call either waited behind a blocked worker or it did not -- and
/// interpolating between two samples invents a value that no caller saw.
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Human-readable duration, because the whole question is which order of
/// magnitude a number is in and `12_847_391` hides that behind a unit.
fn micros(nanos: u64) -> String {
    let us = nanos as f64 / 1_000.0;
    if us >= 1_000.0 {
        format!("{:.2} ms", us / 1_000.0)
    } else {
        format!("{us:.0} us")
    }
}

fn main() {
    let miss = env_u64("PROC_LAT_MISS", 0) == 1;
    let hit = !miss;
    let port = if hit {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let port = listener.local_addr().expect("tcp addr").port();
        // Leaked on purpose: a dropped listener leaves no row in /proc/net/tcp,
        // and every sample would silently become a miss.
        std::mem::forget(listener);
        port
    } else {
        9
    };

    let seconds = env_u64("PROC_LAT_SECONDS", 4);
    let warmup_seconds = env_u64("PROC_LAT_WARMUP_SECONDS", 2);
    let requested_workers = env_u64("PROC_LAT_WORKERS", 0);
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if requested_workers > 0 {
        builder.worker_threads(requested_workers as usize);
    }
    let rt = builder.build().expect("runtime");
    // Printed either way, so a row is never read without the executor size it
    // was measured on: the occupancy argument is `workers / scan`, and that
    // quotient is meaningless without the divisor.
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
    let workers = if requested_workers > 0 { requested_workers } else { cores as u64 };

    print_workload_size();
    eprintln!(
        "proc_lookup_latency: target port {port} ({}) | window {seconds}s | warmup \
         {warmup_seconds}s | executor workers {workers}",
        if hit { "HIT: this process holds it" } else { "MISS: nothing is bound to it" }
    );

    let mut configs = vec![
        Config::new("portable inline", inline),
        Config::new("portable spawn_blocking", offloaded),
    ];
    #[cfg(target_os = "linux")]
    configs.push(Config::new("uring (bounded)", ring));
    #[cfg(not(target_os = "linux"))]
    eprintln!("proc_lookup_latency: io_uring is Linux-only; not measured on this target");

    for config in &configs {
        rt.block_on(measure(config.call, port, 1, Duration::from_secs(warmup_seconds)));
    }

    println!();
    println!(
        "{:<24} {:>6} {:>12} {:>11} {:>11} {:>11} {:>11} {:>11}",
        "configuration", "conc", "ops/s", "p50", "p95", "p99", "max", "scan hold"
    );

    let mut rows = Vec::new();
    for config in &configs {
        for concurrency in [1usize, 64] {
            let cell =
                rt.block_on(measure(config.call, port, concurrency, Duration::from_secs(seconds)));
            assert!(
                !cell.nanos.is_empty(),
                "{} at concurrency {concurrency} completed no lookups in {seconds}s",
                config.name
            );

            let throughput = cell.ops as f64 / cell.elapsed.as_secs_f64();
            let p50 = percentile(&cell.nanos, 50.0);
            let p95 = percentile(&cell.nanos, 95.0);
            let p99 = percentile(&cell.nanos, 99.0);
            let max = *cell.nanos.last().expect("non-empty, asserted above");

            // The executor-occupancy figure: the single-threaded cost of one
            // scan, which is what a worker is unavailable for. Taken from the
            // concurrency-1 row, where nothing else is competing for the host,
            // so it is the scan and not the queueing.
            let hold = if concurrency == 1 { micros(p50) } else { "-".to_string() };

            rows.push((config.name, concurrency, throughput));
            println!(
                "{:<24} {:>6} {:>12.0} {:>11} {:>11} {:>11} {:>11} {:>11}",
                config.name,
                concurrency,
                throughput,
                micros(p50),
                micros(p95),
                micros(p99),
                micros(max),
                hold,
            );
        }
    }

    // Scaling from 1 to 64 is the measurement that tells the funnel apart from
    // the pool: a backend that scales answers `x64` on the ops/s column, and one
    // that does not answers roughly `x1`.
    println!();
    println!("scaling, concurrency 1 -> 64 (ops/s):");
    for (name, _, _) in &rows {
        let one = rows.iter().find(|(n, c, _)| n == name && *c == 1).map(|r| r.2);
        let many = rows.iter().find(|(n, c, _)| n == name && *c == 64).map(|r| r.2);
        if let (Some(one), Some(many)) = (one, many) {
            println!("  {name:<24} {:>7.0} -> {:>7.0}  ({:.1}x)", one, many, many / one);
        }
    }
}

/// Report the size of the workload, because the numbers mean nothing without it.
///
/// Identical to `proc_lookup_bench.rs`: the `/proc` walk is proportional to the
/// number of processes and open descriptors on the host, and 35 ms per lookup on
/// a host with 40 processes is not a statement about this code.
fn print_workload_size() {
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("proc_lookup_latency: cannot read /proc: {err}");
            return;
        }
    };

    let mut pids = 0usize;
    let mut fds = 0usize;
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let is_pid = entry.file_name().to_str().is_some_and(|n| n.parse::<u32>().is_ok());
        if !is_pid {
            continue;
        }
        pids += 1;
        if let Ok(dir) = std::fs::read_dir(entry.path().join("fd")) {
            fds += dir.flatten().count();
        }
    }

    eprintln!(
        "proc_lookup_latency: each uncached lookup walks {pids} processes / {fds} descriptors"
    );
}
