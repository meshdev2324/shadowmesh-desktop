//! Process-attribution lookup: portable inline vs offloaded vs io_uring vs cached.
//!
//! This is the benchmark that decides whether the io_uring backend earned its
//! place, so it is built to be able to answer "no" honestly:
//!
//! * **All variants run in one process.** A ring created in one run and
//!   not the next is not a measurement, it is a coincidence.
//! * **Hits and misses are measured separately.** A port with no socket
//!   short-circuits after the two `/proc/net/tcp{,6}` reads and never walks
//!   `/proc/[pid]/fd`. Timing only misses would flatter io_uring, which is
//!   exactly where its work is; timing only hits would hide it. The dominant
//!   real-world cost is the hit.
//! * **The Tokio runtime is built once per group, outside the measured loop.**
//!   Building one per iteration would cost more than the cache lookup being
//!   measured.
//! * **Every variant is asked the same question** (`find_process_info` for the
//!   same port) and every result goes through `black_box`.
//! * The cached variant uses a TTL long enough that the entry cannot expire
//!   during the run, i.e. it measures the steady state a busy host is in.
//!
//! # The four columns
//!
//! | column | what it measures | where the time goes |
//! | :--- | :--- | :--- |
//! | `plain` | `find_process_info_blocking`, called **inline** | occupies the calling thread |
//! | `spawn_blocking` | `find_process_info_portable`, via `spawn_blocking` | one thread hop, off the executor |
//! | `uring` | `find_process_info_uring` | the ring's single worker thread |
//! | `cached` | `find_process_info` with a 1h memo TTL | a hash hit, no scan at all |
//!
//! The first three are the three configurations the backend default rests on and
//! are measured **in isolation** -- no memo, no backend selection -- so the
//! column is the configuration and not something it sits on top of. `cached` is
//! *not* one of them: it is the memo over whichever backend the process
//! selected, and it is here because a busy host is usually in that state.
//!
//! Criterion reports a mean and a slope, and a mean is not the number that
//! decides this default: the argument against `spawn_blocking` is that it adds a
//! scheduling hop, and a mean hides a tail that a dispatcher feels. The
//! per-call distribution for these same three configurations is in
//! `benches/proc_lookup_latency.rs`, which prints p50/p95/p99 and throughput at
//! concurrency 1 and 64.
//!
//! # `cached` means "the memo over whichever backend is selected"
//!
//! Since RFC-039 §5.4 the process default is `portable`, so with nothing else
//! set the `cached` column is the memo over `portable` and the `plain` column is
//! `portable` alone. Running with `SHADOWMESH_PROC_BACKEND=uring` makes it the
//! memo over the ring instead, which is the A/B the RFC's reversal condition
//! needs — so this bench, and the process that runs it, is the instrument for
//! changing the default back. The columns are labelled by what they measure and
//! the selected backend is printed, so a run cannot be misread as one backend
//! when it was the other.
//!
//! Run it with:
//!
//! ```text
//! cargo bench -p shadowmesh-core --bench proc_lookup_bench
//! ```
//!
//! Results depend entirely on the host: the `/proc` walk is proportional to the
//! number of processes and open descriptors, so a number from one machine says
//! nothing about another. Read them as ratios against `plain` on the same box.

use criterion::black_box;
#[cfg(target_os = "linux")]
use criterion::Criterion;
use shadowmesh_core::engine::procfs::ProcessSearcher;
use std::net::TcpListener;
use std::time::Duration;

use shadowmesh_core::engine::procfs::find_process_info_portable;
#[cfg(target_os = "linux")]
use shadowmesh_core::engine::procfs::find_process_info_uring;

/// TTL used for the cached variant, in milliseconds.
///
/// Long enough that the entry cannot expire mid-run. The shipped default is
/// off; see `engine/procfs/cache.rs` for why.
const BENCH_CACHE_TTL_MS: &str = "3600000";

/// A port this process is actually listening on, so the lookup resolves and the
/// full `/proc` walk runs.
fn hit_port() -> u16 {
    static PORT: std::sync::OnceLock<u16> = std::sync::OnceLock::new();
    *PORT.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let port = listener.local_addr().expect("tcp addr").port();
        // Leaked on purpose: a dropped listener leaves no row in
        // /proc/net/tcp and every "hit" sample would quietly become a miss.
        std::mem::forget(listener);
        port
    })
}

/// A port nothing is bound to, so the lookup returns after the table reads.
///
/// 9 is discard and this benchmark does not bind it.
const MISS_PORT: u16 = 9;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime")
}

/// Report the size of the workload, because the numbers mean nothing without it.
fn print_workload_size() {
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("proc_lookup_bench: cannot read /proc: {err}");
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

    eprintln!("proc_lookup_bench: each uncached lookup walks {pids} processes / {fds} descriptors");
}

fn bench_hits(c: &mut Criterion) {
    let port = hit_port();
    let rt = runtime();
    let mut group = c.benchmark_group("lookup/hit");

    // Config 1 of 3: portable, called inline on the thread that polls it. This
    // is what `backend_find` did on the `Portable` arm before `portable_find`,
    // and it is the only one of the three that can occupy a runtime worker.
    group.bench_function("plain", |b| {
        b.iter(|| black_box(ProcessSearcher::find_process_info_blocking(port)));
    });

    // Config 2 of 3: portable, offloaded through `spawn_blocking`. Same work,
    // one thread hop away from the executor. The memo is bypassed on purpose --
    // `find_process_info_portable` is the backend in isolation, so this column
    // is the offload and not the memo.
    group.bench_function("spawn_blocking", |b| {
        b.iter(|| black_box(rt.block_on(find_process_info_portable(port))));
    });

    // Config 3 of 3: the bounded ring, opt-in via SHADOWMESH_PROC_BACKEND=uring.
    #[cfg(target_os = "linux")]
    group.bench_function("uring", |b| {
        b.iter(|| black_box(rt.block_on(find_process_info_uring(port))));
    });

    group.bench_function("cached", |b| {
        b.iter(|| black_box(rt.block_on(ProcessSearcher::find_process_info(port))));
    });

    group.finish();
}

fn bench_misses(c: &mut Criterion) {
    let port = MISS_PORT;
    let rt = runtime();
    let mut group = c.benchmark_group("lookup/miss");

    group.bench_function("plain", |b| {
        b.iter(|| black_box(ProcessSearcher::find_process_info_blocking(port)));
    });

    group.bench_function("spawn_blocking", |b| {
        b.iter(|| black_box(rt.block_on(find_process_info_portable(port))));
    });

    #[cfg(target_os = "linux")]
    group.bench_function("uring", |b| {
        b.iter(|| black_box(rt.block_on(find_process_info_uring(port))));
    });

    group.bench_function("cached", |b| {
        b.iter(|| black_box(rt.block_on(ProcessSearcher::find_process_info(port))));
    });

    group.finish();
}

fn proc_lookup_benches(c: &mut Criterion) {
    print_workload_size();

    let hit = hit_port();
    let resolved = ProcessSearcher::find_process_info_blocking(hit);
    eprintln!("proc_lookup_bench: hit port {hit} resolves to {resolved:?}");
    assert!(resolved.is_some(), "the hit port did not resolve; this bench would compare nothing");

    #[cfg(target_os = "linux")]
    {
        let via_ring = runtime().block_on(find_process_info_uring(hit));
        assert_eq!(
            resolved, via_ring,
            "the ring and the portable path disagree before measuring anything"
        );
    }

    // Warm-up so the ring worker, the /proc dentry cache and the memo are all
    // in steady state before the first sample.
    let rt = runtime();
    rt.block_on(async {
        for _ in 0..8 {
            black_box(ProcessSearcher::find_process_info(hit).await);
            black_box(ProcessSearcher::find_process_info(MISS_PORT).await);
        }
    });
    drop(rt);

    bench_hits(c);
    bench_misses(c);
}

fn main() {
    // Must land before the first lookup: the memo reads its TTL exactly once
    // per process. Anything set later is ignored, which is deliberate -- a TTL
    // that changed halfway through a run would make the numbers a mixture of
    // two configurations.
    std::env::set_var("SHADOWMESH_PROC_CACHE_TTL_MS", BENCH_CACHE_TTL_MS);

    // Print which backend the `cached` column will actually be measuring. The
    // memo is layered on whichever backend the process selected, so "cached"
    // alone does not name a configuration -- and RFC-039 §5.4 made that
    // ambiguous when portable became the default. A run that silently measures
    // a different backend than its labels suggest is worse than no bench.
    match std::env::var("SHADOWMESH_PROC_BACKEND") {
        Ok(selection) => {
            eprintln!("proc_lookup_bench: `cached` = memo over {selection:?}")
        }
        Err(_) => {
            eprintln!("proc_lookup_bench: `cached` = memo over the portable default")
        }
    }

    // `configure_from_args` is what makes `--warm-up-time`, `--measurement-time`
    // and `--sample-size` mean anything. `Criterion::default()` alone ignores
    // every flag on the command line: only the `criterion_main!` macro (or this
    // call) parses them, so a documented invocation like
    // `cargo bench -p shadowmesh-core --bench proc_lookup_bench -- --warm-up-time 1`
    // used to run silently at the hardcoded defaults below. The defaults stay
    // as the fallback for a bare run.
    let defaults = |c: Criterion| {
        c.measurement_time(Duration::from_secs(8))
            .warm_up_time(Duration::from_secs(3))
            .sample_size(50)
    };

    #[cfg(target_os = "linux")]
    {
        let mut c = defaults(Criterion::default()).configure_from_args();
        proc_lookup_benches(&mut c);
        c.final_summary();
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "proc_lookup_bench: io_uring is Linux-only; this target measures only the \
             portable path and the memo"
        );
        let mut c = defaults(Criterion::default()).configure_from_args();
        proc_lookup_benches(&mut c);
        c.final_summary();
    }
}
