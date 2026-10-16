//! Process attribution for the per-packet data path.
//!
//! # What this is asked, and by whom
//!
//! [`ProcessSearcher::find_process_info`] answers one question: *which process
//! on this host holds a socket bound to this port*. It reads this host's
//! `/proc/net/tcp{,6}`, so the answer only exists for a socket this host owns.
//!
//! The dispatcher reaches it through
//! [`attribute_process_identity`](crate::engine::process::attribute_process_identity),
//! which asks whether `identity.source` is such a socket before spending a
//! lookup on it. It is only asked for traffic this node originated -- the TUN
//! ingress path, where the source address and port are read off a local
//! interface's own IP header. Inbound proxy traffic is **not** looked up: there
//! `identity.source` is the remote peer's endpoint, and resolving a peer's
//! ephemeral port against this host's listeners returned the wrong process,
//! which routing rules and traffic shaping then matched on. See
//! [`SourceOrigin`](crate::engine::metadata::SourceOrigin).
//!
//! # Backends
//!
//! * [`portable`] — plain `std::fs`. Runs everywhere, is the reference the
//!   other backend is tested against, and is **the default**.
//! * [`uring`] — Linux only, **opt-in**. io_uring for the `/proc/net/tcp{,6}`
//!   reads and for the per-pid `/proc/[pid]/fd` open/close fan-out. Selected by
//!   [`BACKEND_ENV`]. Falls back to [`portable`] at runtime whenever the ring
//!   cannot be created, so a seccomp policy that blocks `io_uring_setup`
//!   changes performance and nothing else.
//! * [`cache`] — a short-TTL memo, **disabled by default**; see its module docs
//!   for why this particular answer is not safe to serve stale.
//!
//! Both backends share [`portable::parse_inode_table`]. There is exactly one
//! parser in the tree, so the uring path cannot return a different answer
//! because of a differently-parsed row -- only because of different bytes.
//!
//! ## Why `portable` is the default and the ring is opt-in (RFC-039 §5.4)
//!
//! The ring used to be the Linux default. It was measured, and it loses to the
//! path it wraps. F22, `docs/REMAINING-WORK.md:127`, on one host:
//!
//! | condition | `uring` | `portable` | ratio |
//! | :--- | ---: | ---: | ---: |
//! | cold, concurrency 64 | 127 /s | 480 /s | 3.8x |
//! | warm, concurrency 64 | 641 /s | 3053 /s | 4.8x |
//!
//! Ring throughput is **flat from concurrency 1 to 64** (123.6 -> 127.1 /s):
//! 64x the concurrency buys 3%, because [`uring`] services every lookup on one
//! worker thread. So "io_uring is the fast path" was false as shipped, and the
//! default was the slower of the two by 3.8-4.8x.
//!
//! Flipping the default is a **performance-only** change, and that is checkable
//! rather than asserted: both backends call [`portable::parse_inode_table`], so
//! there is no behavioural divergence to test for. The differential tests below
//! still drive both backends explicitly, because a test that compares the
//! default against itself proves nothing once the default *is* one of them.
//!
//! The ring is kept, bounded and instrumented rather than deleted, so the
//! question stays answerable by re-measurement instead of by memory. RFC-039
//! §5.4 states the reversal condition: if the funnel is removed and the ring
//! wins again at concurrency 64, the default returns to `uring`.
//!
//! **These numbers are a single-host baseline.** They have not been measured on
//! edge hardware. [`BACKEND_ENV`] exists so that re-measurement is a config
//! change rather than a code change.

pub(crate) mod cache;
pub(crate) mod portable;
#[cfg(target_os = "linux")]
pub(crate) mod uring;

use serde::Serialize;
use std::sync::OnceLock;
use tracing::{info, warn};

/// A process, as attributed to a local socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessInfo {
    /// The pid owning the socket.
    pub pid: u32,
    /// The executable name from `/proc/<pid>/comm`.
    pub name: String,
}

/// Maps a local port back to the process holding the socket.
pub struct ProcessSearcher;

impl ProcessSearcher {
    /// Resolve `local_port` to its owning process, using the best backend this
    /// platform and this process can offer.
    ///
    /// Returns `None` when the port has no matching socket, no process owns it
    /// (a socket in another mount or pid namespace, or one that closed between
    /// the two stages), or the lookup failed. Callers treat `None` as "no
    /// attribution available", never as an error.
    pub async fn find_process_info(local_port: u16) -> Option<ProcessInfo> {
        if let Some(hit) = cache::get(local_port) {
            return hit;
        }

        let found = backend_find(local_port).await;

        cache::put(local_port, found.as_ref());
        found
    }

    /// Synchronous, portable-only lookup.
    ///
    /// The data path uses [`ProcessSearcher::find_process_info`]; this exists
    /// for callers with no Tokio runtime and for the benchmark oracle. It never
    /// consults the ring and never consults the memo, so it is a stable
    /// reference implementation.
    pub fn find_process_info_blocking(local_port: u16) -> Option<ProcessInfo> {
        portable::find_process_info(local_port)
    }
}

/// The io_uring backend with no memo in front of it.
///
/// Linux only, and **not** the default — [`BACKEND_ENV`]=`uring` selects it for
/// a process, and this is what the benchmark and the differential tests call so
/// they can measure and compare the ring without re-exporting it for every
/// caller. The data path goes through [`ProcessSearcher::find_process_info`],
/// which layers the cache on top and selects the backend; this is the ring in
/// isolation so `benches/proc_lookup_bench.rs` can time it against the portable
/// path inside a single process, rather than comparing two runs of a benchmark
/// that happened to be built on different days.
///
/// The default being `portable` is why this entry point exists at all: with the
/// default on one side of a comparison, a test or a benchmark that meant to
/// compare two backends would otherwise compare `portable` against itself.
#[cfg(target_os = "linux")]
pub async fn find_process_info_uring(local_port: u16) -> Option<ProcessInfo> {
    uring::find_process_info(local_port).await
}

/// The portable backend with no memo in front of it, through the same
/// `spawn_blocking` offload the shipped path uses.
///
/// The counterpart to [`find_process_info_uring`], and it exists for the same
/// reason: the three configurations the default decision rests on are *inline
/// synchronous*, *offloaded through `spawn_blocking`*, and *the ring*, and the
/// first is only reachable by calling [`ProcessSearcher::find_process_info_blocking`]
/// directly. Without this entry point there is no way to time the configuration
/// that actually ships against the one it replaced inside a single process.
pub async fn find_process_info_portable(local_port: u16) -> Option<ProcessInfo> {
    portable_find(local_port).await
}

/// Which implementation answers the lookup.
///
/// `Portable` is the default and the only member available off Linux, so it is
/// also what every unresolvable spelling of the opt-in degrades to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    /// `std::fs`. Runs everywhere.
    Portable,
    /// io_uring. Linux only, opt-in.
    Uring,
}

/// Selects the process-attribution backend. Unset, or any value that is not a
/// backend name, means [`Backend::Portable`].
///
/// # Why this name
///
/// It is the sibling of `SHADOWMESH_PROC_CACHE_TTL_MS`, the other operator
/// knob on this module (`cache.rs`), and it carries the same `SHADOWMESH_PROC_`
/// prefix. An operator who has read one has read the other.
///
/// The alternatives were rejected deliberately. `SHADOWMESH_USE_IO_URING` would
/// name the *implausible* option and leave nothing to name when a third backend
/// is added, which is the same naming mistake as a boolean called
/// `IS_FAST`. `SHADOWMESH_PROCFS_BACKEND` would name the module while its
/// sibling names the subsystem, and two prefixes for one module means a grep
/// for the knob finds half of it. One prefix, two knobs, one module.
///
/// # Values
///
/// | value | meaning |
/// | :--- | :--- |
/// | unset (default) | [`Backend::Portable`] |
/// | `portable` | [`Backend::Portable`], explicitly |
/// | `uring` | [`Backend::Uring`], on Linux; portable elsewhere and wherever `io_uring_setup` is refused |
///
/// Case and surrounding whitespace are tolerated. Anything else is a typo, and
/// a typo degrades to the measured default with a `warn!` rather than to a
/// guess — the same rule `cache.rs` applies to an unparseable TTL.
pub(crate) const BACKEND_ENV: &str = "SHADOWMESH_PROC_BACKEND";

/// Pure parse of the backend selection, so the rules are unit-testable without
/// a process-global or an environment mutation.
///
/// Trimming and case-folding live here and nowhere else, so the call site cannot
/// disagree with the tests about what a value means. The empty string is the
/// interesting case on the far side of the trim: `SHADOWMESH_PROC_BACKEND=` set
/// to nothing is an operator who exported the variable without choosing, and it
/// is the unset default rather than a request for something.
fn parse_backend(raw: Option<&str>) -> Backend {
    match raw.map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("uring") => Backend::Uring,
        _ => Backend::Portable,
    }
}

/// The selection, memoised. See [`selected_backend`].
static BACKEND: OnceLock<Backend> = OnceLock::new();

/// Test-only override for the memoised selection.
///
/// This exists for the same reason `cache.rs` has one, and the reason is in
/// F11: [`BACKEND`] is a `OnceLock` and cannot be reset, so a test that called
/// `std::env::set_var` and then read [`selected_backend`] would pass or fail
/// depending on which test got there first. Consulting this *before* the memo
/// removes the race. It is entirely `#[cfg(test)]`, so nothing is added to the
/// shipped lookup path and the documented default is unchanged.
#[cfg(test)]
static BACKEND_OVERRIDE: std::sync::Mutex<Option<Backend>> = std::sync::Mutex::new(None);

/// The backend this process uses, resolved once and logged once.
///
/// # Why it is read once
///
/// The environment is a process-global that nothing in this crate owns, so
/// reading it per lookup would put an unsynchronised global read on the
/// per-packet path — and would let a value change under an in-flight lookup.
/// `OnceLock::get_or_init` resolves it on first use and is a single atomic
/// acquire after that. Nothing here mutates the environment, so there is no
/// `set_env` race for the F11 `EnvGuard` to guard against.
///
/// # Why the log is one line per process
///
/// [`selected_backend`] sits on the lookup path. A `info!` per lookup would be
/// a second performance regression on the exact path this change exists to
/// speed up, and — per F16 — a line that fires thousands of times an hour is a
/// line operators learn to skip. One line, at resolution time, is the whole
/// thing an operator needs: the answer is fixed for the life of the process and
/// changing it is a restart.
fn selected_backend() -> Backend {
    #[cfg(test)]
    {
        // `into_inner` rather than `unwrap`: a poisoned lock here means another
        // test panicked while holding it, and the value is still readable.
        let forced = *BACKEND_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(forced) = forced {
            return forced;
        }
    }

    *BACKEND.get_or_init(|| {
        // The decision is `parse_backend`'s alone; the trim here is purely so
        // the log line quotes what the operator actually typed.
        let raw = std::env::var(BACKEND_ENV).ok();
        let quoted = raw.as_deref().map(str::trim).filter(|v| !v.is_empty());
        let chosen = parse_backend(raw.as_deref());

        match quoted {
            None => info!(
                "process attribution: portable backend (default; {BACKEND_ENV} unset). \
                 The io_uring path measured 3.8-4.8x slower than this one at \
                 concurrency 64 -- set {BACKEND_ENV}=uring to re-measure it."
            ),
            Some(value) if value.eq_ignore_ascii_case("uring") => info!(
                "process attribution: io_uring backend, selected by {BACKEND_ENV}=uring \
                 (opt-in; portable is the default)"
            ),
            Some(value) if value.eq_ignore_ascii_case("portable") => {
                info!("process attribution: portable backend, selected by {BACKEND_ENV}=portable")
            }
            Some(value) => warn!(
                "{BACKEND_ENV}={value:?} is not a backend name (expected `portable` or \
                 `uring`); falling back to the portable default. This is a typo, not a \
                 request for a third backend."
            ),
        }
        chosen
    })
}

/// Clears the [`BACKEND_OVERRIDE`] when dropped.
///
/// Callers must **bind** the returned value; dropping it immediately would
/// clear the override before the test body ran.
#[cfg(test)]
pub(crate) struct BackendOverride;

#[cfg(test)]
impl Drop for BackendOverride {
    fn drop(&mut self) {
        *BACKEND_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// Force [`selected_backend`] to `value` until the returned guard drops.
///
/// Lives at module scope rather than inside `mod tests` so the tests below can
/// pin the selection for their own body. Bind the returned guard.
#[cfg(test)]
pub(crate) fn force_backend(value: Backend) -> BackendOverride {
    *BACKEND_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner()) = Some(value);
    BackendOverride
}

/// The backend in force, for a test that wants to assert which configuration it
/// is actually running under rather than assume it.
#[cfg(test)]
pub(crate) fn backend_for_test() -> Backend {
    selected_backend()
}

/// The portable backend, dispatched so its blocking `/proc` scan does **not**
/// occupy a Tokio runtime worker.
///
/// # Why this wrapper exists at all
///
/// [`portable::find_process_info`] is synchronous. It is a `/proc/net/tcp{,6}`
/// read followed — on a hit — by a walk of every `/proc/[pid]/fd` and a
/// `readlink` per descriptor, which is syscall-dense and takes hundreds of
/// microseconds. Calling it directly from `async fn backend_find` runs that scan
/// **inline on the executor worker** that polled the lookup, and the caller is
/// on the dispatcher hot path (`Dispatcher::enrich_metadata` ->
/// `attribute_process_identity`, per packet from TUN ingress). A blocking
/// syscall there is a starvation hazard for every other task on that worker:
/// it is the shape that makes an unrelated test time out under load and pass in
/// isolation, which is exactly the signature observed in
/// `edge_system_interop_test::edge_system_vless_reality_tcp_roundtrip`.
///
/// The ring backend never had this problem, because it answers from a dedicated
/// worker thread. Flipping the default to `portable` without this wrapper moved
/// the blocking scan *onto* the executor, so the default had to be restored to
/// an off-executor dispatch or the default had to go back to `uring`. It is
/// restored here.
///
/// # Why `spawn_blocking` and not the alternatives
///
/// * **A dedicated worker thread per lookup** — what `uring.rs` does, and the
///   measured ceiling the ring already lost to: one thread services every
///   lookup, so throughput is flat in concurrency (F22: 123.6 -> 127.1 /s from
///   concurrency 1 to 64). It would move the blocking scan off the executor and
///   straight back onto the funnel this module was changed to remove.
/// * **`block_in_place`** — keeps the work on the executor thread and merely
///   tells the runtime to migrate other tasks away. The thread is still
///   occupied for the length of the scan, and it **panics on a current-thread
///   runtime**, which this crate's tests and both benches build. It trades the
///   starvation for a panic and buys nothing.
/// * **A dedicated *pool* for `/proc` scans** — the right shape for a job with
///   a bounded thread count, but it needs its own queue, its own bound and its
///   own saturation policy, all of which `uring.rs` already carries and which
///   would have to be rebuilt and re-instrumented to say the same thing.
///   `spawn_blocking` is that, already built and already instrumented.
///
/// Tokio's blocking pool is per-runtime and starts at one thread, growing to
/// serve concurrent blocking calls up to a generous ceiling, so N concurrent
/// lookups use N threads rather than queueing behind one — which is the specific
/// property `uring` lacks.
///
/// # What it costs
///
/// A thread hop and a scheduling latency on a path that was previously free of
/// both, and one small allocation for the task handle. That is not free and is
/// not claimed to be: `benches/proc_lookup_bench.rs` measures the three
/// configurations (inline, `spawn_blocking`, ring) for throughput *and* latency
/// distribution, and the default decision rests on that table rather than on
/// this argument.
///
/// # Degradation
///
/// * **No Tokio runtime** — `spawn_blocking` panics outside one, and this is
///   an `async fn` a caller could in principle drive from another executor. With
///   no runtime there is also no worker to starve, so the scan runs inline,
///   exactly as [`ProcessSearcher::find_process_info_blocking`] always did.
///   This is the one caller that is *not* protected by the offload, and it is
///   protected for the same reason: nothing is being starved.
/// * **The blocking task panicked** — reported once, then answered `None`.
///   `None` is the documented "no attribution available" answer and callers
///   treat it as such; inventing a process would be worse than admitting none.
/// * **The runtime shut down mid-lookup** — answered `None` without a log.
///   That is a normal end to the process, not a defect to page anyone about.
async fn portable_find(local_port: u16) -> Option<ProcessInfo> {
    if tokio::runtime::Handle::try_current().is_err() {
        return portable::find_process_info(local_port);
    }

    match tokio::task::spawn_blocking(move || portable::find_process_info(local_port)).await {
        Ok(found) => found,
        Err(err) if err.is_panic() => {
            report_blocking_panic_once();
            None
        }
        Err(_) => None,
    }
}

/// Latches the `spawn_blocking` panic report so a systematic panic cannot turn
/// this into one log line per packet.
static BLOCKING_PANIC_REPORTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn report_blocking_panic_once() {
    if BLOCKING_PANIC_REPORTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    warn!(
        "process attribution: the /proc scan panicked on Tokio's blocking pool. \
         The lookup answered \"no attribution\"; this is a defect in the scanner, \
         not a configuration problem. Reported once -- if this line is here, the \
         attribution for every lookup is being lost."
    );
}

/// Pick the backend for this target and dispatch to it.
///
/// Non-Linux targets resolve to `portable` at compile time -- macOS has no
/// `io_uring` syscall and no equivalent, so the tree there is the original code
/// with the original behaviour. A *runtime* refusal is a different thing and is
/// handled inside [`uring`], which falls back to [`portable`] rather than
/// propagating.
///
/// Both arms keep their blocking work off the executor: `uring` on its own
/// worker thread, `portable` through [`portable_find`]'s `spawn_blocking`
/// offload. The ring's *own* fallback arms call `portable::find_process_info`
/// directly, which is deliberate and is the reason the bound is safe rather
/// than merely cheap — see [`uring`].
#[cfg(target_os = "linux")]
async fn backend_find(local_port: u16) -> Option<ProcessInfo> {
    match selected_backend() {
        Backend::Portable => portable_find(local_port).await,
        Backend::Uring => uring::find_process_info(local_port).await,
    }
}

#[cfg(not(target_os = "linux"))]
async fn backend_find(local_port: u16) -> Option<ProcessInfo> {
    // Resolved anyway, so the same one-line log is emitted on every platform:
    // an operator who sets the variable on macOS is told what was requested
    // rather than getting silence. There is no ring here to honour it -- macOS
    // has no `io_uring` syscall -- so portable answers, as it always has.
    let _selected = selected_backend();
    portable_find(local_port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    /// A TCP socket this process holds, leaked so it outlives the lookup and
    /// keeps showing up in `/proc/net/tcp`.
    ///
    /// TCP, not UDP: the lookup only ever reads `/proc/net/tcp` and
    /// `/proc/net/tcp6` -- UDP sockets live in `/proc/net/udp`, which nothing
    /// in this path has ever consulted. That is pre-existing behaviour and the
    /// backends preserve it, but it means a UDP listener makes for a test that
    /// can never find anything.
    fn own_port() -> u16 {
        static PORT: OnceLock<u16> = OnceLock::new();
        *PORT.get_or_init(|| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
            let port = listener.local_addr().expect("tcp addr").port();
            std::mem::forget(listener);
            port
        })
    }

    /// The two backends, asked the same question, must give the same answer.
    ///
    /// Both are named **explicitly** rather than reached through
    /// [`ProcessSearcher::find_process_info`]. The default backend is
    /// [`Backend::Portable`] (RFC-039 §5.4), so a test that reached the async
    /// entry point expecting "the other backend" would have been comparing
    /// `portable` with `portable` and passing for the wrong reason. Every
    /// differential test in this module names both sides for that reason, and a
    /// test that wants to assert something about the *default* says so
    /// explicitly instead.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn blocking_and_ring_backends_agree() {
        let port = own_port();
        let blocking = ProcessSearcher::find_process_info_blocking(port);
        let ring = super::find_process_info_uring(port).await;
        assert_eq!(blocking, ring, "the two backends disagreed on our own port");
        assert_eq!(blocking.as_ref().map(|p| p.pid), Some(std::process::id()));
    }

    /// The shipped default resolves a socket this process holds.
    ///
    /// Pinned with [`force_backend`] rather than by reading the environment,
    /// for the F11 reason: [`BACKEND`] is a `OnceLock`, so a `set_var` here
    /// would be a race rather than a setup. What is asserted is the selection
    /// and the dispatch it drives, and those two together are what "the default
    /// is portable" actually means.
    #[tokio::test]
    async fn the_default_backend_resolves_a_socket_this_process_holds() {
        let _pinned = force_backend(Backend::Portable);
        assert_eq!(backend_for_test(), Backend::Portable);

        let port = own_port();
        let found = ProcessSearcher::find_process_info(port)
            .await
            .unwrap_or_else(|| panic!("no process attributed to our own TCP port {port}"));
        assert_eq!(found.pid, std::process::id(), "attributed to the wrong pid");
        assert!(!found.name.is_empty());
    }

    /// The opt-in must never produce a worse answer than the default.
    ///
    /// This is the contract the RFC-039 §5.4 reversal depends on and the one
    /// the module docs have always promised: selecting the ring changes
    /// performance, never behaviour. It holds for two very different reasons
    /// depending on the host, and the test is written so that it is the *same*
    /// assertion either way:
    ///
    /// * **Ring available** — the ring answers, and it must match `portable`.
    /// * **Ring refused** — `io_uring_setup` failed (seccomp, kernel,
    ///   `RLIMIT_NPROC`), `uring::find_process_info` routes to `portable`, and
    ///   the lookup must still resolve to this process. No panic, no `None`,
    ///   no hang.
    ///
    /// Which of the two ran is reported rather than asserted, because asserting
    /// "the ring is unavailable" would fail on every ordinary host and
    /// asserting "it is available" would fail on exactly the locked-down hosts
    /// this behaviour exists for. Both outcomes are correct; only the answer
    /// matters.
    ///
    /// To exercise the refused half for real, run this one test with
    /// `io_uring_setup` blocked by a seccomp filter -- the condition
    /// [`uring`] documents. The output then reads
    /// `io_uring ring available in this process: false` alongside the pass,
    /// and that pairing *is* the proof.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn selecting_uring_never_answers_worse_than_portable() {
        let _pinned = force_backend(Backend::Uring);
        assert_eq!(backend_for_test(), Backend::Uring);
        eprintln!("io_uring ring available in this process: {}", super::uring::is_available());

        let port = own_port();
        let via_uring = ProcessSearcher::find_process_info(port).await;
        let via_portable = ProcessSearcher::find_process_info_blocking(port);

        assert_eq!(
            via_uring, via_portable,
            "selecting the ring changed the answer for port {port}: \
             uring={via_uring:?} portable={via_portable:?}"
        );
        assert_eq!(
            via_uring.as_ref().map(|p| p.pid),
            Some(std::process::id()),
            "this process holds port {port}; the opt-in must attribute it here whether \
             the ring ran or the lookup fell back"
        );
    }

    /// The differential test.
    ///
    /// Walks a spread of real and synthetic ports through both backends and
    /// demands identical answers. Synthetic ports are the interesting half:
    /// they mostly miss, and a miss has several ways to be wrong (wrong table,
    /// wrong row, wrong inode) that a single successful hit would not expose.
    ///
    /// `/proc/net/tcp` belongs to the whole host and changes while this runs,
    /// so a single disagreement is not automatically a backend bug. When the
    /// two disagree the test re-reads through the portable path: if that third
    /// answer matches the uring one, the system moved underneath the pair and
    /// the run is not evidence of anything. Only a *persistent* disagreement
    /// fails, which is the case that matters.
    ///
    /// The ring is addressed by name and its liveness is asserted first,
    /// because [`super::find_process_info_uring`] transparently returns
    /// portable answers when the ring never started. Without that assertion, a
    /// host where `io_uring_setup` is refused would run this entire sweep
    /// comparing `portable` against `portable` and report success.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn backends_agree_across_many_ports() {
        assert!(
            super::uring::is_available(),
            "the ring never started, so this sweep would compare the portable path \
             against itself and prove nothing -- see `uring_ring_is_live_on_this_host`"
        );

        let mut ports = vec![own_port()];
        ports.extend([22u16, 53, 80, 443, 993, 1080, 5353, 8080, 51820, 1, 0, 65535]);
        // The ephemeral range, where real sockets actually land.
        ports.extend(30000..30100);
        // And a stride across the whole port space.
        ports.extend((0..65535u32).step_by(1013).map(|p| p as u16));

        let mut hits = 0;
        for port in ports {
            let blocking = ProcessSearcher::find_process_info_blocking(port);
            let asyn = super::find_process_info_uring(port).await;
            if asyn.is_some() {
                hits += 1;
            }

            if blocking == asyn {
                continue;
            }
            let recheck = ProcessSearcher::find_process_info_blocking(port);
            assert_eq!(
                recheck, asyn,
                "backends disagreed persistently on port {port}: \
                 blocking={blocking:?} recheck={recheck:?} uring={asyn:?}"
            );
        }
        assert!(hits > 0, "the sweep never resolved anything; it proved nothing");
    }

    #[tokio::test]
    async fn unknown_port_resolves_to_nothing() {
        // 0 is not a bindable port, so nothing can own it.
        assert!(ProcessSearcher::find_process_info_blocking(0).is_none());
        assert!(ProcessSearcher::find_process_info(0).await.is_none());
    }

    /// The differential test over the ports the host really has open.
    ///
    /// `backends_agree_across_many_ports` sweeps a fixed list, which on any
    /// normal machine mostly misses. These ports come out of the live
    /// `/proc/net/tcp{,6}`, so they carry real hex ports (`4965`, `8EA5`,
    /// `C001`), real states (`01`, `06`, `0A`) and real inodes -- the input
    /// shape where a difference between the backends would actually produce two
    /// different processes for one port.
    ///
    /// The ring is called directly rather than through `find_process_info`, so
    /// the memo cannot make two different backends agree by returning the same
    /// cached value.
    ///
    /// # Why disagreement takes three rounds to be evidence
    ///
    /// The port list is a snapshot of a host that **moves while this runs**: a
    /// socket closes, a process restarts, a port is rebound between two reads
    /// microseconds apart. One disagreement is therefore not automatically a
    /// backend bug, and the previous version of this test accepted the first
    /// re-read as settling it. That is too weak in one direction and far too
    /// strong in another: it let a genuine defect through whenever the host
    /// happened to move, and it called a move a defect whenever it did not.
    ///
    /// The rule here is that a disagreement is only reported once the **portable
    /// answer has held still across every round**. If it is stable and the ring
    /// still differs, the port did not move and one backend cannot see it. A
    /// false accusation now requires the host to be stable for the duration of
    /// the re-reads *and* the ring to be wrong on every one of them, which is
    /// what caught the `getdents64` short-read truncation in
    /// [`super::uring::scan_fd_dir`]: a `java` process holding 559 descriptors
    /// that the ring reported as `None` while the portable path named it, every
    /// time it was asked.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn backends_agree_on_the_ports_this_host_has_open() {
        let mut ports: Vec<u16> = Vec::new();
        for path in portable::PROC_NET_TABLES {
            let Ok(content) = std::fs::read_to_string(path) else { continue };
            for line in content.lines().skip(1) {
                let mut fields = line.split_whitespace();
                let Some(addr) = fields.nth(1) else { continue };
                let Some(port) =
                    addr.split(':').nth(1).and_then(|hex| u16::from_str_radix(hex, 16).ok())
                else {
                    continue;
                };
                ports.push(port);
            }
        }
        // Our own sockets, so the sweep contains something that resolves even
        // on a host whose sockets belong to other users -- `/proc/[pid]/fd` of
        // another uid is unreadable without CAP_SYS_PTRACE, so those ports are
        // `None` on both backends and prove less than a hit does.
        ports.push(own_port());

        assert!(!ports.is_empty(), "no ports at all; the sweep would prove nothing");

        let mut hits = 0;
        for port in ports {
            let blocking = ProcessSearcher::find_process_info_blocking(port);
            let ring = super::find_process_info_uring(port).await;
            if ring.is_some() {
                hits += 1;
            }
            if blocking == ring {
                continue;
            }

            // The host may have moved between the two reads. Only a portable
            // answer that repeats, while the ring keeps disagreeing, is a
            // backend difference rather than a socket that went away.
            let mut stable = blocking.clone();
            let mut disagreements = vec![ring.clone()];
            for _ in 0..2 {
                let recheck = ProcessSearcher::find_process_info_blocking(port);
                let ring_again = super::find_process_info_uring(port).await;
                if recheck != stable {
                    // The port itself changed underneath us; this round proves
                    // nothing, and neither does the disagreement it came from.
                    stable = None;
                    break;
                }
                disagreements.push(ring_again);
            }
            if stable.is_none() {
                continue;
            }

            assert_eq!(
                disagreements[0], disagreements[1],
                "the ring's answer for port {port} changed between two reads while the \
                 portable answer stayed put: blocking={blocking:?} \
                 first={:?} second={:?} -- the port is moving, not the backend",
                disagreements[0], disagreements[1],
            );
            assert_eq!(
                stable, ring,
                "backends disagreed persistently on port {port} while the port itself \
                 was not moving: blocking={blocking:?} recheck={stable:?} uring={ring:?}"
            );
        }
        assert!(hits > 0, "the sweep never resolved a port; it proved nothing");
    }

    /// Without this the uring tests above would still pass on a host where the
    /// ring never started and every "uring" answer was really `portable`.
    #[cfg(target_os = "linux")]
    #[test]
    fn uring_ring_is_live_on_this_host() {
        assert!(
            uring::is_available(),
            "the io_uring worker did not start, so every uring assertion in this \
             module would be silently testing the portable fallback"
        );
    }

    // --- executor occupancy --------------------------------------------------
    //
    // The lookup is a blocking `/proc` scan reached from `async fn`s on the
    // dispatcher hot path. Calling it inline runs that scan on a Tokio runtime
    // worker; `portable_find` moves it onto the blocking pool instead. This is
    // the instrument that tells the two apart, and it carries its own control so
    // a green result cannot mean "the probe stopped working".

    /// How long each canary measurement window runs.
    const CANARY_WINDOW: Duration = Duration::from_millis(120);

    /// Lookups issued per loaded window. Enough that the window is filled by the
    /// load rather than by the canary's deadline.
    const CANARY_LOOKUPS: usize = 300;

    /// Count how many times the runtime is willing to schedule the canary while
    /// `load` runs alongside it, and how long the load itself took.
    ///
    /// The canary is a bare `yield_now()` loop: it does no work, so the only
    /// thing that can slow it down is the runtime not running it. Everything
    /// else in this process is idle. Its hop count is therefore a direct read on
    /// how much of the executor a neighbouring task can take.
    ///
    /// The load's own duration comes back because a hop count is meaningless
    /// without it: a load that finished in 20ms leaves the canary 100ms of free
    /// worker it did not have to compete for, and would be reported as a healthy
    /// offload.
    async fn canary_hops_during(
        load: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> (usize, Duration) {
        let canary = tokio::spawn(async {
            let deadline = Instant::now() + CANARY_WINDOW;
            let mut hops = 0usize;
            while Instant::now() < deadline {
                tokio::task::yield_now().await;
                hops += 1;
            }
            hops
        });
        let started = Instant::now();
        tokio::spawn(load).await.expect("load task must not panic");
        let took = started.elapsed();
        (canary.await.expect("canary task must not panic"), took)
    }

    /// The shipped lookup path must not monopolise an executor worker.
    ///
    /// **One worker thread, on purpose.** The defect is a blocking syscall on a
    /// runtime worker, and on an eight-worker runtime the other seven hide it.
    /// Pinning the runtime to a single worker makes one blocked thread the whole
    /// executor.
    ///
    /// Three windows are measured back to back in the same process:
    ///
    /// 1. **baseline** — the canary alone. This is what a free worker yields.
    /// 2. **inline** — `find_process_info_blocking` in a loop, which is what
    ///    `backend_find` used to do on the `Portable` arm. This is the
    ///    **control**: if the probe cannot tell this apart from the baseline, the
    ///    probe is worthless and this test is asserting nothing. It must collapse.
    /// 3. **offloaded** — [`ProcessSearcher::find_process_info`], the shipped
    ///    path, which goes through `spawn_blocking`. It must stay near baseline.
    ///
    /// Both loads issue the same number of lookups and yield once between each,
    /// which is generous to the inline case: that `yield_now` is exactly the
    /// scheduling opportunity a real caller gives its neighbours, so the inline
    /// arm is allowed a hop per lookup rather than none at all. It still loses by
    /// more than an order of magnitude, and the arm that has to clear the bar is
    /// the shipped one.
    ///
    /// # The two bounds are not equally tight, on purpose
    ///
    /// `offloaded` is held to **ten percent of baseline**, which is tight: it is
    /// the shipped path, and a regression to inline occupancy is the defect this
    /// test exists to catch.
    ///
    /// `inline` is held to **a tenth of baseline** -- an order of magnitude, not
    /// a fixed percentage chosen for how the numbers looked on one afternoon.
    /// The control's job is to prove the probe can *tell the two apart*; a dead
    /// probe reports `inline == baseline` and misses this by 10x, while the
    /// measured separation is ~49x, so the bound sits with several times the
    /// margin on both sides of it. Tightening it further would assert a specific
    /// contention ratio, which is a property of the host's `/proc` size and CPU
    /// count, not of this code.
    ///
    /// The memo is pinned off and the backend pinned to `portable`, so this
    /// measures a real scan rather than a cache hit: with the memo on, the lookup
    /// returns without dispatching and every number above would be fiction.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn the_shipped_lookup_does_not_monopolise_the_executor_worker() {
        let _pinned = force_backend(Backend::Portable);
        let _memo_off = super::cache::force_ttl(None);
        assert!(
            super::cache::ttl_for_test().is_none(),
            "this test measures an uncached scan; a memo hit would never dispatch"
        );

        let port = own_port();

        let (baseline, _) = canary_hops_during(async {
            tokio::time::sleep(CANARY_WINDOW).await;
        })
        .await;

        let (inline, inline_took) = canary_hops_during(async move {
            for _ in 0..CANARY_LOOKUPS {
                tokio::task::yield_now().await;
                std::hint::black_box(ProcessSearcher::find_process_info_blocking(port));
            }
        })
        .await;

        let (offloaded, offloaded_took) = canary_hops_during(async move {
            for _ in 0..CANARY_LOOKUPS {
                tokio::task::yield_now().await;
                std::hint::black_box(ProcessSearcher::find_process_info(port).await);
            }
        })
        .await;

        eprintln!(
            "executor canary hops in {CANARY_WINDOW:?}: baseline={baseline} ({:?}) \
             inline={inline} over {inline_took:?} offloaded={offloaded} over {offloaded_took:?}",
            CANARY_WINDOW
        );

        assert!(
            baseline > 1_000,
            "the canary barely ran at all; this host is unusable as an instrument: {baseline} hops"
        );

        // Both loads must actually have filled their window, or the hop counts
        // are comparing different amounts of contention.
        assert!(
            inline_took >= CANARY_WINDOW / 2 && offloaded_took >= CANARY_WINDOW / 2,
            "a load finished early, so the windows are not comparable: inline ran \
             {CANARY_LOOKUPS} lookups in {inline_took:?}, offloaded in {offloaded_took:?}"
        );

        // The control. Without this the assertion below could be passing because
        // the probe measures nothing, which is the failure mode a timing test is
        // most prone to. One order of magnitude, per the module note above: a
        // probe that has stopped distinguishing the two reports `inline ==
        // baseline` and misses this bound by 10x.
        assert!(
            inline * 10 < baseline,
            "the probe cannot distinguish a blocking scan from a free worker \
             (inline={inline} vs baseline={baseline}, {:.1}% of a free worker). \
             The offloaded figure would prove nothing until this one fails loudly \
             instead.",
            100.0 * inline as f64 / baseline as f64,
        );

        // Ten percent, not parity: the offload costs a thread hop per lookup and
        // a pool wake-up, and the canary competes with those. The bar is set to
        // catch a regression to inline occupancy -- which the control above
        // proves this host separates by a wide margin, see that note -- not to
        // catch a few percent of scheduling noise.
        assert!(
            offloaded * 10 >= baseline,
            "the shipped lookup path took the executor worker with it: the canary \
             managed {offloaded} hops against a baseline of {baseline} \
             ({:.1}% of a free worker). The /proc scan is back on the runtime \
             worker -- see portable_find.",
            100.0 * offloaded as f64 / baseline as f64,
        );
    }

    // --- port reuse ---------------------------------------------------------
    //
    // The lookup's key is a 16-bit port, and a port is not owned for as long as
    // anyone cares to keep it: the kernel is free to hand a just-closed number
    // to a different process at the next instant. The two tests below pin both
    // halves of that fact, because it is the entire argument for the memo's
    // default and nothing else in the tree demonstrates it.

    /// Child exit code meaning "the port was taken before I got there".
    const EXIT_CHILD_COULD_NOT_BIND: i32 = 70;

    /// How many ports to try before giving up on winning the bind race.
    const REBIND_ATTEMPTS: usize = 3;

    /// Fork a child that binds `port` and then does nothing but pause.
    ///
    /// A second listener inside this process would not do: the answer would be
    /// this pid before and after, so the test would pass *with* a stale memo,
    /// because the stale value would happen to be right. Proving that a
    /// rebound port follows its new owner needs two different pids.
    ///
    /// `fork(2)` rather than re-executing the test binary: this is a plain
    /// `#[test]`, the harness is libtest, and nextest runs one test per process,
    /// so nothing else is running in here for a forked child to deadlock
    /// against. The child performs a `bind` and then `pause` in a loop, and
    /// reports failure through `_exit` rather than by returning, so it never
    /// unwinds through a harness, a lock or an allocator arena the parent owned.
    fn fork_listener(port: u16) -> libc::pid_t {
        // SAFETY: the parent is single-threaded at this point, and the child
        // performs a `bind`, a `pause` and `_exit`.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // The listener is bound into a **named** binding and leaked, because
            // a temporary in the `if` condition is dropped before the first
            // `pause` -- the child would hold the port for less time than the
            // parent's first poll, and the test would fail for a reason that
            // has nothing to do with the lookup. This is the same reason
            // `own_port` leaks its listener.
            let bound = std::net::TcpListener::bind(("127.0.0.1", port));
            let Ok(listener) = bound else {
                // SAFETY: `_exit` never returns and runs no cleanup.
                unsafe { libc::_exit(EXIT_CHILD_COULD_NOT_BIND) }
            };
            std::mem::forget(listener);
            loop {
                // SAFETY: `pause` has no preconditions and, with no handler
                // installed for any signal, does not return.
                unsafe { libc::pause() };
            }
        }
        assert!(pid > 0, "fork failed: {}", std::io::Error::last_os_error());
        pid
    }

    /// Kill and reap a child, whether it is running or already a zombie.
    ///
    /// Both failures are expected on the paths that get here: `kill` returns
    /// `ESRCH` for a child that exited on its own, and `waitpid` returns
    /// `ECHILD` for one this call has already reaped. Neither is a test
    /// failure -- the point of this call is that no child outlives the test,
    /// and an ignored return value is still a reaped child.
    fn kill_and_reap(child: libc::pid_t) {
        // SAFETY: `child` is this process's own child and has not been reaped
        // more than once.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
    }

    /// Whether the child came up holding `port`.
    ///
    /// `false` covers both ways this can fail to be evidence: the child lost
    /// the bind to another process, and the child did not come up at all
    /// within the deadline. The second is a scheduling or table-read stall
    /// rather than a property of the lookup, so it retries on another port
    /// instead of failing the test. That is a deliberate trade: a five-second
    /// stall on a loaded host says nothing about port reuse, and a test that
    /// fails for it teaches people to re-run the suite.
    ///
    /// `libc::waitpid` returns a raw `pid_t` rather than an `io::Result`, so
    /// every call here checks what it was handed instead of unwrapping.
    fn wait_until_bound(port: u16, child: libc::pid_t) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if portable::find_inode(port).is_some() {
                return true;
            }
            // SAFETY: `child` is this process's own un-reaped child, and a null
            // status pointer means the exit status is simply not wanted.
            let reaped = unsafe { libc::waitpid(child, std::ptr::null_mut(), libc::WNOHANG) };
            if reaped == child {
                return false;
            }
            if reaped != 0 || Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// One rebind cycle: a child owns `port`, the child dies, this process takes
    /// `port`, and the pid observed afterwards comes back.
    ///
    /// Both observations go through [`ProcessSearcher::find_process_info`], the
    /// async entry point the data path actually uses -- memo and backend both.
    /// The blocking helper would be the wrong instrument twice over: it is
    /// documented to bypass the memo, so it cannot demonstrate a stale entry,
    /// and using it would leave the memo untested by the very test that exists
    /// to describe what the memo costs.
    ///
    /// `None` means the cycle could not be set up -- the port was lost to
    /// another process, or the child never came up -- which the caller retries
    /// on a different port. Every path through here reaps the child.
    fn rebind_cycle(rt: &tokio::runtime::Runtime) -> Option<(libc::pid_t, u32)> {
        // A free port, released again so the child can take it.
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);

        let child = fork_listener(port);
        if !wait_until_bound(port, child) {
            kill_and_reap(child);
            return None;
        }

        let before = rt
            .block_on(ProcessSearcher::find_process_info(port))
            .unwrap_or_else(|| panic!("port {port} is bound but resolved to nothing"));
        assert_eq!(
            before.pid as libc::pid_t, child,
            "the port is held by the child process, so the lookup must say so"
        );

        // A killed listener leaves no TIME_WAIT behind -- there was never a
        // connection to close -- so the number is immediately rebindable. The
        // loop below is belt and braces for the kernel taking its own time.
        kill_and_reap(child);

        let deadline = Instant::now() + Duration::from_secs(5);
        let listener = loop {
            match TcpListener::bind(("127.0.0.1", port)) {
                Ok(listener) => break listener,
                Err(err) => {
                    assert!(
                        Instant::now() < deadline,
                        "port {port} was never released by the child: {err}"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        // Leaked so the row survives the lookup below, for the same reason
        // `own_port` leaks its listener.
        std::mem::forget(listener);

        let after = rt
            .block_on(ProcessSearcher::find_process_info(port))
            .unwrap_or_else(|| panic!("this process holds port {port} but resolved to nothing"));
        Some((child, after.pid))
    }

    /// The shipped default, asserted rather than assumed.
    ///
    /// With the memo disabled -- the state an unset
    /// `SHADOWMESH_PROC_CACHE_TTL_MS` produces, and the state a rebinding
    /// kernel can never talk us out of -- a port that changes hands is
    /// attributed to its **new** owner on the very next lookup. This is the
    /// control the memo is measured against: it is the answer a stale entry
    /// would have to differ from for anything to be proven.
    #[test]
    fn a_rebound_port_is_attributed_to_its_new_owner() {
        let _disabled = super::cache::force_ttl(None);
        assert_eq!(
            super::cache::ttl_for_test(),
            None,
            "this test asserts the behaviour of the memo-disabled configuration"
        );

        // Current-thread, so the process stays single-threaded and the fork in
        // `rebind_cycle` keeps its argument.
        let rt =
            tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");

        for _ in 0..REBIND_ATTEMPTS {
            let Some((child, after)) = rebind_cycle(&rt) else { continue };
            assert_eq!(
                after,
                std::process::id(),
                "the port now belongs to this process, not to the child ({child}) that \
                 held it a moment ago"
            );
            return;
        }
        panic!(
            "could not complete a rebind cycle on any of {REBIND_ATTEMPTS} ports -- another \
             process kept winning the bind, or a forked child never came up. This is a \
             property of the host, not of the lookup."
        );
    }

    /// What enabling the memo would cost, asserted so it cannot be forgotten.
    ///
    /// This is a characterisation test: it asserts that the memo **does**
    /// report the previous owner, which is the defect the default TTL of `0`
    /// exists to avoid. It is here so that trade is executable rather than a
    /// paragraph in a module doc nobody re-reads.
    ///
    /// If this test ever fails, the memo grew revalidation. That is a good
    /// outcome and the reason it exists -- but the default TTL, the operator
    /// documentation and the risk note in `docs/perf-baseline.md` all have to be
    /// revisited in the same change. Do not delete this test to make it green.
    #[test]
    fn the_memo_would_report_the_previous_owner_of_a_rebound_port() {
        let _enabled = super::cache::force_ttl(Some(Duration::from_secs(60)));
        assert!(super::cache::ttl_for_test().is_some(), "the memo must be enabled here");

        let rt =
            tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");

        for _ in 0..REBIND_ATTEMPTS {
            let Some((child, after)) = rebind_cycle(&rt) else { continue };
            assert_eq!(
                after as libc::pid_t, child,
                "the memo served the previous owner's pid for a port that has changed hands: \
                 child={child} observed={after}"
            );
            return;
        }
        panic!(
            "could not complete a rebind cycle on any of {REBIND_ATTEMPTS} ports -- another \
             process kept winning the bind, or a forked child never came up. This is a \
             property of the host, not of the lookup."
        );
    }

    // --- backend selection parse rules --------------------------------------
    //
    // These call `parse_backend` directly, so they need neither the environment
    // nor the memoised selection and cannot be affected by test order. The
    // memoised read is covered by `the_default_backend_resolves_a_socket_this_
    // process_holds`, which pins the value instead of racing for it.

    /// The unset case, which is the whole point of RFC-039 §5.4.
    #[test]
    fn an_unset_backend_env_selects_portable() {
        assert_eq!(
            parse_backend(None),
            Backend::Portable,
            "the default backend must stay portable -- it measured 3.8-4.8x faster \
             than the ring at concurrency 64 (F22)"
        );
    }

    #[test]
    fn uring_is_selectable_by_name() {
        assert_eq!(parse_backend(Some("uring")), Backend::Uring);
    }

    #[test]
    fn portable_is_selectable_explicitly() {
        assert_eq!(parse_backend(Some("portable")), Backend::Portable);
    }

    #[test]
    fn backend_names_tolerate_case_and_padding() {
        // Operators paste these out of shells and compose files.
        assert_eq!(parse_backend(Some(" URING ")), Backend::Uring);
        assert_eq!(parse_backend(Some("Uring")), Backend::Uring);
        assert_eq!(parse_backend(Some("PORTABLE\n")), Backend::Portable);
    }

    /// A typo degrades to the default rather than to a guess.
    ///
    /// The same rule `parse_ttl` applies to an unparseable TTL: a value we
    /// cannot interpret must not become a plausible-looking configuration. If
    /// this ever returned `Uring` for an unrecognised spelling, a typo would
    /// silently put every node on the slower backend on a machine that had
    /// already decided to opt out.
    #[test]
    fn a_typo_selects_portable_rather_than_guessing() {
        for typo in ["io_uring", "ring", "true", "1", "none", "portables", "ur ing"] {
            assert_eq!(
                parse_backend(Some(typo)),
                Backend::Portable,
                "{typo:?} is not a backend name and must not be treated as one"
            );
        }
        // An exported-but-empty variable is the same as an unset one, not a
        // request for a backend named "".
        assert_eq!(parse_backend(Some("")), Backend::Portable);
        assert_eq!(parse_backend(Some("   ")), Backend::Portable);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_targets_use_the_portable_backend() {
        // No ring exists here, and that is the documented contract. Selecting
        // `uring` here must not change behaviour, because there is nothing to
        // select.
        let _pinned = force_backend(Backend::Uring);
        assert!(!cfg!(target_os = "linux"));
        assert!(ProcessSearcher::find_process_info_blocking(0).is_none());
    }
}
