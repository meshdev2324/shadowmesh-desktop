//! io_uring backend for the per-packet process lookup (Linux only).
//!
//! # What io_uring actually covers here
//!
//! The lookup is two stages: read `/proc/net/tcp` and `/proc/net/tcp6` to turn a
//! port into a socket inode, then scan `/proc/[pid]/fd` for the descriptor that
//! links to that inode. Both are read-mostly, so both were candidates.
//!
//! * **The `/proc/net/tcp{,6}` read is a clean win.** `fs::read_to_string`
//!   costs an open, a stat, one or two reads and a close *per file*, and the
//!   two files are independent, so there is nothing for the CPU to overlap.
//!   Submitted concurrently to one ring their SQEs are pushed back to back and
//!   leave in a single `io_uring_enter`, and each buffer round-trips through
//!   the operation instead of being reallocated per read.
//! * **The per-pid directory fan-out is a partial win.** The mainline ABI has
//!   no `IORING_OP_GETDENTS` and no `IORING_OP_READLINK`, so the directory
//!   read itself and the `socket:[inode]` string comparison cannot be
//!   expressed as SQEs at all -- on a typical host the `readlink` of every
//!   open descriptor outnumbers everything else in the lookup by an order of
//!   magnitude. What *can* be batched is the `open`/`close` of every
//!   `/proc/[pid]/fd` directory, and that is what this backend does: the whole
//!   chunk is opened in one submit and closed in another, instead of paying
//!   two syscalls per pid.
//!
//! So this is a real io_uring path over the parts of the lookup the ABI can
//! express, and it is explicit about the part it cannot.
//!
//! # Runtime shape
//!
//! `tokio_uring` owns a thread-local driver and its `Runtime::block_on` panics
//! if called from inside another Tokio runtime -- which is exactly where
//! `Dispatcher::enrich_metadata` calls it from. Rather than demanding that
//! every caller built their runtime with `enable_io`, a single dedicated worker
//! thread owns the ring and services lookups over a **bounded** channel. That
//! also means the ring is created once per process instead of once per lookup.
//!
//! If the worker cannot start -- `io_uring_setup` refused by a seccomp policy,
//! an old kernel, `RLIMIT_NPROC` -- the channel simply closes and every lookup
//! transparently falls back to [`super::portable`], so behaviour on a
//! locked-down host is exactly what it was before this file existed. That
//! fallback is reported, not silent: see [`spawn_worker`].
//!
//! # The queue is bounded, and what happens when it is full
//!
//! The channel used to be unbounded, which made the memory cost of a burst a
//! function of how far the arrival rate outran one thread. It is now bounded at
//! [`RING_QUEUE_DEPTH`], and the policy at the bound is **refuse the newcomer**:
//! the lookup is answered from [`super::portable`] instead.
//!
//! Why that is not an attribution gap, which is the question the policy turns
//! on: a [`Job`] owns the `oneshot::Sender` that answers it, so refusing a job
//! **drops the sender**, and [`find_process_info`]'s existing
//! `Err(_) => portable::find_process_info(..)` arm is exactly what that
//! triggers. The caller waits for an answer and gets one from the other
//! backend. `tests::a_refused_lookup_is_answered_from_portable_not_dropped`
//! pins that arm so it cannot be quietly removed, and
//! `tests::a_burst_past_the_bound_still_attributes_every_lookup` pins the
//! end-to-end version.
//!
//! The two rejected alternatives, and why they are worse:
//!
//! * **Drop-oldest.** Evicts the queued job that has waited longest. The worker
//!   was about to serve it, so the evicted caller now redoes that lookup on the
//!   portable path *while* the worker carries on chewing the rest: the work is
//!   not saved, it is done twice, and the caller that waited longest pays for
//!   it. Rejecting the newcomer keeps the queue holding the work nearest
//!   completion, which is what maximises ring throughput under contention.
//! * **Block.** `sync_channel` would let the sender wait for room. The sender is
//!   a synchronous std channel and the caller is an async task on a shared
//!   runtime, so blocking there trades unbounded memory for unbounded latency
//!   held by runtime worker threads -- and under high concurrency a synchronous
//!   block is how a Tokio runtime starves. Rejection keeps the lookup
//!   asynchronous and the answer correct.

use super::portable;
use super::ProcessInfo;
use futures_util::future::join_all;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use tokio::sync::oneshot;
use tokio_uring::fs::File;
use tracing::warn;

/// Submission-queue depth for the shared ring. Lookups issue a handful of
/// operations at a time, so this is sized for batching, not for throughput.
const RING_ENTRIES: u32 = 64;

/// How many lookups may wait for the worker before the queue refuses one.
///
/// # Derived from the measurement, not chosen
///
/// F22 (`docs/REMAINING-WORK.md:127`, 2026-10-13) measured, on the ring, at
/// concurrency 64:
///
/// * **127 lookups/s, cold** (641 /s warm);
/// * **flat from concurrency 1 to 64** -- 123.6 -> 127.1 /s, so 64x the
///   concurrency buys 3%. The worker is the ceiling, not the queue;
/// * **~174 bytes per pending lookup**, and the queue "does not drain"
///   (80,000 queued = +13.6 MiB).
///
/// The bound is therefore **the number of lookups this worker can serve in one
/// second at its measured cold rate**: `ceil(127/s) = 128`.
///
/// Both directions of the choice are argued by the same measurement:
///
/// * **Not smaller.** A queue shallower than one second of arrivals refuses
///   lookups the worker would have served inside that second. The refusal path
///   is correct but it is the slow path, so refusing work the ring could have
///   done is a needless loss.
/// * **Not larger.** Depth past one second of service time *is* the "never
///   drains" property F22 measured. A deeper queue does not make the worker
///   faster -- the flat 123.6 -> 127.1 curve says depth buys nothing at all
///   once the worker is busy -- it only buys a longer time before the memory is
///   returned. That is the unbounded cost this constant exists to remove.
///
/// **What it costs.** `128 x 174 B = 22,272 B`, about **21.8 KiB**, against the
/// 13.6 MiB F22 observed at 80,000 queued -- a ~625x reduction in worst-case
/// queue footprint, to a figure that is not a resource-exhaustion path on any
/// host. The ceiling is the important half of this change; the number is
/// chosen so that reaching it does not quietly reintroduce one.
///
/// **This is a single-host baseline.** It has not been measured on edge
/// hardware, and the worker rate is a property of the host's process and
/// descriptor counts. If the ring is re-measured and the rate moves, this
/// constant is the thing that should move with it -- see RFC-039 §5.4.
const RING_QUEUE_DEPTH: usize = 128;

/// Rejection count at which the first saturation warning fires, and the decade
/// step between subsequent ones.
const FIRST_WARN_AT: u64 = 1;

/// Saturation reporting stops escalating past this many refusals.
///
/// Keeps the decade multiply total. A process that has refused a billion
/// lookups has a far worse problem than a missing log line, and this is the
/// ceiling rather than a judgement that a billion is fine.
const WARN_CEILING: u64 = 1_000_000_000;

/// `/proc/[pid]/fd` directories opened per batched submit.
///
/// Bounded so the lookup never holds an unbounded number of descriptors open;
/// 32 keeps the batched open/close worth its indirection while staying well
/// inside any plausible `RLIMIT_NOFILE`.
const FD_DIR_CHUNK: usize = 32;

/// First read size for a `/proc/net/tcp` table. The table is a few kilobytes on
/// a typical host and only grows with the socket count, so starting small avoids
/// memsetting 128 KiB for a 4 KiB file.
const FIRST_READ: usize = 16 * 1024;

/// Read size once the table has proved it is larger than [`FIRST_READ`].
const NEXT_READ: usize = 128 * 1024;

/// `getdents64` buffer. One syscall returns this many bytes of
/// `struct linux_dirent64` records, typically a few hundred descriptors.
const DENTS_BUF: usize = 8 * 1024;

/// Buffer size once a `getdents64` has filled [`DENTS_BUF`] completely, which
/// is the signal that more descriptors may remain.
const DENTS_BUF_NEXT: usize = 64 * 1024;

/// `socket:[4294967295]` is 20 bytes; 64 leaves room without a second retry.
const READLINK_BUF: usize = 64;

// ---------------------------------------------------------------------------
// Dispatch to the worker
// ---------------------------------------------------------------------------

/// Find the process owning `local_port`, using io_uring for the bulk reads.
///
/// Falls back to [`portable::find_process_info`] whenever the ring is not
/// usable, **or whenever the queue is full**, so callers never have to know
/// which backend answered and never receive nothing. See the module docs for
/// the bound and the refusal policy.
pub(crate) async fn find_process_info(local_port: u16) -> Option<ProcessInfo> {
    let Some(worker) = shared_worker() else {
        return portable::find_process_info(local_port);
    };

    let (reply, rx) = oneshot::channel();
    if !worker.submit(local_port, reply) {
        // The queue is full, or the worker died after being established. The
        // job was dropped either way, so the reply sender went with it; answer
        // this lookup from the portable path rather than leave the caller
        // waiting on a reply nobody will send.
        return portable::find_process_info(local_port);
    }

    match rx.await {
        Ok(answer) => answer,
        // The worker died mid-job after accepting it.
        Err(_) => portable::find_process_info(local_port),
    }
}

enum Job {
    Lookup(u16, oneshot::Sender<Option<ProcessInfo>>),
}

struct Worker {
    tx: SyncSender<Job>,
    /// Lookups refused because the queue was at [`RING_QUEUE_DEPTH`].
    ///
    /// The observability half of the bound. A bounded queue that refuses
    /// silently is worse than an unbounded one that is merely slow, because
    /// the refusal looks exactly like a lookup that found nothing -- which is
    /// the one answer the data path cannot distinguish from a real miss.
    refused: AtomicU64,
    /// Refusal count at which the next warning fires. Advanced by CAS so
    /// concurrent refusals cannot each claim the same decade and print it N
    /// times.
    next_warn_at: AtomicU64,
}

impl Worker {
    fn new(tx: SyncSender<Job>) -> Self {
        Self { tx, refused: AtomicU64::new(0), next_warn_at: AtomicU64::new(FIRST_WARN_AT) }
    }

    /// Hand a lookup to the ring. Never blocks.
    ///
    /// Returns `false` when the job did not reach the worker -- the channel is
    /// dead, or it is full. In both cases the `reply` sender is dropped on the
    /// way out, which is what routes the caller to the portable fallback in
    /// [`find_process_info`]. The caller always gets an answer.
    fn submit(&self, port: u16, reply: oneshot::Sender<Option<ProcessInfo>>) -> bool {
        match self.tx.try_send(Job::Lookup(port, reply)) {
            Ok(()) => true,
            // `Full` hands the job back rather than eating it, so dropping it is
            // deliberate: dropping the sender is the whole mechanism.
            Err(TrySendError::Full(job)) => {
                drop(job);
                self.note_refusal();
                false
            }
            Err(TrySendError::Disconnected(job)) => {
                drop(job);
                false
            }
        }
    }

    /// Refusals since this process started.
    ///
    /// Test-only today. The *shipped* observability for this is the
    /// decade-throttled `warn!` in [`Worker::note_refusal`] -- this is the seam
    /// for a caller that wants a number instead of a log line, and exporting it
    /// as a metric is `services/**` (L8) to wire, per RFC-039 §7.1. Adding a
    /// non-test accessor here with no caller in this crate would be a dead-code
    /// warning, which is the correct signal that the consumer does not exist yet.
    #[cfg(test)]
    pub(crate) fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Count a refusal and log it on the first, then once per decade.
    ///
    /// The throttling is not decoration. Under saturation the refusal path is
    /// taken per lookup, and a `warn!` per lookup would make the log the most
    /// expensive thing on the path -- while also being, per F16, a warning that
    /// fires constantly and is therefore ignored. Reporting the first and then
    /// each order of magnitude gives the magnitude without the volume: five
    /// lines ever, whatever the burst was.
    fn note_refusal(&self) {
        let count = self.refused.fetch_add(1, Ordering::Relaxed) + 1;

        let next = self.next_warn_at.load(Ordering::Relaxed);
        if count < next {
            return;
        }
        if next >= WARN_CEILING {
            return;
        }
        // Only the thread that wins the CAS speaks for this decade.
        if self
            .next_warn_at
            .compare_exchange(next, next * 10, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        warn!(
            "process attribution: io_uring queue is saturated -- {count} lookup(s) refused \
             and answered from the portable path. The queue is bounded at {RING_QUEUE_DEPTH} \
             entries, which is the number this worker serves in one second at its measured \
             rate; arrivals are outrunning the single ring worker. This costs throughput, not \
             correctness: every refused lookup is still attributed, by portable.rs. The count \
             is per process -- surface it as a metric rather than reading this line. If it \
             climbs while nothing is loaded, the ring is the wrong backend for this workload \
             (RFC-039 section 5.4)."
        );
    }
}

/// The process-wide ring worker, or `None` if io_uring is unavailable here.
///
/// `None` is a permanent answer for this process: a seccomp policy that refuses
/// `io_uring_setup` refuses it on the next attempt too, and re-probing per
/// packet would put the failing syscall straight back on the hot path. It is a
/// permanent answer *because* [`spawn_worker`] waits for the worker's report
/// rather than assuming a spawned thread means a ring.
static WORKER: OnceLock<Option<Arc<Worker>>> = OnceLock::new();

fn shared_worker() -> Option<&'static Arc<Worker>> {
    WORKER.get_or_init(spawn_worker).as_ref()
}

/// Whether this process actually got a ring.
///
/// `true` once the ring exists; `false` on any target or sandbox where
/// `io_uring_setup` was refused. The lookup path treats the two identically, but
/// tests use this to prove they are not silently exercising the portable
/// fallback under the name of the io_uring backend.
///
/// **This reports the ring, not the thread.** It used to answer
/// `shared_worker().is_some()`, which is true the moment the worker *thread*
/// is spawned -- so on a host where `io_uring_setup` was refused it reported
/// `true` and `uring_ring_is_live_on_this_host` passed on a process with no
/// ring at all. Verified on 2026-10-13 by running this module's tests under a
/// seccomp filter returning `EPERM` for `io_uring_setup`: the thread came up,
/// the ring did not, and the old answer said the ring was live. [`spawn_worker`]
/// now waits for the worker's own report, which is why this is true only when a
/// ring exists.
#[cfg(test)]
pub(crate) fn is_available() -> bool {
    shared_worker().is_some()
}

/// Lookups refused by the shared worker's bound since this process started.
///
/// Process-global, so a test reading it is describing the whole process rather
/// than one test -- which is why every assertion that needs a specific number
/// builds its own [`Worker`] instead.
#[cfg(test)]
pub(crate) fn refused_lookups() -> u64 {
    shared_worker().map_or(0, |worker| worker.refused())
}

fn spawn_worker() -> Option<Arc<Worker>> {
    // Bounded, not `mpsc::channel`. See `RING_QUEUE_DEPTH`.
    let (tx, rx) = mpsc::sync_channel::<Job>(RING_QUEUE_DEPTH);

    // A rendezvous, not a queue: the worker reports on this exactly once, before
    // it takes its first job, and this function waits for the report.
    //
    // Waiting is the point. The previous version returned as soon as the thread
    // was spawned, which made "the worker exists" indistinguishable from "the
    // ring exists" -- and the second is what every caller of `is_available()`
    // is asking. It blocked a runtime thread for the duration of one
    // `io_uring_setup` syscall, exactly once per process, inside the
    // `OnceLock` that guarantees a single thread ever runs this.
    let (ready_tx, ready_rx) = mpsc::sync_channel::<bool>(0);

    let spawned = std::thread::Builder::new()
        .name("shadowmesh-procfs-uring".to_string())
        .spawn(move || worker_main(rx, ready_tx));

    // A spawn failure leaves `rx` dropped, which makes the first `try_send`
    // fail with `Disconnected` and routes the lookup to the portable path --
    // the same outcome as a refused `io_uring_setup`, and for the same reason.
    if spawned.is_err() {
        return None;
    }

    match ready_rx.recv() {
        Ok(true) => Some(Arc::new(Worker::new(tx))),
        // The worker could not create a ring, or died before reporting. The
        // `Job` sender is dropped here, so every lookup reads `Disconnected`
        // and is answered from `portable.rs`. The worker thread, if it is still
        // winding down, is detached rather than joined -- joining a thread that
        // has already been asked to exit buys nothing and risks blocking here.
        _ => None,
    }
}

fn worker_main(rx: mpsc::Receiver<Job>, ready: SyncSender<bool>) {
    // The operator asked for the ring by selecting this backend, and the ring
    // is not coming: that is a posture divergence between what was configured
    // and what is running, and the `info!` at selection time already said the
    // ring was requested. So it is a warning, and it is once -- `worker_main`
    // runs exactly one time per process.
    let runtime = match tokio_uring::Runtime::new(tokio_uring::builder().entries(RING_ENTRIES)) {
        Ok(runtime) => runtime,
        Err(_) => {
            warn!(
                "process attribution: io_uring was selected but the ring could not be \
                 created (io_uring_setup refused -- seccomp, kernel, or RLIMIT_NPROC). \
                 Every lookup is falling back to portable. Performance changes; behaviour \
                 does not."
            );
            // Report *before* returning. `spawn_worker` is blocked on this, and
            // returning without a report would leave it waiting forever.
            let _ = ready.send(false);
            return;
        }
    };

    // Report the ring before taking any job, so `is_available()` cannot answer
    // for a process that has not finished deciding.
    if ready.send(true).is_err() {
        return;
    }

    // `runtime` is `!Send` (it owns a LocalSet) and stays on this thread for
    // the rest of the loop.
    while let Ok(job) = rx.recv() {
        match job {
            Job::Lookup(port, reply) => {
                let answer = runtime.block_on(lookup(port));
                // A send error only means the requester gave up; the ring is
                // still healthy.
                let _ = reply.send(answer);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The io_uring lookup itself (runs on the worker thread, inside the ring)
// ---------------------------------------------------------------------------

async fn lookup(target_port: u16) -> Option<ProcessInfo> {
    let inode = find_inode(target_port).await?;
    find_pid_by_inode(inode).await
}

/// Port -> socket inode, reading both tables concurrently on the ring.
///
/// The IPv4 table is still consulted first and still wins ties: a v4-mapped v6
/// socket appears in both, and the original implementation always preferred the
/// IPv4 row. Batching the reads must not change which row is believed.
async fn find_inode(target_port: u16) -> Option<u64> {
    let (tcp, tcp6) = tokio::join!(
        read_table(Path::new(portable::PROC_NET_TABLES[0])),
        read_table(Path::new(portable::PROC_NET_TABLES[1])),
    );

    for table in [tcp, tcp6].into_iter().flatten() {
        if let Some(inode) = portable::parse_inode_table(&table, target_port) {
            return Some(inode);
        }
    }
    None
}

/// The accumulation half of [`read_table`], split out so the termination rule
/// can be driven directly.
///
/// The rule is the whole defect and it is *not* testable through a file:
/// `pread` on a regular file returns `min(requested, remaining)`, so the only
/// short read a scratch file can produce is the final one -- whose bytes have
/// already been appended by the time the loop stops. `/proc/net/tcp` is a
/// seq_file and genuinely short-reads mid-stream. Extracting the state lets a
/// test script that shape; see
/// `tests::a_short_read_mid_table_is_not_the_end_of_the_table`.
struct TableDrain {
    out: Vec<u8>,
    pos: u64,
    size: usize,
}

impl TableDrain {
    fn new() -> Self {
        Self { out: Vec::with_capacity(FIRST_READ), pos: 0, size: FIRST_READ }
    }

    /// Absorb one read and report whether the table is complete.
    ///
    /// `buf` is the bytes the read actually returned; `requested` is the size
    /// of the buffer it was given, which the rule needs because the two answer
    /// different questions. A read that filled its buffer proves more may
    /// follow, so the next read is the larger one. A read that did **not** fill
    /// it proves nothing at all on a seq_file, so it must not end the loop --
    /// only a zero read is the end of the table.
    ///
    /// Getting this wrong is the shipped defect: treating a short read as EOF
    /// dropped every row past that point, so the io_uring backend answered "no
    /// process owns this port" for ports the portable backend attributed to a
    /// live process, and shaping and routing rules keyed on process name
    /// silently stopped applying. `fs::read_to_string` loops until a zero read
    /// for exactly this reason.
    fn feed(&mut self, buf: &[u8], requested: usize) -> bool {
        self.out.extend_from_slice(buf);
        self.pos += buf.len() as u64;

        if buf.is_empty() {
            return true;
        }
        if buf.len() == requested {
            self.size = NEXT_READ;
        }
        false
    }
}

/// Read one `/proc/net/tcp{,6}` table through the ring.
///
/// `None` means the table contributes no inode, which is exactly what the
/// portable path's `if let Ok(..)` guard does: an unreadable or non-UTF-8 table
/// is skipped, not an error.
///
/// Takes a `&Path` rather than a `&'static str` so the read loop can be pinned
/// against `fs::read_to_string` on scratch files -- see
/// `tests::ring_read_matches_read_to_string` -- and against the short-read
/// shape a scratch file cannot produce, via [`TableDrain`].
async fn read_table(path: &Path) -> Option<String> {
    let file = File::open(path).await.ok()?;
    let mut drain = TableDrain::new();

    loop {
        // `read_at` hands the buffer back with the result, so the allocation is
        // made once per file rather than once per read.
        let (res, buf) = file.read_at(vec![0u8; drain.size], drain.pos).await;
        let requested = buf.len();
        let read = res.ok()?;
        if drain.feed(&buf[..read], requested) {
            break;
        }
    }

    // Closing is a syscall too, but on the ring: it leaves in the same batch
    // as the reads it follows.
    let _ = file.close().await;

    // `fs::read_to_string` rejects non-UTF-8, so a lossy conversion here would
    // be a behaviour change. Propagate the failure instead.
    String::from_utf8(drain.out).ok()
}

// ---------------------------------------------------------------------------
// Stage two: /proc/[pid]/fd
// ---------------------------------------------------------------------------

/// Scan `/proc/[pid]/fd` for the descriptor linking to `target_inode`.
///
/// Same traversal as [`portable::find_pid_by_inode`] -- same `/proc` order,
/// same first-match-wins rule -- with the per-pid `open`/`close` pair folded
/// into two batched submits per [`FD_DIR_CHUNK`] pids instead of one syscall
/// each.
async fn find_pid_by_inode(target_inode: u64) -> Option<ProcessInfo> {
    let target_link = format!("socket:[{}]", target_inode);

    for chunk in list_procs().chunks(FD_DIR_CHUNK) {
        // One submit for the whole chunk: every SQE is pushed before the driver
        // parks, so the kernel sees one batched openat.
        let opened = join_all(chunk.iter().map(|(_, dir)| open_fd_dir(dir))).await;

        let mut found = None;
        for ((pid, proc_dir), dir) in chunk.iter().zip(&opened) {
            // Skipping a pid whose fd directory would not open matches the
            // portable path, where `read_dir` failing simply skipped the pid.
            let Ok(dir) = dir else { continue };
            // Keep scanning after a match only to keep the close below total;
            // the portable path would have returned at the first hit.
            if found.is_none() {
                found = scan_fd_dir(dir.as_raw_fd(), proc_dir, *pid, &target_link);
            }
        }

        // One submit to release the chunk. Directories opened but not scanned
        // are closed here too, which is why the scan above does not return
        // early.
        let _ = join_all(opened.into_iter().flatten().map(|dir| dir.close())).await;

        if found.is_some() {
            return found;
        }
    }
    None
}

/// `/proc/<pid>/fd` for every numeric pid, in the order `read_dir` yields them.
///
/// The filter is the portable path's, filter for filter: skip anything that is
/// not a directory, skip a name that is not UTF-8, skip a name that is not a
/// `u32`. Keeping the two identical is what makes "the uring backend returned a
/// different pid" a meaningful bug report rather than a reshuffle.
fn list_procs() -> Vec<(u32, PathBuf)> {
    let mut procs = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(pid_str) = path.file_name().and_then(|s| s.to_str()) else { continue };
            let Ok(pid) = pid_str.parse::<u32>() else { continue };
            procs.push((pid, path));
        }
    }
    procs
}

async fn open_fd_dir(proc_dir: &Path) -> std::io::Result<File> {
    File::open(proc_dir.join("fd")).await
}

/// `readlink` each numeric descriptor in an open `/proc/<pid>/fd` until one
/// links to `socket:[inode]`.
///
/// io_uring has no `READLINK` opcode, so this stays on the syscall the portable
/// path uses; what the ring bought is having `dir_fd` arrive without an `open`
/// per pid.
fn scan_fd_dir(dir_fd: RawFd, proc_dir: &Path, pid: u32, target_link: &str) -> Option<ProcessInfo> {
    let mut buf = vec![0u8; DENTS_BUF];

    loop {
        // SAFETY: `dir_fd` is an open directory descriptor owned by the caller's
        // `File` for the duration of this call, and `buf` is a live, correctly
        // sized allocation for the length passed.
        let filled = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                dir_fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };

        if filled <= 0 {
            // 0 is end-of-directory; negative is an error the portable path
            // would also have hit as a short `read_dir`.
            return None;
        }

        let filled = filled as usize;
        let mut offset = 0usize;

        while offset < filled {
            // struct linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen;
            //                         u8 d_type; char d_name[]; }
            // `d_reclen` sits at 16 and `d_name` at 19 with no padding on any
            // Linux ABI this crate builds for.
            let reclen = match read_u16(&buf, offset + 16) {
                Some(len) if len as usize > 0 && offset + len as usize <= filled => len as usize,
                // A zero or out-of-range record length means the buffer is not
                // a getdents64 payload. Refuse it rather than looping.
                _ => return None,
            };

            let name = &buf[offset + 19..offset + reclen];
            let name = match name.iter().position(|&b| b == 0) {
                Some(end) => &name[..end],
                None => name,
            };

            // `.` and `..` are not numeric, and neither is anything that is not
            // a file descriptor. `read_dir` + `read_link` would have tried them
            // and failed to match; skipping them changes no outcome.
            if !name.is_empty()
                && name.iter().all(u8::is_ascii_digit)
                && link_is(dir_fd, name, target_link)
            {
                return portable::read_process_name(proc_dir, pid);
            }

            offset += reclen;
        }

        // `getdents64` returns 0 at end of directory and **that is the only**
        // end of directory.
        //
        // A short return does not mean the directory ended. The kernel's
        // `filldir64` stops emitting when the next record will not fit the
        // buffer, and it does not have to fill the last bytes: on
        // `/proc/127379/fd`, a read into an 8192-byte buffer returned 8184
        // bytes with 218 descriptors still to come. Treating that as EOF --
        // which is what this loop used to do, and what a short read does mean
        // on a regular file -- walked 341 of 559 descriptors, and any socket
        // on a descriptor past the cut was attributed to "no process owns this
        // port". `std::fs::read_dir`, which the portable path uses, loops
        // until a zero read and so saw all 559.
        //
        // This is the same defect `read_table` above already carries a note
        // about, in the same file: a `/proc` read that is not a regular file
        // may come up short with more to read.
        //
        // Grow the buffer once it has been filled to the brim, so a process
        // with thousands of descriptors costs a couple of syscalls rather than
        // one per few hundred descriptors. The record is bounded well below
        // `DENTS_BUF_NEXT` (a `linux_dirent64` name is at most 255 bytes), so
        // the buffer can always hold at least one record and the loop below
        // cannot spin.
        if filled == buf.len() {
            buf.resize(DENTS_BUF_NEXT, 0);
        }
    }
}

/// Does `/proc/<pid>/fd/<name>` resolve to `target_link`?
fn link_is(dir_fd: RawFd, name: &[u8], target_link: &str) -> bool {
    // A pid with more than 2^31 open descriptors is not a thing; the bound
    // only has to keep the NUL-terminated copy on the stack.
    let mut c_name = [0u8; 24];
    if name.len() >= c_name.len() {
        return false;
    }
    c_name[..name.len()].copy_from_slice(name);

    let mut out = [0u8; READLINK_BUF];
    // SAFETY: `c_name` is NUL-terminated and outlives the call, `dir_fd` is open
    // for the duration of the scan, and `out` is a live buffer of the length
    // given.
    let len = unsafe {
        libc::readlinkat(
            dir_fd,
            c_name.as_ptr().cast::<libc::c_char>(),
            out.as_mut_ptr().cast::<libc::c_char>(),
            out.len(),
        )
    };

    len > 0 && String::from_utf8_lossy(&out[..len as usize]) == target_link
}

/// Little-endian `u16` out of a byte slice, or `None` if it would read past the
/// end. The kernel is little-endian on every ABI supported here; the explicit
/// byte assembly keeps this correct by construction regardless.
fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    let bytes = buf.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A ring owned by this test thread.
    ///
    /// `worker_main` builds one per process; a test needs its own because it
    /// drives the functions under test directly rather than through the worker.
    fn ring() -> tokio_uring::Runtime {
        tokio_uring::Runtime::new(&tokio_uring::builder()).expect("ring refused on this host")
    }

    /// A scratch file removed on drop, so a failing test leaves nothing behind.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn scratch(name: &str, bytes: &[u8]) -> Scratch {
        let path =
            std::env::temp_dir().join(format!("shadowmesh-procfs-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).expect("write scratch file");
        Scratch(path)
    }

    /// A syntactically valid `/proc/net/tcp` row.
    fn row(index: usize, port: u16, state: &str) -> String {
        format!(
            "{index:>2}: 0100007F:{port:04X} 00000000:0000 {state} \
             00000000:00000000 00:00000000 00000000     0        0 {} 1 \
             0000000000000000 100 0 0 10 0\n",
            10_000 + index
        )
    }

    /// The read loop must be byte-identical to `fs::read_to_string`.
    ///
    /// This is the only part of the io_uring path that re-implements something
    /// the portable path gets from the standard library: `read_to_string` opens,
    /// reads to EOF and validates UTF-8, while `read_table` opens, loops over
    /// `read_at` and converts at the end. Every way those two can disagree --
    /// stopping a read short, dropping the tail of a large table, accepting
    /// non-UTF-8 that `read_to_string` would reject -- is a case where the two
    /// backends attribute a port to different processes.
    #[test]
    fn ring_read_matches_read_to_string() {
        let rt = ring();

        // Empty file.
        let empty = scratch("empty", b"");
        assert_eq!(rt.block_on(read_table(&empty.0)), std::fs::read_to_string(&empty.0).ok());

        // Header only, below one buffer: the single-read path.
        let header = scratch(
            "header",
            b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n",
        );
        assert_eq!(rt.block_on(read_table(&header.0)), std::fs::read_to_string(&header.0).ok());

        // Larger than FIRST_READ, so the grow-and-continue loop runs. Any
        // dropped tail row would cost the process an attribution.
        let mut big = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n",
        );
        for i in 0..2_000 {
            big.push_str(&row(i, (i % 0x1_0000) as u16, "0A"));
        }
        assert!(
            big.len() > FIRST_READ && big.len() > NEXT_READ,
            "scratch table must span both buffer sizes: {} bytes",
            big.len()
        );
        let big = scratch("big", big.as_bytes());
        assert_eq!(rt.block_on(read_table(&big.0)), std::fs::read_to_string(&big.0).ok());

        // Exactly FIRST_READ bytes: the awkward case, where a single read fills
        // the buffer and the loop has to go round again to discover EOF.
        let exact = format!("{}{}", "x".repeat(FIRST_READ - 1), "\n");
        let exact = scratch("exact", exact.as_bytes());
        assert_eq!(exact.0.metadata().unwrap().len(), FIRST_READ as u64);
        assert_eq!(rt.block_on(read_table(&exact.0)), std::fs::read_to_string(&exact.0).ok());

        // Non-UTF-8: `read_to_string` rejects the file, so the portable path
        // skips the table entirely. The ring path must skip it too rather than
        // substituting replacement characters and inventing rows.
        let bad = scratch("bad-utf8", &[0xff, 0xfe, 0x80, 0x81, b'\n']);
        assert!(std::fs::read_to_string(&bad.0).is_err(), "fixture is not actually invalid UTF-8");
        assert_eq!(rt.block_on(read_table(&bad.0)), None);

        // Missing file: skipped, like the portable path's `if let Ok(..)`.
        let gone = std::env::temp_dir().join("shadowmesh-procfs-does-not-exist");
        assert_eq!(rt.block_on(read_table(&gone)), None);
    }

    /// A descriptor table larger than one `getdents64` buffer.
    ///
    /// `scan_fd_dir` used to treat a short `getdents64` as end of directory.
    /// The kernel stops emitting when the next record will not fit, so a read
    /// into an 8192-byte buffer of 24-byte records returns **8184 bytes with
    /// entries still to come** -- and that is the shape it saw on a live host:
    /// a `java` process with 559 open descriptors, whose socket sat four
    /// entries past the cut, resolved through the portable path and returned
    /// `None` through the ring.
    ///
    /// The defect is in the termination rule rather than in anything specific
    /// to `/proc`, so this reproduces it against a scratch directory holding
    /// more entries than fit in one buffer, with the target on the far side.
    #[test]
    fn fd_scan_walks_past_a_short_getdents_read() {
        /// Comfortably more than the 341 records an 8 KiB buffer holds.
        const ENTRIES: usize = 2_000;

        let dir = std::env::temp_dir().join(format!("shadowmesh-fdscan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        for i in 0..ENTRIES {
            std::os::unix::fs::symlink(format!("socket:[{i}]"), dir.join(i.to_string()))
                .expect("symlink");
        }

        // Pick the target from the **end** of the emission order.
        //
        // `read_dir` is itself `getdents64`, so it yields entries in exactly
        // the order the kernel emits them, and its last entry is in the final
        // batch by construction. Choosing a fixed name instead would be a coin
        // toss: the kernel returns directory entries in hash order, so any
        // particular entry may well fall inside the first batch, where a walk
        // that stopped early would still find it and the test would prove
        // nothing.
        let last = std::fs::read_dir(&dir)
            .expect("read scratch dir")
            .flatten()
            .last()
            .expect("scratch dir is not empty");
        let target = std::fs::read_link(last.path()).expect("readlink target");
        let target = target.to_string_lossy().into_owned();

        let handle = std::fs::File::open(&dir).expect("open scratch dir");
        let raw = {
            use std::os::unix::io::AsRawFd;
            handle.as_raw_fd()
        };
        let found = scan_fd_dir(raw, Path::new("/proc/self"), std::process::id(), &target);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            found.map(|p| p.pid),
            Some(std::process::id()),
            "the last descriptor emitted, which a walk stopping at the first short \
             getdents64 read can never reach, was not found"
        );
    }

    /// A `/proc/net/tcp`-shaped table with `rows` data rows.
    fn table_of_rows(rows: usize) -> String {
        let mut table = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n",
        );
        for i in 0..rows {
            table.push_str(&row(i, port_of(i), "0A"));
        }
        table
    }

    /// The port [`row`] puts on row `index`.
    ///
    /// Row index and port are deliberately different values: a test that
    /// confuses the two silently asks about a socket that was never written.
    fn port_of(index: usize) -> u16 {
        (index + 1) as u16
    }

    /// The inode [`row`] puts at field 9 of row `index`.
    fn inode_of(index: usize) -> u64 {
        10_000 + index as u64
    }

    /// A short read in the middle of the table is not the end of the table.
    ///
    /// This is the shipped defect, and it is the one guard in this file that
    /// actually reproduces it. Every other read-path test here reads a *regular*
    /// file, and `pread` on a regular file returns `min(requested, remaining)` --
    /// so its only short read is the last one, whose bytes are already in the
    /// buffer by the time the loop stops. Measured: restoring the old
    /// `read < requested` break leaves `ring_read_matches_read_to_string`,
    /// `a_table_larger_than_one_read_keeps_every_socket_attributable` and
    /// `ring_read_of_the_live_table_is_always_a_whole_table` all green. That is
    /// why this test drives [`TableDrain`] with a scripted read sequence instead.
    ///
    /// The shape scripted below is the one the production doc comment records
    /// from a real host: a 16 KiB `pread` of `/proc/net/tcp` comes back with
    /// roughly 4 KiB while the table is still going. Getting this wrong cost the
    /// ring backend ~50% of the table, and every socket past the cut was
    /// attributed to "no process owns this port" -- so shaping and routing rules
    /// keyed on process name silently stopped applying.
    #[test]
    fn a_short_read_mid_table_is_not_the_end_of_the_table() {
        // (buffer the read was given, bytes it actually returned)
        let script: [(usize, usize); 4] = [
            (FIRST_READ, FIRST_READ), // filled its buffer: more may follow
            (NEXT_READ, 4 * 1024),    // short, and the table is NOT over
            (NEXT_READ, 4 * 1024),    // short again
            (NEXT_READ, 0),           // a zero read is the only real end
        ];

        let mut drain = TableDrain::new();
        let mut expected: Vec<u8> = Vec::new();
        let mut requested_each_round: Vec<usize> = Vec::new();

        for (step, (requested, returned)) in script.iter().copied().enumerate() {
            // Distinct filler per read, so a dropped tail is visible in the
            // bytes rather than only in the length.
            let chunk = vec![b'a' + step as u8; returned];
            expected.extend_from_slice(&chunk);
            requested_each_round.push(drain.size);

            let complete = drain.feed(&chunk, requested);
            assert_eq!(
                complete,
                returned == 0,
                "read {} returned {returned} of {requested} requested bytes and the drain \
                 reported the table complete -- a short read mid-table ends the loop, which is \
                 exactly the defect that attributed every socket past that point to 'no process \
                 owns this port'",
                step,
            );
        }

        assert_eq!(
            drain.out, expected,
            "the drain did not reassemble the table; rows past the first short read were dropped"
        );
        // A read that filled its buffer is the only thing that may grow the
        // next one: a short read proves nothing about what follows.
        assert_eq!(
            requested_each_round,
            vec![FIRST_READ, NEXT_READ, NEXT_READ, NEXT_READ],
            "buffer sizing stopped tracking what the previous read proved"
        );
    }

    /// A table larger than one read must keep every socket attributable.
    ///
    /// This is the property the live-table test was reaching for, stated in
    /// terms of the consequence: a truncated table loses sockets, and a lost
    /// socket is attributed to "no process owns this port", which silently stops
    /// shaping and routing rules from applying. The fixture spans both buffer
    /// sizes, so rows exist past the 16 KiB cut *and* past the 128 KiB one, and
    /// the last row is checked by name as the canary for "past the end of
    /// everything the loop was willing to read".
    #[test]
    fn a_table_larger_than_one_read_keeps_every_socket_attributable() {
        let rt = ring();

        // (1) No truncation, at full strength: byte equality against a fixture
        // that spans both buffer sizes, so rows exist past the 16 KiB cut *and*
        // past the 128 KiB one.
        const BIG_ROWS: usize = 2_000;
        let big = table_of_rows(BIG_ROWS);
        assert!(
            big.len() > FIRST_READ && big.len() > NEXT_READ,
            "fixture must span both buffer sizes, got {} bytes",
            big.len()
        );
        let big_file = scratch("attribution-big", big.as_bytes());
        let Some(big_table) = rt.block_on(read_table(&big_file.0)) else {
            panic!("ring read of a valid UTF-8 fixture returned nothing");
        };
        assert_eq!(
            big_table,
            big,
            "ring read truncated the table: {} of {} bytes, so every socket past the cut lost \
             its owner",
            big_table.len(),
            big.len()
        );

        // (2) The same property in the terms that matter -- attribution -- with
        // every port in the table actually resolved through the real parser.
        //
        // The sweep is quadratic in the table size (one full parse per port), so
        // it runs on a fixture sized to cross [`FIRST_READ`] and no further.
        // That is the cut that matters: the shipped defect lost rows at a 16 KiB
        // read that came back short.
        const ROWS: usize = 220;
        let text = table_of_rows(ROWS);
        assert!(text.len() > FIRST_READ, "fixture must cross the first read size");
        let file = scratch("attribution", text.as_bytes());
        let Some(table) = rt.block_on(read_table(&file.0)) else {
            panic!("ring read of a valid UTF-8 fixture returned nothing");
        };
        assert_eq!(table, text, "ring read truncated the table");

        let mut unattributed = Vec::new();
        for i in 0..ROWS {
            let port = port_of(i);
            let want = Some(inode_of(i));
            let got = portable::parse_inode_table(&table, port);
            if got != want {
                unattributed.push((port, want, got));
            }
        }
        assert!(
            unattributed.is_empty(),
            "{} of {} sockets resolved to no owner (e.g. {unattributed:?}); each one is a port \
             whose shaping and routing rules silently stopped applying",
            unattributed.len(),
            ROWS
        );

        // Named separately because it is the one most likely to be lost: the
        // final row sits past the read boundary the loop had to notice.
        assert_eq!(
            portable::parse_inode_table(&table, port_of(ROWS - 1)),
            Some(inode_of(ROWS - 1)),
            "the last row of the table lost its inode"
        );
    }

    /// The same contract, checked against the tables the kernel actually has.
    ///
    /// `/proc/net/tcp` belongs to the whole host and **moves while this runs**.
    /// Any two reads therefore see two different snapshots, so comparing them to
    /// each other proves nothing. This version used to assert
    /// `ring.len() >= earlier_snapshot.len()` and to diff per-port inodes
    /// against that earlier snapshot: under a full parallel test run sockets
    /// opened and closed in the gap between the two reads, the second read was
    /// legitimately *shorter*, and the test fired while reporting "the ring read
    /// is truncating the table". That named a defect which was not there, in the
    /// one file whose entire subject is this bug class. A test that invents a
    /// diagnosis is worse than a flaky test.
    ///
    /// So nothing here compares two reads. What is left are the properties that
    /// hold for **every** snapshot of the table, whatever the host is doing, and
    /// which a truncated read still violates:
    ///
    /// * the read completes and is UTF-8,
    /// * row 0 is the header, which the kernel always emits,
    /// * the table ends on a record boundary -- every row the kernel prints ends
    ///   in `\n`, so a read that stopped mid-row is a read that stopped early,
    /// * every row is a whole row.
    ///
    /// The evidence that the ring does not drop rows lives in
    /// `a_table_larger_than_one_read_keeps_every_socket_attributable` and
    /// `a_short_read_mid_table_is_not_the_end_of_the_table`, which can actually
    /// prove it because their input does not move.
    #[test]
    fn ring_read_of_the_live_table_is_always_a_whole_table() {
        let rt = ring();

        for path in portable::PROC_NET_TABLES {
            let Some(table) = rt.block_on(read_table(Path::new(path))) else {
                // An unreadable or non-UTF-8 table is skipped by both backends,
                // so there is nothing to assert here.
                continue;
            };

            let mut lines = table.lines();
            let header = lines.next().unwrap_or_default();
            assert!(
                header.starts_with("  sl"),
                "ring read of {path:?} did not start with the header row, so the read stopped \
                 before the table began: {header:?}"
            );

            assert!(
                table.ends_with('\n'),
                "ring read of {path:?} ended mid-row -- every row the kernel emits ends in a \
                 newline, so this read stopped before the end of the table"
            );

            // A torn row is what a stopped-early read leaves behind: the tail
            // bytes of a row with no terminating newline, or a row whose fields
            // never arrived. `parse_inode_table` needs 10 fields to read an
            // inode and silently skips anything shorter, so a short row here
            // would be a socket that quietly stopped being attributable.
            let mut torn = Vec::new();
            for (n, line) in table.lines().skip(1).enumerate() {
                if line.split_whitespace().count() < 10 {
                    torn.push((n, line));
                }
            }
            assert!(
                torn.is_empty(),
                "ring read of {path:?} contains {} incomplete rows (e.g. {torn:?}); each one is \
                 a socket that lost its owner",
                torn.len()
            );
        }
    }

    /// Stage one -- port to inode -- must agree too.
    ///
    /// The end-to-end sweep in `mod.rs` can only report "these two backends
    /// answered differently about port N", which leaves open whether the split
    /// happened in the table read or in the fd walk. This asks both stages
    /// directly, and on a disagreement prints the rows each side believed, so
    /// the failure says which stage moved rather than just that something did.
    #[test]
    fn table_stage_agrees_with_the_portable_stage() {
        let rt = ring();

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
        assert!(!ports.is_empty(), "the host reports no TCP sockets at all");

        for port in ports {
            let ring_inode = rt.block_on(find_inode(port));
            let portable_inode = portable::find_inode(port);
            if ring_inode == portable_inode {
                continue;
            }
            // The table belongs to the host and moves under the test; only a
            // disagreement that survives a second look is evidence.
            let recheck = portable::find_inode(port);
            let ring_again = rt.block_on(find_inode(port));
            assert!(
                recheck == ring_again,
                "the two table readers disagreed persistently on port {port}: \
                 ring={ring_inode:?} ring_again={ring_again:?} portable={portable_inode:?} \
                 recheck={recheck:?}"
            );
        }
    }

    /// The fd walk must attribute the same pid to the same inode.
    ///
    /// The ring version chunks the pid list 32 at a time and replaces
    /// `read_dir` with a hand-rolled `getdents64` loop, so it is the one place
    /// where the two backends can disagree about an answer rather than about a
    /// byte. Both are asked about a socket this process is holding, and about an
    /// inode nobody holds.
    #[test]
    fn fd_walk_agrees_with_the_portable_walk() {
        let rt = ring();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let port = listener.local_addr().expect("tcp addr").port();
        let inode = portable::find_inode(port).expect("our own listener must be in the table");

        let portable_answer = portable::find_pid_by_inode(inode);
        let ring_answer = rt.block_on(find_pid_by_inode(inode));
        assert_eq!(portable_answer, ring_answer, "the fd walk disagreed on inode {inode}");
        assert_eq!(
            portable_answer.as_ref().map(|p| p.pid),
            Some(std::process::id()),
            "the socket is held by this process; neither walk may say otherwise"
        );

        // An inode no process holds: both must answer None, not "the first pid
        // with an empty fd directory".
        assert_eq!(portable::find_pid_by_inode(u64::MAX), None);
        assert_eq!(rt.block_on(find_pid_by_inode(u64::MAX)), None);

        drop(listener);
    }

    /// The pid list the ring walks must be the portable path's list.
    ///
    /// Same filter, same order: a backend that visited pids in a different
    /// order could attribute the same inode to a different process whenever two
    /// processes shared it.
    ///
    /// The directory check deliberately tolerates a process exiting between
    /// being listed and being stat'd. `/proc` is the whole host and it churns —
    /// an earlier version asserted every listed pid was still a live directory,
    /// which fails intermittently on a busy machine for a reason that has
    /// nothing to do with the code under test. The property worth keeping is
    /// that the entries we *do* stat are directories; a pid that vanished is
    /// correct behaviour, not a defect.
    #[test]
    fn proc_list_matches_the_portable_filter() {
        let procs = list_procs();
        assert!(!procs.is_empty(), "/proc must contain at least this process");
        assert!(
            procs.iter().any(|(pid, _)| *pid == std::process::id()),
            "this process must appear in its own /proc listing"
        );

        let mut vanished = 0;
        for (pid, dir) in &procs {
            match dir.is_dir() {
                true => {}
                // ENOENT means the process exited mid-scan. Anything else --
                // EACCES on another user's, say -- is a real filter problem.
                false
                    if std::fs::metadata(dir)
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                {
                    vanished += 1;
                }
                false => panic!("listed /proc entry {pid} ({dir:?}) is not a directory"),
            }
        }
        // Sanity on the tolerance itself: a total wipe-out would mean the filter
        // is broken rather than racing.
        assert!(
            vanished * 4 < procs.len(),
            "{vanished} of {} listed pids vanished -- that is not a normal exit race",
            procs.len(),
        );
    }

    // -------------------------------------------------------------------------
    // The bound, and what happens at it
    //
    // A bounded queue with a silent refusal is a correctness bug wearing a
    // performance costume: a refused lookup and a lookup that genuinely found
    // no process return the same thing to the caller. So the two properties that
    // make the bound safe are pinned here rather than asserted in a comment --
    // the bound holds, and a refusal still yields the right answer.
    // -------------------------------------------------------------------------

    /// The bound is enforced, and refusing costs the *newcomer* the slot.
    ///
    /// Built by hand rather than through `spawn_worker` so the full/empty
    /// boundary is exact: a channel of one, with its receiver held and never
    /// drained so the channel stays *connected*. That distinction is the whole
    /// reason this test exists -- a held-but-idle receiver isolates `Full` from
    /// `Disconnected`, and the two would otherwise be indistinguishable in a
    /// test that leaked the receiver.
    #[test]
    fn a_full_queue_refuses_the_newcomer_rather_than_growing() {
        let (tx, rx) = mpsc::sync_channel::<Job>(1);
        let worker = Worker::new(tx);

        let (reply_a, _rx_a) = oneshot::channel();
        assert!(worker.submit(1, reply_a), "the first job must fit in an empty queue");

        // Two more than the bound, so "one refusal" is a specific claim rather
        // than a coincidence of scheduling.
        let (reply_b, _rx_b) = oneshot::channel();
        assert!(!worker.submit(2, reply_b), "a queue at its bound must refuse the newcomer");
        assert_eq!(worker.refused(), 1, "the refusal must be counted, not swallowed");

        let (reply_c, _rx_c) = oneshot::channel();
        assert!(!worker.submit(3, reply_c), "the queue must stay bounded, not just refuse once");
        assert_eq!(worker.refused(), 2);

        // Dropping the receiver unblocks the destructor path; nothing below
        // depends on it, and a test that leaves a channel half-open is a test
        // that teaches the next reader to ignore it.
        drop(rx);
    }

    /// The mechanism the whole policy rests on, asserted directly.
    ///
    /// `find_process_info` refuses by dropping the `oneshot::Sender`, and its
    /// `Err(_)` arm answers from `portable.rs`. This test is that claim, with
    /// nothing else in the way: a job that never reaches a worker must produce
    /// a *closed* reply channel, so the awaiting caller is handed to the
    /// fallback rather than left hanging on a reply that will never come.
    ///
    /// If this ever fails, the drop-newest policy has stopped being lossless
    /// and the refusal path in `find_process_info` has become an attribution
    /// gap. Do not fix it by making the caller tolerate a dropped lookup --
    /// that is the defect.
    #[tokio::test]
    async fn a_refused_lookup_is_answered_from_portable_not_dropped() {
        let (tx, rx) = mpsc::sync_channel::<Job>(1);
        let worker = Worker::new(tx);

        // Occupy the single slot with a job nobody will service.
        let (occupied, _rx_occupied) = oneshot::channel();
        assert!(worker.submit(1, occupied));

        let (reply, rx_reply) = oneshot::channel();
        assert!(!worker.submit(2, reply), "the queue was full; this one is refused");

        // The refused job took its sender with it, so this is `Err` -- which is
        // precisely the arm that routes the caller to `portable.rs`.
        assert!(
            rx_reply.await.is_err(),
            "a refused lookup must close its reply channel so the caller falls back; \
             if this resolved, the fallback would never run and a refusal would be a gap"
        );
        drop(rx);
    }

    /// The end-to-end version: a burst larger than the bound loses no attribution.
    ///
    /// Pushes `RING_QUEUE_DEPTH + RING_QUEUE_DEPTH/4` concurrent lookups of a
    /// port **this process holds** -- a hit, so every one of them has a
    /// ground-truth answer, rather than a miss where `None` is right either way
    /// and a broken path would look identical to a working one.
    ///
    /// Whether the bound is actually reached depends on how fast the host's
    /// worker drains, so the assertion is the invariant and not the saturation:
    /// every lookup must name this process, whether it was served by the ring
    /// before the queue filled or refused and answered by `portable.rs`. The
    /// observed refusal count is printed rather than asserted, because
    /// asserting it would make the test fail on a host fast enough not to
    /// saturate -- which would be the test failing for the wrong reason.
    ///
    /// `nextest` runs one test per process, which is what makes using the
    /// process-wide worker here safe: nothing else is running that could be
    /// disturbed by the flood.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_burst_past_the_bound_still_attributes_every_lookup() {
        let port = hit_port();

        let before = refused_lookups();
        let burst = RING_QUEUE_DEPTH + RING_QUEUE_DEPTH / 4;

        let answers = tokio::time::timeout(Duration::from_secs(30), async {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..burst {
                tasks.spawn(async move { find_process_info(port).await });
            }
            let mut out = Vec::with_capacity(burst);
            while let Some(joined) = tasks.join_next().await {
                out.push(joined.expect("lookup task must not panic"));
            }
            out
        })
        .await
        .expect("the burst did not finish in 30s -- a refused lookup was left unanswered");

        assert_eq!(answers.len(), burst, "a lookup went missing from the burst");
        for answer in answers {
            let info = answer.unwrap_or_else(|| {
                panic!("port {port} is held by this process but resolved to nothing")
            });
            assert_eq!(
                info.pid,
                std::process::id(),
                "a lookup under saturation attributed the port to the wrong process"
            );
        }

        eprintln!(
            "probe: burst of {burst} past a bound of {RING_QUEUE_DEPTH} -> {} refused, \
             all attributed",
            refused_lookups() - before
        );
    }

    // -------------------------------------------------------------------------
    // Throughput and backlog probes
    //
    // These two are `#[ignore]`d and are the instrument behind the "what is the
    // real ceiling" question. They assert nothing about speed: every number they
    // print is a property of the host it ran on (a lookup is proportional to the
    // process count, the descriptor count and the table size), so a wall-clock
    // assertion would fail on any machine but this one and train people to
    // ignore the suite. What they do fix is the *shape* of the result: that the
    // ring's aggregate rate is set by one thread, and that the queue in front of
    // that thread has a ceiling.
    //
    // Run them on purpose:
    //
    // ```text
    // cargo nextest run -p shadowmesh-core --run-ignored all -- probe_
    // ```
    // -------------------------------------------------------------------------

    /// Processes and descriptors this host has, because the rates below are
    /// proportional to both and mean nothing without them.
    fn host_workload_size() -> (usize, usize) {
        let mut pids = 0usize;
        let mut fds = 0usize;
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_none_or(|n| n.parse::<u32>().is_err())
                {
                    continue;
                }
                pids += 1;
                if let Ok(dir) = std::fs::read_dir(path.join("fd")) {
                    fds += dir.flatten().count();
                }
            }
        }
        (pids, fds)
    }

    /// A port this process holds, so a lookup runs the whole `/proc` walk.
    fn hit_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let port = listener.local_addr().expect("tcp addr").port();
        // Leaked so the row survives the measurement: a dropped listener makes
        // every "hit" sample silently become a miss.
        std::mem::forget(listener);
        port
    }

    /// A port nothing is bound to, so the lookup stops after the table reads.
    fn miss_port() -> u16 {
        9
    }

    /// Resident set size of this process, in bytes.
    fn rss_bytes() -> usize {
        let statm = std::fs::read_to_string("/proc/self/statm").expect("read /proc/self/statm");
        let pages: usize = statm
            .split_whitespace()
            .nth(1)
            .expect("statm resident field")
            .parse()
            .expect("statm is numbers");
        // SAFETY: `sysconf(_SC_PAGESIZE)` takes no arguments and has no
        // preconditions beyond a live libc.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page > 0, "sysconf returned a non-positive page size");
        pages * page as usize
    }

    /// Lookups per second through the shared worker, at a given concurrency.
    ///
    /// `per_task` lookups per task, `concurrency` tasks: the number of callers
    /// that can have a lookup outstanding at once. This is the shape the TUN
    /// ingress path produces, where every locally-sourced packet spawns its own
    /// task with its own fresh `ConnectionMetadata`.
    fn ring_rate(
        rt: &tokio::runtime::Runtime,
        port: u16,
        concurrency: usize,
        per_task: usize,
    ) -> f64 {
        let started = std::time::Instant::now();
        rt.block_on(async {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..concurrency {
                tasks.spawn(async move {
                    for _ in 0..per_task {
                        std::hint::black_box(find_process_info(port).await);
                    }
                });
            }
            while tasks.join_next().await.is_some() {}
        });
        let elapsed = started.elapsed().as_secs_f64();
        (concurrency * per_task) as f64 / elapsed
    }

    /// The same workload run through the portable path, which is not funnelled
    /// through anything and so scales with the machine.
    fn portable_rate(
        rt: &tokio::runtime::Runtime,
        port: u16,
        concurrency: usize,
        per_task: usize,
    ) -> f64 {
        let started = std::time::Instant::now();
        rt.block_on(async {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..concurrency {
                tasks.spawn(async move {
                    for _ in 0..per_task {
                        // Blocking on purpose: this is what the portable path
                        // does on a runtime thread, and blocking is exactly the
                        // thing the ring worker avoids by owning a thread.
                        std::hint::black_box(portable::find_process_info(port));
                    }
                });
            }
            while tasks.join_next().await.is_some() {}
        });
        let elapsed = started.elapsed().as_secs_f64();
        (concurrency * per_task) as f64 / elapsed
    }

    /// The throughput ceiling, measured rather than assumed.
    ///
    /// The claim under test is that the ring is serialised: `worker_main` takes
    /// one job, `block_on`s the whole lookup, and only then calls `recv` again,
    /// so no amount of caller concurrency can make the rate exceed one lookup
    /// per service time. The portable column is the control -- same work, same
    /// parser, no funnel, so it should scale with the core count. If the ring
    /// column is flat where the portable column is not, the ceiling is the
    /// worker and not the `/proc` walk.
    ///
    /// This is the probe RFC-039 §5.4's reversal condition is measured with: if
    /// the funnel is removed -- per-worker rings, or more than one of them --
    /// and the ring column overtakes the portable one at concurrency 64, the
    /// default goes back to `uring`. Run it before arguing from the number
    /// rather than after.
    ///
    /// It times the ring directly rather than through the process default,
    /// because the default is `portable` now (RFC-039 §5.4) and a probe that
    /// measured the default would report the portable figure in both columns.
    #[test]
    #[ignore = "host-specific measurement; run it deliberately"]
    fn probe_throughput_ceiling() {
        let (pids, fds) = host_workload_size();
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
        eprintln!("probe: {pids} processes / {fds} open descriptors, {cores} cores available");

        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
        let per_task = 25usize;

        for (label, port) in
            [("hit (full /proc walk)", hit_port()), ("miss (tables only)", miss_port())]
        {
            eprintln!("probe: port {port} -- {label}");
            for concurrency in [1usize, 8, 64] {
                let ring = ring_rate(&rt, port, concurrency, per_task);
                let portable = portable_rate(&rt, port, concurrency, per_task);
                eprintln!(
                    "probe:   concurrency {concurrency:>3}: ring {ring:>10.1}/s ({:>7.2} ms) | \
                     portable {portable:>10.1}/s ({:>7.2} ms)",
                    1000.0 / ring,
                    1000.0 / portable,
                );
            }
        }
    }

    /// How much memory a backlog of un-served lookups costs.
    ///
    /// **This probe's assertion used to be that RSS never stops growing** --
    /// it asserted the queue was unbounded, which was true when the channel
    /// was `mpsc::channel` and is false by design now. F22 measured 80,000
    /// queued lookups at +13.6 MiB and called it "a slow OOM"; `RING_QUEUE_DEPTH`
    /// is the response, so the probe now asserts the opposite and for the right
    /// reason: **RSS plateaus**, and the plateau is the bound.
    ///
    /// The plateau is the property that matters and it was previously only
    /// *predicted* in a comment ("a plateau -- which is what a bounded queue
    /// would show -- would be visible rather than inferred"). It is now
    /// measured. A queue that grew past the bound would still be a defect even
    /// with `sync_channel` in place, because a bound nobody watches is a bound
    /// somebody eventually changes without noticing why.
    ///
    /// The receivers are dropped, not awaited: draining tens of thousands of
    /// jobs at the rate measured above would take minutes. The worker keeps
    /// chewing for the rest of the test process's life and the process exits
    /// when the test returns.
    #[test]
    #[ignore = "host-specific measurement; run it deliberately"]
    fn probe_queue_backlog_memory() {
        assert!(shared_worker().is_some(), "no ring on this host; the probe would measure nothing");

        let step = 20_000usize;
        let steps = 4usize;

        eprintln!(
            "probe: size_of::<Job>() = {} bytes (u16 + oneshot::Sender); queue bound {} entries",
            std::mem::size_of::<Job>(),
            RING_QUEUE_DEPTH,
        );

        let mut previous = rss_bytes();
        let baseline = previous;
        let mut pending: Vec<oneshot::Receiver<Option<ProcessInfo>>> =
            Vec::with_capacity(step * steps);

        for round in 1..=steps {
            let worker = shared_worker().expect("ring checked above");
            let mut refused_here = 0u64;
            for _ in 0..step {
                let (reply, rx) = oneshot::channel();
                if worker.submit(miss_port(), reply) {
                    pending.push(rx);
                } else {
                    refused_here += 1;
                }
            }
            let now = rss_bytes();
            let queued = step * round;
            eprintln!(
                "probe: {queued:>6} offered -> +{:>9} KiB since baseline ({:>6} B/offered) \
                 | {refused_here:>6} refused at the bound, {} refused in total",
                (now - baseline) / 1024,
                (now - baseline) / queued,
                worker.refused(),
            );
            previous = now;
        }

        // The property: after the first round the queue cannot hold more than
        // `RING_QUEUE_DEPTH`, so everything past that is refused. The first
        // round's growth is the real queue filling; every round after it is
        // caller-side bookkeeping (the `pending` vector) rather than queue
        // memory, and must be far smaller.
        let first = previous - baseline;
        assert!(
            refused_lookups() > 0,
            "no lookup was ever refused across {steps} rounds of {step} offers -- the queue \
             grew past {RING_QUEUE_DEPTH} entries, which is the defect the bound exists to stop"
        );
        // Each additional 20,000 offers costs the pending vector 24 bytes a
        // receiver, nowhere near the ~174 B/lookup of a queued job. Compare the
        // last two rounds: if the queue were still growing at ~174 B a lookup,
        // the later rounds would dominate.
        assert!(
            first < (step * steps) * 2,
            "RSS grew {first} bytes over {step} rounds; at ~174 B per pending lookup a \
             still-unbounded queue would be at least {} bytes. The bound is not holding.",
            step * steps * 174,
        );

        // Dropping the receivers is the point: a caller that gives up frees its
        // own slot, but only after the job has already been queued and only if
        // it manages to -- nothing in `find_process_info` drops the sender
        // early on a cancelled future.
        drop(pending);
    }

    #[test]
    fn reads_dent_records_in_kernel_layout() {
        // One linux_dirent64 record: d_ino=1, d_off=2, d_reclen=24, d_type=8
        // (DT_REG), d_name="12\0", padded to 24 bytes.
        let mut rec = vec![0u8; 24];
        rec[0] = 1;
        rec[8] = 2;
        rec[16..18].copy_from_slice(&24u16.to_le_bytes());
        rec[18] = 8;
        rec[19..22].copy_from_slice(b"12\0");

        assert_eq!(read_u16(&rec, 16), Some(24));
        // 23 + 2 runs one byte past the record; the read must be refused
        // rather than wrapped or panicking.
        assert_eq!(read_u16(&rec, 23), None);
        assert_eq!(read_u16(&rec, 24), None);

        let name = &rec[19..24];
        let name = &name[..name.iter().position(|&b| b == 0).unwrap()];
        assert_eq!(name, b"12");
        assert!(name.iter().all(u8::is_ascii_digit));
    }

    #[test]
    fn rejects_truncated_or_oversized_records() {
        // reclen = 0 would make the offset loop spin forever.
        let zero = vec![0u8; 24];
        assert_eq!(read_u16(&zero, 16), Some(0));

        // reclen = 9000 exceeds the buffer the kernel said it filled.
        let mut huge = vec![0u8; 24];
        huge[16..18].copy_from_slice(&9000u16.to_le_bytes());
        assert_eq!(read_u16(&huge, 16), Some(9000));
    }
}
