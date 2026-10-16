//! Short-TTL memo for `port -> owning process`.
//!
//! # Why this exists
//!
//! `/proc/net/tcp` is consulted on the per-packet UDP path. On a busy host it
//! changes a handful of times a second, while packets arrive by the thousand,
//! so the overwhelming majority of reads re-derive a table nobody has changed.
//! The benchmark in `benches/proc_lookup_bench.rs` measures that: a cache
//! beats every syscall-level optimisation of the same read, io_uring included.
//!
//! # Why it is off by default
//!
//! This lookup decides which process a piece of traffic is attributed to, and
//! that feeds traffic shaping and routing rules. A port is not a stable key:
//! when a socket closes, the kernel is free to hand the same port to a
//! different process immediately. A stale hit therefore reports a *wrong
//! process*, not a stale-but-equivalent answer. Caching that is a
//! correctness/security trade the operator has to opt into, so the default TTL
//! is `0` — disabled — and the shipped behaviour is byte-for-byte the
//! uncached lookup.
//!
//! Set `SHADOWMESH_PROC_CACHE_TTL_MS` to a positive value to enable it.
//! Misses (`None`) expire on a much shorter clock than hits: a socket that has
//! just been created must not stay invisible because of a lookup that missed
//! before it was bound.

use super::ProcessInfo;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Environment variable that turns the memo on.
pub(crate) const TTL_ENV: &str = "SHADOWMESH_PROC_CACHE_TTL_MS";

/// Hard ceiling on retained entries. Ports are 16-bit but the *observed* set is
/// bounded by what the host actually has open; the cap exists so a hostile or
/// simply very busy client cannot turn a latency optimisation into a leak.
const MAX_ENTRIES: usize = 4096;

/// A miss is re-checked after at most this long regardless of the hit TTL.
const MAX_NEGATIVE_TTL: Duration = Duration::from_millis(250);

type Entry = (Instant, Option<ProcessInfo>);

static TTL: OnceLock<Option<Duration>> = OnceLock::new();
static ENTRIES: OnceLock<RwLock<HashMap<u16, Entry>>> = OnceLock::new();

/// Test-only override for the memoised TTL.
///
/// The outer `Option` means "is there an override"; the inner `Option` mirrors
/// [`ttl`]'s own return type, so a test can force the *disabled* state as
/// easily as an enabled one.
///
/// This exists because [`TTL`] is a `OnceLock` and **cannot be reset**. The
/// first caller in a process latches the value for good, so a test that called
/// `std::env::set_var` and then read `ttl()` passed only if it won a race to be
/// first — which is why three of the tests below failed in a full parallel run
/// and passed when run alone. Consulting this override *before* the memo removes
/// the race, and it is entirely `#[cfg(test)]`, so nothing is added to the
/// shipped lookup path.
#[cfg(test)]
static TTL_OVERRIDE: std::sync::Mutex<Option<Option<Duration>>> = std::sync::Mutex::new(None);

/// Pure parse of the TTL environment value. `None` — missing, unparseable, or
/// zero — disables the cache.
///
/// Split out from [`ttl`] so the parsing rules are unit-testable without going
/// through a process-global. An unparseable value disables the cache rather
/// than guessing: a typo'd TTL that silently became "1 hour" would be a much
/// worse failure than a typo'd TTL that does nothing.
fn parse_ttl(raw: Option<String>) -> Option<Duration> {
    let ms: u64 = raw?.trim().parse().ok()?;
    (ms > 0).then(|| Duration::from_millis(ms))
}

fn ttl() -> Option<Duration> {
    #[cfg(test)]
    {
        let forced = *TTL_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(forced) = forced {
            return forced;
        }
    }
    *TTL.get_or_init(|| parse_ttl(std::env::var(TTL_ENV).ok()))
}

fn entries() -> &'static RwLock<HashMap<u16, Entry>> {
    ENTRIES.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Effective lifetime for a miss: `ttl / 8`, capped at [`MAX_NEGATIVE_TTL`].
fn miss_ttl() -> Option<Duration> {
    let base = ttl()?;
    let eighth = base / 8;
    Some(eighth.min(MAX_NEGATIVE_TTL))
}

/// Look up a port. `None` from the map means "not memoised, go to the syscall".
pub(crate) fn get(port: u16) -> Option<Option<ProcessInfo>> {
    let ttl = ttl()?;
    let now = Instant::now();

    let map = entries().read();
    let (stored_at, info) = map.get(&port)?;
    let lifetime = if info.is_some() { ttl } else { miss_ttl()? };

    if now.duration_since(*stored_at) < lifetime {
        Some(info.clone())
    } else {
        None
    }
}

/// Memoise a lookup result. A no-op while the cache is disabled.
pub(crate) fn put(port: u16, info: Option<&ProcessInfo>) {
    if ttl().is_none() {
        return;
    }
    let mut map = entries().write();
    if map.len() >= MAX_ENTRIES && !map.contains_key(&port) {
        // Expired entries first; only give up if everything is still live.
        let now = Instant::now();
        map.retain(|_, (at, _)| now.duration_since(*at) < ttl().unwrap_or_default());
        if map.len() >= MAX_ENTRIES {
            return;
        }
    }
    map.insert(port, (Instant::now(), info.cloned()));
}

/// Drop every memoised entry. Test-only seam for the TTL tests below.
#[cfg(test)]
pub(crate) fn reset() {
    if let Some(map) = ENTRIES.get() {
        map.write().clear();
    }
}

/// Clears the [`TTL_OVERRIDE`] when dropped.
///
/// Callers must **bind** the returned value; dropping it immediately would
/// clear the override before the test body ran.
#[cfg(test)]
pub(crate) struct TtlOverride;

#[cfg(test)]
impl Drop for TtlOverride {
    fn drop(&mut self) {
        *TTL_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// Force [`ttl`] to `value` until the returned guard drops.
///
/// This replaces the old `std::env::set_var` approach, which could not work:
/// `TTL` is a `OnceLock`, so whichever test read `ttl()` first latched the
/// answer for the whole process and every later `set_var` was a no-op. Three of
/// the tests below failed in a full parallel run and passed alone for exactly
/// that reason.
///
/// It lives at module scope rather than inside `mod tests` so that a test in
/// [`super`] can pin the memo's state for its own body. `force_ttl(None)` pins
/// the **shipped** state -- disabled -- independently of whatever
/// `SHADOWMESH_PROC_CACHE_TTL_MS` happens to be in the operator's environment,
/// which is what a test asserting a property of the default configuration needs
/// and what a developer running the suite with that variable exported does not.
#[cfg(test)]
pub(crate) fn force_ttl(value: Option<Duration>) -> TtlOverride {
    *TTL_OVERRIDE.lock().unwrap_or_else(|e| e.into_inner()) = Some(value);
    TtlOverride
}

/// The memo's current effective TTL, for a test that wants to assert which
/// configuration it is actually running under rather than assume it.
#[cfg(test)]
pub(crate) fn ttl_for_test() -> Option<Duration> {
    ttl()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The memo is process-global by design, so its tests must not run
    /// concurrently with each other or the assertions below would be racing on
    /// entries another test just cleared.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Serialise against the other cache tests, force an enabled TTL, and clear
    /// any entry a sibling test left behind.
    ///
    /// Returns `(lock_guard, override_guard)`; bind both.
    fn install_ttl() -> (std::sync::MutexGuard<'static, ()>, TtlOverride) {
        let lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        (lock, force_ttl(Some(Duration::from_millis(200))))
    }

    fn info(pid: u32) -> ProcessInfo {
        ProcessInfo { pid, name: format!("p{pid}") }
    }

    #[test]
    fn hit_and_miss_round_trip() {
        let (_lock, _ttl) = install_ttl();
        assert!(ttl().is_some(), "cache must be enabled for this test");

        assert_eq!(get(40001), None, "cold port must not be memoised");
        put(40001, Some(&info(7)));
        assert_eq!(get(40001), Some(Some(info(7))));

        put(40002, None);
        assert_eq!(get(40002), Some(None), "a miss must be memoised too");
    }

    #[test]
    fn negative_ttl_shorter_than_positive() {
        let (_lock, _ttl) = install_ttl();
        // The invariant that matters is that a miss never outlives a hit,
        // otherwise a newly bound socket stays invisible for longer than a
        // stale attribution would be tolerated.
        assert!(miss_ttl().unwrap() < ttl().unwrap());
        assert!(miss_ttl().unwrap() <= MAX_NEGATIVE_TTL);
    }

    #[test]
    fn expired_entries_are_not_returned() {
        let (_lock, _ttl) = install_ttl();
        put(40003, Some(&info(9)));
        assert!(get(40003).is_some());

        std::thread::sleep(ttl().unwrap() + Duration::from_millis(150));
        assert_eq!(get(40003), None, "stale entry must not be served");
    }

    #[test]
    fn entry_cap_is_enforced() {
        let (_lock, _ttl) = install_ttl();
        reset();
        let base: u16 = 41000;
        for offset in 0..(MAX_ENTRIES + 50) {
            put(base.saturating_add(offset as u16), Some(&info(1)));
        }
        let len = entries().read().len();
        assert!(len <= MAX_ENTRIES, "cache grew past its cap: {len}");
        reset();
    }

    // --- parse rules ---------------------------------------------------------
    //
    // These exercise `parse_ttl` directly, so they need neither the env var nor
    // the memo and cannot be affected by test order at all. The memoised read is
    // covered by the behavioural tests above.

    #[test]
    fn a_positive_ttl_enables_the_cache() {
        assert_eq!(parse_ttl(Some("250".into())), Some(Duration::from_millis(250)));
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(parse_ttl(Some("  250\n".into())), Some(Duration::from_millis(250)));
    }

    #[test]
    fn an_unset_ttl_disables_the_cache() {
        assert_eq!(parse_ttl(None), None, "the shipped default must stay disabled");
    }

    #[test]
    fn a_zero_ttl_disables_the_cache() {
        assert_eq!(parse_ttl(Some("0".into())), None, "zero means off, not instant expiry");
    }

    #[test]
    fn a_typo_disables_the_cache_rather_than_guessing() {
        // The documented rule: a value we cannot parse must not become a
        // plausible-looking duration. Silently reading "1h" here would be worse
        // than doing nothing.
        assert_eq!(parse_ttl(Some("forever".into())), None);
        assert_eq!(parse_ttl(Some("-5".into())), None);
        assert_eq!(parse_ttl(Some("".into())), None);
    }

    #[test]
    fn the_forced_override_shadows_the_memo_and_clears() {
        // `TEST_LOCK` is mandatory here for the same reason it is mandatory in
        // the behavioural tests: the override is process-global. Without it this
        // test's guard can drop while a sibling sits between `put` and `get`,
        // and that sibling's `let ttl = ttl()?` then yields `None` — observed as
        // `hit_and_miss_round_trip` failing with `left: None`.
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();

        let forced = force_ttl(Some(Duration::from_millis(42)));
        assert_eq!(ttl(), Some(Duration::from_millis(42)), "override must win over the memo");
        drop(forced);
        // After the guard, `ttl()` is back to whatever the process latched — the
        // point is only that it is no longer the forced value.
        assert_ne!(ttl(), Some(Duration::from_millis(42)), "override must not outlive its guard");
        reset();
    }
}
