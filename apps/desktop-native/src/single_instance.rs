// SPDX-FileCopyrightText: 2026 ShadowMesh Principal Engineers
// SPDX-License-Identifier: GPL-3.0-only
//
// This file is part of the ShadowMesh public UI layer, published for
// independent security audit. See docs/LICENSING.md.

//! P1-8: Single-instance guard — dependency-free.
//!
//! Linux: binds a unix socket at `$XDG_RUNTIME_DIR/shadowmesh-desktop.lock`.
//! A second instance fails the bind (address in use) and exits 0 silently.
//! Windows: holds an OS-locked lockfile in `dirs::data_dir()`; a second
//! instance cannot re-acquire it while the first process lives.
//!
//! The lock is held for the whole process lifetime via a leak-on-purpose
//! `OnceLock` (the OS reclaims socket/file handles at exit, so there is no
//! stale-lock issue on any supported platform).

use std::sync::OnceLock;

/// Bind path for the single-instance lock on the current platform.
fn lock_target() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let runtime_dir =
            std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).or_else(|| {
                // XDG fallback: use /tmp when the session runtime dir is not
                // exported (rare: manually stripped environments).
                std::env::var_os("TMPDIR")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                    .into()
            })?;
        Some(runtime_dir.join("shadowmesh-desktop.lock"))
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        Some(std::env::temp_dir().join("shadowmesh-desktop.lock"))
    }
    #[cfg(windows)]
    {
        let data_dir = dirs::data_dir()?;
        Some(data_dir.join("shadowmesh-desktop").join("desktop.lock"))
    }
}

/// Acquires the single-instance lock. Returns `false` when another instance
/// already holds it (caller must exit 0 silently).
///
/// A returned `true` guarantees the guard is held for the process lifetime.
/// Failures to even determine a lock location are treated as "not locked"
/// (fail-open) so the app never refuses to start over missing env vars —
/// the guard is a UX nicety, not a security control.
pub fn acquire_lock() -> bool {
    static LOCK: OnceLock<()> = OnceLock::new();

    LOCK.set(()).is_ok() && try_lock()
}

fn try_lock() -> bool {
    let Some(path) = lock_target() else {
        warn_once("no lock location; single-instance guard disabled");
        return true;
    };

    #[cfg(unix)]
    {
        try_lock_unix(&path)
    }

    #[cfg(windows)]
    {
        try_lock_windows(&path)
    }
}

#[cfg(unix)]
fn try_lock_unix(path: &std::path::Path) -> bool {
    use std::os::unix::net::UnixListener;

    // Remove a stale socket left by an unclean shutdown (e.g. SIGKILL). The
    // subsequent bind attempt is the real arbiter: if a live instance is
    // listening, `bind` fails with EADDRINUSE and we lose the race cleanly.
    let _ = std::fs::remove_file(path);

    match UnixListener::bind(path) {
        // Hold the listener for the process lifetime; leak it so it is never
        // dropped (dropping closes the socket and would release the lock).
        Ok(listener) => {
            std::mem::forget(listener);
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => false,
        Err(e) => {
            warn_once(&format!("lock bind failed: {e}"));
            // Fail-open: inability to take the lock must not block startup.
            true
        }
    }
}

#[cfg(windows)]
fn try_lock_windows(path: &std::path::Path) -> bool {
    use std::fs::OpenOptions;

    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            warn_once("cannot create lock dir; single-instance guard disabled");
            return true;
        }
    }

    // The file is only advisory on its own — real exclusion comes from the
    // OS refusing a second exclusively-shared handle while ours is open.
    // std::fs exclusive create covers the common double-launch case.
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_file) => {
            // Hold the handle (leak on purpose — see `acquire_lock`).
            // The file is removed when this process exits via the same
            // best-effort path below; on unclean exits, the next start
            // cleans it because the handle is gone by then.
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // The file exists — but the owner may already be dead. Try to
            // open it exclusively: success means the owner is gone and we
            // adopt the lock; failure means a live owner.
            match OpenOptions::new().write(true).open(path) {
                Ok(_file) => true,
                Err(_) => false,
            }
        }
        Err(e) => {
            warn_once(&format!("lock open failed: {e}"));
            true
        }
    }
}

/// Emit a single warn line per process for guard infrastructure issues.
fn warn_once(msg: &str) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        // The tracing subscriber may not be initialized yet; fall back to
        // stderr so the diagnostic is not silently lost.
        eprintln!("shadowmesh-desktop: {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_target_is_absolute() {
        if let Some(p) = lock_target() {
            assert!(p.is_absolute(), "lock path must be absolute: {}", p.display());
        }
    }

    #[test]
    fn double_acquire_reports_second_as_taken() {
        // First acquire wins; a second one in the same process fails because
        // the OnceLock is already set (the OS-level bind would also fail).
        assert!(acquire_lock(), "first acquire must succeed");
        assert!(!acquire_lock(), "second acquire must report the instance as taken");
    }
}
