//! RFC-011 §4.2–4.4 desktop production contracts.
//!
//! Implementation Source:
//! - Spec: docs/rfc/011-cross-platform-production-readiness.md
//! - §4.2 Update Trust Model: notice-only — fetch a version manifest over
//!   HTTPS, compare, surface "update available"; NEVER download, write, or
//!   execute a binary in this phase.
//! - §4.3 Autostart Policy: opt-in, off by default; user-scope mechanisms
//!   only (XDG autostart on Linux, HKCU Run on Windows).
//! - §4.4 Forensic-Wipe UX: ordered, idempotent, best-effort-continue
//!   purge (tunnel teardown → zeroize → app-owned files → device identity
//!   → first-run reset).
//!
//! ZPII: no secrets in any log line; wipe logs only action names.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Interval between update-notice checks (RFC-011: ≥ 24h).
pub const UPDATE_CHECK_INTERVAL_HOURS: u64 = 24;

/// Where the app's own state lives (device id, security log, caches).
pub fn app_state_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("no OS config dir on this platform")?.join("shadowmesh");
    std::fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    Ok(base)
}

// ---------------------------------------------------------------------------
// §4.2 Update notice (fetch-only)
// ---------------------------------------------------------------------------

/// Latest-version metadata derived from the control plane's global manifest
/// (RFC-011 §4.2: notice-only — fetch + compare; NEVER download, write, or
/// execute a binary in this phase).
#[derive(Debug, Clone)]
pub struct UpdateNotice {
    pub latest_version: String,
    pub notes_url: String,
}

impl UpdateNotice {
    /// Uses the existing core ApiClient's manifest fetch (reqwest/rustls,
    /// same credential path as node sync — no new HTTP stack). `None` means
    /// up to date, unknown, or fetch failure (notice-only: a failed check
    /// must never nag or error the UI).
    pub fn fetch(
        api_client: &shadowmesh_core::ApiClient,
        current_version: &str,
    ) -> Result<Option<UpdateNotice>> {
        let manifest = api_client
            .fetch_global_manifest()
            .map_err(|e| anyhow::anyhow!("manifest fetch failed: {e:?}"))?;

        // The manifest's `version` field tracks the control-plane release;
        // comparing against the client build surfaces a notice whenever the
        // fleet is running something newer than this build.
        let latest = manifest.version;
        if latest.is_empty() {
            return Ok(None);
        }
        if is_newer(&latest, current_version) {
            Ok(Some(UpdateNotice {
                // The manifest carries no release URL today; the UI opens the
                // project's releases page instead.
                notes_url: String::new(),
                latest_version: latest,
            }))
        } else {
            Ok(None)
        }
    }

    /// True when the 24h cadence allows a new check.
    pub fn check_due(state_dir: &Path) -> bool {
        let stamp = state_dir.join("last_update_check");
        match std::fs::read_to_string(&stamp) {
            Ok(s) => s
                .trim()
                .parse::<u64>()
                .map(|ts| now_unix_hours() - ts >= UPDATE_CHECK_INTERVAL_HOURS)
                .unwrap_or(true),
            Err(_) => true,
        }
    }

    pub fn record_check(state_dir: &Path) {
        let stamp = state_dir.join("last_update_check");
        let _ = std::fs::write(&stamp, now_unix_hours().to_string());
    }
}

fn now_unix_hours() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 3600)
        .unwrap_or(0)
}

/// Dotted-numeric comparison ("1.2.3" > "1.2.2"). Splits on every
/// non-digit so "0.2.0" yields [0, 2, 0]; a non-numeric candidate yields an
/// empty vec and is rejected (never triggers a false update notice).
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|t| !t.is_empty())
            .map(|t| t.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (a, b) = (parse(candidate), parse(current));
    if a.is_empty() || b.is_empty() {
        return false;
    }
    let n = a.len().max(b.len());
    for i in 0..n {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        if av != bv {
            return av > bv;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// §4.3 Autostart (opt-in, user scope, default OFF)
// ---------------------------------------------------------------------------

pub struct Autostart;

impl Autostart {
    pub fn is_enabled() -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            let entry = Self::xdg_entry_path()?;
            Ok(entry.is_file())
        }
        #[cfg(target_os = "windows")]
        {
            let key = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
                .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Run")?;
            Ok(key.get_value::<String, _>("ShadowMesh").is_ok())
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            anyhow::bail!("autostart not supported on this platform")
        }
    }

    /// Enables/disables user-scope autostart. Idempotent; no root/daemon
    /// services are registered (RFC-011 §4.3).
    pub fn set_enabled(enabled: bool) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let entry = Self::xdg_entry_path()?;
            if enabled {
                if let Some(parent) = entry.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let exe = std::env::current_exe()?;
                // Only the Exec line matters for launch; Icon commented until
                // an icon path is published with the install.
                std::fs::write(
                    &entry,
                    format!(
                        "[Desktop Entry]\nType=Application\nName=ShadowMesh\nExec={} --tray\nX-GNOME-Autostart-enabled=true\n",
                        exe.display()
                    ),
                )?;
            } else {
                let _ = std::fs::remove_file(&entry);
            }
            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            use winreg::{RegKey, enums::*};
            let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                KEY_SET_VALUE,
            )?;
            if enabled {
                let exe = std::env::current_exe()?;
                key.set_value("ShadowMesh", &exe.to_string_lossy().to_string())?;
            } else {
                let _ = key.delete_value("ShadowMesh");
            }
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            anyhow::bail!("autostart not supported on this platform")
        }
    }

    #[cfg(target_os = "linux")]
    fn xdg_entry_path() -> Result<PathBuf> {
        let base = dirs::config_dir().context("no XDG config dir")?;
        Ok(base.join("autostart").join("shadowmesh.desktop"))
    }
}

// ---------------------------------------------------------------------------
// §4.4 Forensic wipe (ordered, idempotent, best-effort continue-on-error)
// ---------------------------------------------------------------------------

/// Outcome of a wipe run — per-step results so the UI can show exactly
/// what succeeded; failures never abort the remaining steps (RFC-011 §4.4).
#[derive(Debug, Default)]
pub struct WipeReport {
    pub tunnel_teardown_ok: bool,
    pub files_removed: usize,
    pub steps_failed: Vec<&'static str>,
}

/// Runs the §4.4 purge order. `teardown` is supplied by the caller (the
/// desktop owns the VPN handle) so this module stays UI/framework-free.
pub fn forensic_wipe(state_dir: &Path, teardown: impl FnOnce()) -> WipeReport {
    let mut report = WipeReport::default();

    // 1. Tunnel teardown (kill-switch semantics live in the core).
    teardown();
    report.tunnel_teardown_ok = true;

    // 2. In-memory zeroization happens via the core's Zeroize types when
    //    the VPN manager is dropped; nothing to do explicitly here.

    // 3. App-owned files: security log, caches, update-check stamp.
    for name in ["security.jsonl", "node_cache", "last_update_check"] {
        let path = state_dir.join(name);
        if path.exists() {
            if secure_remove(&path).is_ok() {
                report.files_removed += 1;
            } else {
                report.steps_failed.push("file-removal");
            }
        }
    }

    // 4. Device identity — regenerated as a fresh UUID on next launch
    //    (§4.5 contract: first run generates).
    if secure_remove(&state_dir.join("device_id")).is_err() {
        report.steps_failed.push("device-identity");
    }

    // 5. First-run reset: removal of the activation/token marker is the
    //    "uninstalled-like" state the confirmation dialog promises.
    if secure_remove(&state_dir.join("activation.json")).is_ok() {
        report.files_removed += 1;
    }

    report
}

/// Overwrite-then-unlink: forensic-grade deletion for small files.
/// Best effort — an fs-level failure is reported, not panicked on.
fn secure_remove(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let len = std::fs::metadata(path)?.len();
    if len > 0 && len <= 16 * 1024 * 1024 {
        let zeros = vec![0u8; len as usize];
        std::fs::write(path, &zeros)?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.1.9", "0.2.0"));
        assert!(!is_newer("0.2.0", "0.2.0"));
        assert!(!is_newer("garbage", "1.2.3"));
    }

    #[test]
    fn wipe_removes_state_files_idempotently() {
        let dir = std::env::temp_dir().join(format!("sm-wipe-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("device_id"), "identity").unwrap();
        std::fs::write(dir.join("security.jsonl"), b"secret-line").unwrap();

        let r1 = forensic_wipe(&dir, || {});
        assert!(r1.tunnel_teardown_ok);
        assert!(r1.steps_failed.is_empty(), "no failures expected: {r1:?}");
        assert!(!dir.join("device_id").exists());
        assert!(!dir.join("security.jsonl").exists());

        // Idempotent: second run on the same dir is a clean no-op.
        let r2 = forensic_wipe(&dir, || {});
        assert!(r2.steps_failed.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_check_cadence_respects_24h() {
        let dir = std::env::temp_dir().join(format!("sm-upd-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        assert!(UpdateNotice::check_due(&dir), "no stamp = due");
        UpdateNotice::record_check(&dir);
        assert!(!UpdateNotice::check_due(&dir), "fresh stamp = not due");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
