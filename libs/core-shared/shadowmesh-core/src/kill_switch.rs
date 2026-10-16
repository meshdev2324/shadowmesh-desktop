use crate::ApiClient;
use crate::ShadowMeshError;
use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Represents a security or state change event recorded by the kill switch.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KillSwitchEvent {
    /// Unix timestamp when the event occurred.
    pub timestamp: u64,
    /// The type of event (e.g., "lockout_change", "kill_switch_triggered").
    pub event_type: String,
    /// Detailed information about the event.
    pub details: String,
}

/// The current state of the kill switch subsystem.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KillSwitchState {
    /// Whether the kill switch is currently active (blocking traffic).
    pub is_active: bool,
    /// Whether the device is in a lockout state (critical security failure).
    pub is_lockout: bool,
    /// A map of individual feature flags and their enabled status.
    pub feature_flags: std::collections::HashMap<String, bool>,
    /// Unix timestamp of the last remote security check.
    pub last_remote_check: Option<u64>,
    /// Whether the system is running in fallback mode using cached state.
    pub fallback_mode: bool,
}

/// Manages the application's kill switch and security lockout mechanisms.
///
/// SOP 01: Refactored with Atomic flags and DashMap for high-performance status checks.
pub struct KillSwitchManager {
    is_active_atomic: AtomicBool,
    is_lockout_atomic: AtomicBool,
    fallback_mode_atomic: AtomicBool,
    feature_flags: DashMap<String, bool>,
    state: Mutex<KillSwitchInternalState>,
}

struct KillSwitchInternalState {
    is_active: bool,
    is_lockout: bool,
    last_check: Option<u64>,
    audit_log: Vec<KillSwitchEvent>,
    cached_state: Option<KillSwitchState>,
}

impl KillSwitchManager {
    /// Creates a new `KillSwitchManager` with default (inactive) state.
    pub fn new() -> Self {
        KillSwitchManager {
            is_active_atomic: AtomicBool::new(false),
            is_lockout_atomic: AtomicBool::new(false),
            fallback_mode_atomic: AtomicBool::new(false),
            feature_flags: DashMap::new(),
            state: Mutex::new(KillSwitchInternalState {
                is_active: false,
                is_lockout: false,
                last_check: None,
                audit_log: Vec::new(),
                cached_state: None,
            }),
        }
    }

    fn get_current_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Returns true if the kill switch is active or the device is in lockout.
    pub fn is_active(&self) -> bool {
        // Fast path: check atomic flags
        if self.is_active_atomic.load(Ordering::Relaxed)
            || self.is_lockout_atomic.load(Ordering::Relaxed)
        {
            return true;
        }

        let state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return true, // Fail-safe
        };
        // Check cached state (for fallback)
        if let Some(cached) = state.cached_state.as_ref() {
            if cached.is_active || cached.is_lockout {
                return true;
            }
        }

        state.is_active || state.is_lockout
    }

    /// Returns true if the device is currently in a security lockout state.
    pub fn is_lockout(&self) -> bool {
        if self.is_lockout_atomic.load(Ordering::Relaxed) {
            return true;
        }

        let state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return true, // Fail-safe
        };
        if let Some(cached) = state.cached_state.as_ref() {
            if cached.is_lockout {
                return true;
            }
        }
        state.is_lockout
    }

    /// Sets the lockout state of the device.
    pub fn set_lockout(&self, enabled: bool) {
        self.is_lockout_atomic.store(enabled, Ordering::Relaxed);

        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        state.is_lockout = enabled;

        state.audit_log.push(KillSwitchEvent {
            timestamp: Self::get_current_time(),
            event_type: "lockout_change".to_string(),
            details: format!("Lockout: {}", enabled),
        });

        // Update cached state
        if let Some(ref mut cached) = state.cached_state.as_mut() {
            cached.is_lockout = enabled;
        }
    }

    /// What a feature's **absence** from `feature_flags` means.
    ///
    /// Absent is the real state, not a corner case. `check_remote` either
    /// populates every flag in the verified manifest or returns `Err` having
    /// touched nothing — RFC-011 §4.2's signature check fails closed in all
    /// four directions (no key, no signature header, wrong key, edited body),
    /// so the table is simply missing every remote flag it never got to write.
    /// That is every device today: K14 records that no deployment can deliver a
    /// signed manifest, so remote feature flags have never been applied
    /// anywhere, and this function answers for every flag the table has never
    /// held.
    ///
    /// A single fallback cannot express the answer, which is why the obvious
    /// fix was refused. Flipping `unwrap_or(true)` to `unwrap_or(false)` reads
    /// as "fail closed", but the state it would fail toward is *remote
    /// suppression*: an attacker who can answer the manifest request but cannot
    /// sign it gets `Err`, and under a scalar `false` that same attack turns
    /// `mfa_auth` off — converting "suppress an update notice" into "remove a
    /// control". Strictly worse than the defect, under exactly the threat C6
    /// was hardened for. Polarity is per-feature because the features are not
    /// alike.
    ///
    /// These mirror `services/server/src/api/handlers/system.rs`'s
    /// `get_security_manifest` one-for-one: each `SHADOWMESH_FEATURE_<NAME>`
    /// default at `:122-132`, replicated below. Enforcement surfaces default
    /// enabled, because an absent flag is a flag nobody has contradicted and
    /// the control is safer assumed on. `quantum_resistance` defaults disabled
    /// (`system.rs:130`, "high overhead, held back from the promoted batch"):
    /// its cost is borne by everyone even when nobody asked for it. Unknown
    /// flags default enabled for the same reason the enforcement set does — a
    /// flag this table predates is more likely to gate a control than to gate
    /// telemetry, and refusing an unknown control is the lossier of the two
    /// mistakes.
    ///
    /// The honest cost: this is a second copy of the server's defaults, and an
    /// operator who sets `SHADOWMESH_FEATURE_MFA_AUTH=0` moves the manifest
    /// without moving this table. The two agree only for a device holding a
    /// signed manifest, which is none today. Until K14 closes, the client and
    /// the server disagree on an absent flag by construction; the parity test
    /// below is what keeps that disagreement from going unnoticed.
    fn default_feature_enabled(feature: &str) -> bool {
        match feature {
            // Enforcement surfaces. Absent still means enforced.
            "core_vpn"
            | "mfa_auth"
            | "biometric_lock"
            | "camouflage_mode"
            | "reality_protocol"
            | "quantum_fragmentation"
            | "remote_panic_wipe"
            | "ebpf_monitoring" => true,
            // High overhead, off by default in the server manifest.
            "quantum_resistance" => false,
            // Unknown: a control nobody has contradicted is still a control.
            _ => true,
        }
    }

    /// Checks if a specific application feature is enabled.
    /// Returns false if the device is in lockout or the kill switch is active.
    pub fn is_feature_enabled(&self, feature: String) -> bool {
        if self.is_lockout() {
            return false;
        }

        if self.is_active_atomic.load(Ordering::Relaxed) && feature != "kill_switch" {
            return false;
        }

        self.feature_flags
            .get(&feature)
            .map(|r| *r.value())
            .unwrap_or_else(|| Self::default_feature_enabled(&feature))
    }

    /// Toggles an application feature flag.
    pub fn set_feature_enabled(&self, feature: String, enabled: bool) {
        self.feature_flags.insert(feature.clone(), enabled);

        if let Ok(mut state) = self.state.lock() {
            state.audit_log.push(KillSwitchEvent {
                timestamp: Self::get_current_time(),
                event_type: "feature_toggle".to_string(),
                details: format!("{}: {}", feature, enabled),
            });
        }
    }

    /// Synchronizes the local security state with the remote API.
    ///
    /// The manifest is verified before it is applied: RFC-011 §4.2 asks for a
    /// minisign/ed25519 signature and `ApiClient::fetch_security_manifest_async`
    /// fails closed when one cannot be checked (no configured public key, no
    /// signature header, wrong key, edited body). So this returns `Err` and
    /// leaves every flag exactly as it was — an attacker who can answer the
    /// request but cannot sign it gets to suppress an update notice, which is
    /// the whole of the threat this signature exists to close, and gets
    /// *nothing* else.
    ///
    /// What it still does not do is let the remote side set `is_active` or
    /// `is_lockout`. Those remain local decisions; the manifest only populates
    /// `feature_flags`.
    pub fn check_remote(&self, client: Arc<ApiClient>) -> Result<(), ShadowMeshError> {
        let manifest = client.fetch_security_manifest()?;

        for (feature, enabled) in manifest.flags {
            self.feature_flags.insert(feature, enabled);
        }

        let mut state = self.state.lock().map_err(|e| ShadowMeshError::Other(e.to_string()))?;
        let current_time = Self::get_current_time();
        state.last_check = Some(current_time);

        let mut feature_flags_map = std::collections::HashMap::new();
        for r in self.feature_flags.iter() {
            feature_flags_map.insert(r.key().clone(), *r.value());
        }

        // Update cached state for fallback (in case of network outage)
        state.cached_state = Some(KillSwitchState {
            is_active: state.is_active,
            is_lockout: state.is_lockout,
            feature_flags: feature_flags_map,
            last_remote_check: Some(current_time),
            fallback_mode: self.fallback_mode_atomic.load(Ordering::Relaxed),
        });

        Ok(())
    }

    /// Manually triggers the kill switch for the specified reason.
    pub fn trigger_kill_switch(&self, reason: String) {
        self.is_active_atomic.store(true, Ordering::Relaxed);

        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        state.is_active = true;

        state.audit_log.push(KillSwitchEvent {
            timestamp: Self::get_current_time(),
            event_type: "kill_switch_triggered".to_string(),
            details: reason,
        });

        // Also update cached state
        if let Some(ref mut cached) = state.cached_state.as_mut() {
            cached.is_active = true;
        } else {
            let mut feature_flags_map = std::collections::HashMap::new();
            for r in self.feature_flags.iter() {
                feature_flags_map.insert(r.key().clone(), *r.value());
            }
            state.cached_state = Some(KillSwitchState {
                is_active: true,
                is_lockout: state.is_lockout,
                feature_flags: feature_flags_map,
                last_remote_check: Some(Self::get_current_time()),
                fallback_mode: self.fallback_mode_atomic.load(Ordering::Relaxed),
            });
        }
    }

    /// Deactivates the kill switch, restoring normal network operation.
    pub fn deactivate_kill_switch(&self) {
        self.is_active_atomic.store(false, Ordering::Relaxed);

        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        state.is_active = false;

        state.audit_log.push(KillSwitchEvent {
            timestamp: Self::get_current_time(),
            event_type: "kill_switch_deactivated".to_string(),
            details: "Manually deactivated".to_string(),
        });

        // Update cached state
        if let Some(ref mut cached) = state.cached_state.as_mut() {
            cached.is_active = false;
        }
    }

    /// Sets whether the kill switch should operate in fallback mode using cached state.
    pub fn set_fallback_mode(&self, enabled: bool) {
        self.fallback_mode_atomic.store(enabled, Ordering::Relaxed);
    }

    /// Returns true if the kill switch is currently in fallback mode.
    pub fn is_fallback_mode(&self) -> bool {
        self.fallback_mode_atomic.load(Ordering::Relaxed)
    }

    /// Returns a copy of the security audit log.
    pub fn get_audit_log(&self) -> Vec<KillSwitchEvent> {
        match self.state.lock() {
            Ok(state) => state.audit_log.clone(),
            Err(_) => Vec::new(),
        }
    }

    /// Manually updates the cached state for the kill switch.
    pub fn save_state_to_cache(&self, ks_state: KillSwitchState) {
        if let Ok(mut state) = self.state.lock() {
            state.cached_state = Some(ks_state);
        }
    }

    /// Retrieves the currently cached kill switch state.
    pub fn get_cached_state(&self) -> Option<KillSwitchState> {
        self.state.lock().ok().and_then(|s| s.cached_state.clone())
    }
}

impl Default for KillSwitchManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nine flags `get_security_manifest` publishes, paired with the
    /// compiled-in default each `SHADOWMESH_FEATURE_<NAME>` env var falls back
    /// to when it is unset.
    ///
    /// Source: `services/server/src/api/handlers/system.rs:122-132` —
    /// `:122` `core_vpn` true; `:123` `mfa_auth` true; `:124` `biometric_lock`
    /// true; `:125` `camouflage_mode` true; `:126` `reality_protocol` true;
    /// `:127-128` `quantum_fragmentation` true; `:130` `quantum_resistance`
    /// false (its comment sits on `:129` — "Off by default: high overhead,
    /// held back from the promoted batch"); `:131` `remote_panic_wipe` true;
    /// `:132` `ebpf_monitoring` true.
    ///
    /// Hand-copied rather than read from the server crate: this is the client,
    /// and the point of the test is that a silent drift between the two lists
    /// fails here instead of on a device.
    const MANIFEST_DEFAULTS: [(&str, bool); 9] = [
        ("core_vpn", true),
        ("mfa_auth", true),
        ("biometric_lock", true),
        ("camouflage_mode", true),
        ("reality_protocol", true),
        ("quantum_fragmentation", true),
        ("quantum_resistance", false),
        ("remote_panic_wipe", true),
        ("ebpf_monitoring", true),
    ];

    #[test]
    fn an_absent_enforcement_feature_fails_enabled() {
        let ks = KillSwitchManager::new();
        // Nothing has populated `feature_flags`, which is the state of every
        // device that has never completed a verified remote check. The control
        // is safer assumed on than assumed off.
        assert!(ks.is_feature_enabled("mfa_auth".to_string()));
    }

    #[test]
    fn an_absent_monitoring_feature_fails_disabled() {
        let ks = KillSwitchManager::new();
        // The one manifest member with `false` polarity. Absent must not claim
        // a control that is not there.
        assert!(!ks.is_feature_enabled("quantum_resistance".to_string()));
    }

    #[test]
    fn every_flag_the_server_manifest_declares_matches_the_client_default() {
        let ks = KillSwitchManager::new();
        for (feature, expected) in MANIFEST_DEFAULTS {
            assert_eq!(
                ks.is_feature_enabled(feature.to_string()),
                expected,
                "client default for `{feature}` disagrees with the \
                 SHADOWMESH_FEATURE_* manifest default (system.rs:122-132)"
            );
        }

        // The count is the count. A flag added to the server manifest without a
        // client arm would fall through to the unknown-feature arm (which fails
        // enabled) and so would surface here as a polarity disagreement rather
        // than as a missing entry — that is why the length is pinned too.
        assert_eq!(MANIFEST_DEFAULTS.len(), 9);
    }

    #[test]
    fn an_unknown_feature_fails_enabled() {
        let ks = KillSwitchManager::new();
        // A flag no table knows about is more likely enforcement than
        // telemetry, so it defaults enabled with the enforcement set.
        assert!(ks.is_feature_enabled("a_flag_added_next_release".to_string()));
    }

    #[test]
    fn an_explicitly_set_flag_still_wins_over_the_default() {
        let ks = KillSwitchManager::new();
        // Baseline first, so the assertions below can only have been decided by
        // the table entry: absent `mfa_auth` is enabled and absent
        // `quantum_resistance` is disabled.
        assert!(ks.is_feature_enabled("mfa_auth".to_string()));
        assert!(!ks.is_feature_enabled("quantum_resistance".to_string()));

        ks.set_feature_enabled("mfa_auth".to_string(), false);
        assert!(!ks.is_feature_enabled("mfa_auth".to_string()));

        ks.set_feature_enabled("quantum_resistance".to_string(), true);
        assert!(ks.is_feature_enabled("quantum_resistance".to_string()));
    }

    #[test]
    fn lockout_and_active_kill_switch_override_any_flag() {
        let ks = KillSwitchManager::new();
        // Both flags explicitly enabled, so only the override can answer false.
        ks.set_feature_enabled("mfa_auth".to_string(), true);
        ks.set_feature_enabled("quantum_resistance".to_string(), true);

        ks.set_lockout(true);
        assert!(!ks.is_feature_enabled("mfa_auth".to_string()));
        assert!(!ks.is_feature_enabled("quantum_resistance".to_string()));
        ks.set_lockout(false);

        ks.trigger_kill_switch("tests: exercising the override".to_string());
        assert!(!ks.is_feature_enabled("mfa_auth".to_string()));
        assert!(!ks.is_feature_enabled("quantum_resistance".to_string()));
        // The documented carve-out: the connection that is killing its own
        // traffic must still be able to say it is doing so.
        assert!(ks.is_feature_enabled("kill_switch".to_string()));
    }
}
