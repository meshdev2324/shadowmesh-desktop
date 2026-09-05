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

    /// Checks if a specific application feature is enabled.
    /// Returns false if the device is in lockout or the kill switch is active.
    pub fn is_feature_enabled(&self, feature: String) -> bool {
        if self.is_lockout() {
            return false;
        }

        if self.is_active_atomic.load(Ordering::Relaxed) && feature != "kill_switch" {
            return false;
        }

        self.feature_flags.get(&feature).map(|r| *r.value()).unwrap_or(true)
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
