use crate::vpn_manager::TrafficModePreference;
use crate::ConnectionStats;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// User preferences regarding traffic management and data usage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrafficPreferences {
    /// Optional monthly data limit in Megabytes.
    pub data_limit_mb: Option<u32>,
    /// Whether to prioritize Wi-Fi connections over cellular.
    pub prioritize_wifi: bool,
    /// Whether to restrict data usage when the application is in the background.
    pub restrict_background_data: bool,
    /// Preferred traffic mode strategy.
    pub mode_preference: TrafficModePreference,
}

impl Default for TrafficPreferences {
    fn default() -> Self {
        TrafficPreferences {
            data_limit_mb: None,
            prioritize_wifi: true,
            restrict_background_data: false,
            mode_preference: TrafficModePreference::Auto,
        }
    }
}

/// Collects and manages traffic usage statistics.
///
/// SOP 01: Optimized with Lock-Free atomics and sharded DashMap for high-speed tracking.
pub struct TrafficAnalytics {
    bytes_total: AtomicU64,
    bytes_by_server: DashMap<String, u64>,
    bytes_this_month: AtomicU64,
}

impl TrafficAnalytics {
    /// Creates a new `TrafficAnalytics` instance with zeroed statistics.
    pub fn new() -> Self {
        TrafficAnalytics {
            bytes_total: AtomicU64::new(0),
            bytes_by_server: DashMap::new(),
            bytes_this_month: AtomicU64::new(0),
        }
    }

    /// Records connection statistics for a specific server.
    pub fn record_stats(&self, server_id: String, stats: ConnectionStats) {
        let amount = stats.bytes_received + stats.bytes_sent;

        self.bytes_total.fetch_add(amount, Ordering::Relaxed);
        self.bytes_this_month.fetch_add(amount, Ordering::Relaxed);

        *self.bytes_by_server.entry(server_id).or_insert(0) += amount;
    }

    /// Returns the total number of bytes transmitted (sent + received) across all sessions.
    pub fn get_total_bytes(&self) -> u64 {
        self.bytes_total.load(Ordering::Relaxed)
    }

    /// Returns the total number of bytes transmitted during the current month.
    pub fn get_bytes_this_month(&self) -> u64 {
        self.bytes_this_month.load(Ordering::Relaxed)
    }

    /// Resets the monthly traffic counter to zero.
    pub fn reset_month(&self) {
        self.bytes_this_month.store(0, Ordering::Relaxed);
    }
}

impl Default for TrafficAnalytics {
    fn default() -> Self {
        Self::new()
    }
}
