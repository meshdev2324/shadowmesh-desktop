/// Linux-specific networking optimizations.
#[cfg(target_os = "linux")]
pub mod linux;

/// Generic socket tuning and OS abstractions.
pub mod socket;
