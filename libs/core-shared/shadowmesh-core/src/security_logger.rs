use crate::ShadowMeshError;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

/// Categorization of various security-related events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityEventType {
    /// The state of the kill switch has changed.
    KillSwitchStateChange,
    /// A potential jailbreak or root access was detected on the device.
    JailbreakRootDetected,
    /// A server certificate validation attempt failed.
    CertificateValidationFailed,
    /// An integrity check failed for one or more components.
    TamperingAlert,
    /// The application has initiated a secure panic/wipe.
    PanicInitiated,
    /// A user login attempt (success or failure).
    LoginAttempt,
    /// A user has logged out.
    Logout,
}

/// Represents a single security event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unix timestamp when the event occurred.
    pub timestamp: u64,
    /// Anonymized identifier for the device.
    pub device_id: String,
    /// The version of the application.
    pub app_version: String,
    /// The type of security event.
    pub event_type: SecurityEventType,
    /// Detailed information about the event (PII scrubbed).
    pub details: String,
    /// Whether the action associated with the event was successful.
    pub success: bool,
}

/// A logger for recording and transmitting security-sensitive events.
pub struct SecurityEventLogger {
    events: Arc<Mutex<Vec<SecurityEvent>>>,
    _storage_path: PathBuf,
    device_id: String,
    app_version: String,
}

impl SecurityEventLogger {
    /// Creates a new `SecurityEventLogger`.
    pub fn new(
        device_id: String,
        app_version: String,
        storage_dir: String,
    ) -> Result<Self, ShadowMeshError> {
        let storage_path = PathBuf::from(storage_dir);
        std::fs::create_dir_all(&storage_path)?;
        Ok(SecurityEventLogger {
            events: Arc::new(Mutex::new(Vec::new())),
            _storage_path: storage_path,
            device_id,
            app_version,
        })
    }

    /// Logs a security event locally and optionally transmits it to the server.
    ///
    /// The device ID is anonymized via SHA-256 and PII is scrubbed from the details string.
    /// This implementation includes atomic file-system persistence for forensic resistance.
    pub fn log_event(
        &self,
        event_type: SecurityEventType,
        details: String,
        success: bool,
        api_client: Option<Arc<crate::api_client::ApiClient>>,
    ) {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        // 🛡️ Forensic Resistance: Scrub PII from details before logging
        let scrubbed_details = scrub_pii(&details);

        let anonymized_device_id = shadowmesh_common::crypto::anonymize_id(&self.device_id);

        let event = SecurityEvent {
            timestamp,
            device_id: anonymized_device_id,
            app_version: self.app_version.clone(),
            event_type,
            details: scrubbed_details,
            success,
        };

        // Log locally (In-Memory)
        if let Ok(mut events) = self.events.lock() {
            events.push(event.clone());
        }

        // 🛡️ Persistent Forensic Log: Append-only with FS sync
        let log_file = self._storage_path.join("security.jsonl");
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&log_file)
        {
            if let Ok(json) = serde_json::to_string(&event) {
                let _ = writeln!(file, "{}", json);
                let _ = file.sync_all(); // Ensure it's on disk
            }
        }

        // Log to Rust server if client provided
        if let Some(client) = api_client {
            let event_json = serde_json::to_string(&event).unwrap_or_default();
            let _ = client.log_security_event(event_json);
        }
    }

    /// Retrieves all locally logged security events.
    pub fn get_events(&self) -> Vec<SecurityEvent> {
        self.events.lock().map(|guard| guard.clone()).unwrap_or_default()
    }

    /// 🛡️ Forensic Purge: Clears in-memory events and deletes the persistent log file.
    pub fn purge(&self) {
        if let Ok(mut events) = self.events.lock() {
            events.clear();
        }

        let log_file = self._storage_path.join("security.jsonl");
        if log_file.exists() {
            let _ = std::fs::remove_file(log_file);
        }
        info!("CRITICAL: Security logs purged from memory and disk.");
    }
}

/// Scrubs Personally Identifiable Information (PII) such as IP addresses,
/// cryptographic keys, and activation codes from the input string.
pub fn scrub_pii(input: &str) -> String {
    shadowmesh_common::logging::scrub_pii(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_log_event() -> Result<(), ShadowMeshError> {
        let temp_dir = tempdir().map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
        let logger = SecurityEventLogger::new(
            "test_device_123".to_string(),
            "1.0.0".to_string(),
            temp_dir
                .path()
                .to_str()
                .ok_or_else(|| ShadowMeshError::Other("Invalid path".into()))?
                .to_string(),
        )?;

        logger.log_event(
            SecurityEventType::KillSwitchStateChange,
            "enabled".to_string(),
            true,
            None,
        );

        let events = logger.get_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, SecurityEventType::KillSwitchStateChange);
        assert_eq!(events[0].details, "enabled");
        assert!(events[0].success);
        Ok(())
    }

    #[test]
    fn test_multiple_events() -> Result<(), ShadowMeshError> {
        let temp_dir = tempdir().map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
        let logger = SecurityEventLogger::new(
            "test_device_456".to_string(),
            "1.0.0".to_string(),
            temp_dir
                .path()
                .to_str()
                .ok_or_else(|| ShadowMeshError::Other("Invalid path".into()))?
                .to_string(),
        )?;

        logger.log_event(SecurityEventType::LoginAttempt, "user login".to_string(), true, None);
        logger.log_event(SecurityEventType::Logout, "user logout".to_string(), true, None);

        let events = logger.get_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, SecurityEventType::LoginAttempt);
        assert_eq!(events[1].event_type, SecurityEventType::Logout);
        Ok(())
    }

    #[test]
    fn test_device_id_anonymized() -> Result<(), ShadowMeshError> {
        let temp_dir = tempdir().map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
        let original_device_id = "real_device_id";
        let logger = SecurityEventLogger::new(
            original_device_id.to_string(),
            "1.0.0".to_string(),
            temp_dir
                .path()
                .to_str()
                .ok_or_else(|| ShadowMeshError::Other("Invalid path".into()))?
                .to_string(),
        )?;

        logger.log_event(SecurityEventType::TamperingAlert, "test".to_string(), false, None);

        let events = logger.get_events();
        let logged_device_id = &events[0].device_id;
        assert_ne!(logged_device_id, original_device_id);
        assert_eq!(logged_device_id.len(), 64); // SHA256 hash is 64 hex chars
        Ok(())
    }
}
