use serde::Serialize;

#[derive(Debug, Serialize, PartialEq)]
pub struct AppNotification {
    pub title: String,
    pub body: String,
    pub status: NotificationStatus,
}

#[derive(Debug, Serialize, PartialEq)]
pub enum NotificationStatus {
    Info,
    Success,
    Warning,
    Error,
}

pub fn map_vpn_status_to_notification(connected: bool, state: &str) -> Option<AppNotification> {
    match (connected, state) {
        (true, "connected") => Some(AppNotification {
            title: "ShadowMesh Protected".to_string(),
            body: "Your connection is now encrypted and secure.".to_string(),
            status: NotificationStatus::Success,
        }),
        (false, "disconnected") => Some(AppNotification {
            title: "ShadowMesh Disconnected".to_string(),
            body: "Your connection is no longer protected.".to_string(),
            status: NotificationStatus::Warning,
        }),
        (false, "error") => Some(AppNotification {
            title: "Connection Failed".to_string(),
            body: "ShadowMesh encountered an error while connecting.".to_string(),
            status: NotificationStatus::Error,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connected_notification() {
        let note = map_vpn_status_to_notification(true, "connected").unwrap();
        assert_eq!(note.status, NotificationStatus::Success);
        assert!(note.title.contains("Protected"));
    }

    #[test]
    fn test_error_notification() {
        let note = map_vpn_status_to_notification(false, "error").unwrap();
        assert_eq!(note.status, NotificationStatus::Error);
    }
}
