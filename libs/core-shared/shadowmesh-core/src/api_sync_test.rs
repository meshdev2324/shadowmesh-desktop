#[cfg(test)]
mod tests {
    use crate::api_client::*;
    use serde_json::json;

    #[test]
    fn test_activation_response_deserialization_robustness() {
        // Test that extra fields from server don't break client, and defaults work
        let server_json = json!({
            "message": "Activated",
            "token": "test-token",
            "code_info": {"plan": "Team"},
            "expires_at": "2026-12-31T23:59:59Z",
            "remaining_days": 180,
            "subscription_notice": "Welcome",
            "devices_remaining": 2,
            "unknown_new_field": "some data"
        });

        let res: ActivationResponse = serde_json::from_value(server_json).unwrap();
        assert_eq!(res.token, Some("test-token".to_string()));
        assert_eq!(res.remaining_days, 180);
    }

    #[test]
    fn test_error_response_alias() {
        let server_json = json!({
            "status": "error",
            "error": "Access Denied"
        });

        let res: ApiErrorResponse = serde_json::from_value(server_json).unwrap();
        assert_eq!(res.message, "Access Denied");
    }

    #[test]
    fn test_vpn_config_websocket_deserialization() {
        let config_json = json!({
            "assigned_ip": "10.0.0.2",
            "server_public_key": "pubkey",
            "endpoint": "1.2.3.4:443",
            "dns": "1.1.1.1",
            "mtu": 1280,
            "traffic_mode": "websocket",
            "ws_config": {
                "server_ip": "1.2.3.4",
                "port": 443,
                "path": "/ws",
                "host": "cdn.shadowmesh.org",
                "uuid": "uuid-v4"
            }
        });

        let config: crate::VPNConfig = serde_json::from_value(config_json).unwrap();
        assert!(config.ws_config.is_some());
        assert_eq!(config.ws_config.unwrap().host, "cdn.shadowmesh.org");
    }
}
