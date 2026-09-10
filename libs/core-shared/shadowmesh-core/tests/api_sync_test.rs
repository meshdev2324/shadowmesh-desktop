use chrono::{DateTime, Utc};
use shadowmesh_core::api_client::ActivationResponse;
use shadowmesh_core::vpn_manager::ServicePlan;
use std::str::FromStr;

#[test]
fn test_service_plan_deserialization_parity() {
    let plans = vec![
        ("\"solo\"", ServicePlan::Solo),
        ("\"family\"", ServicePlan::Family),
        ("\"team\"", ServicePlan::Team),
        ("\"premium\"", ServicePlan::Premium),
        ("\"trial\"", ServicePlan::Trial),
    ];

    for (json_str, expected) in plans {
        let deserialized: ServicePlan =
            serde_json::from_str(json_str).expect("Failed to deserialize ServicePlan");
        assert_eq!(deserialized, expected);
    }
}

#[test]
fn test_activation_response_chrono_deserialization() {
    let json_payload = r#"{
        "message": "Device activated successfully",
        "token": "sm_tok_99182312",
        "plan": "family",
        "expires_at": "2026-12-31T23:59:59Z",
        "remaining_days": 160,
        "subscription_notice": "Active",
        "devices_remaining": 8,
        "vpn_config": null,
        "server_location": "US-West"
    }"#;

    let resp: ActivationResponse =
        serde_json::from_str(json_payload).expect("Failed to parse ActivationResponse payload");
    assert_eq!(resp.message, "Device activated successfully");
    assert_eq!(resp.plan.as_deref(), Some("family"));

    let expected_date = DateTime::<Utc>::from_str("2026-12-31T23:59:59Z").unwrap();
    assert_eq!(resp.parsed_expires_at(), Some(expected_date));
}

#[test]
fn test_zero_copy_bytes_deserialization() {
    let raw_nodes_json = r#"[
        {
            "id": "node-1",
            "name": "Singapore High Speed",
            "region": "sg",
            "country": "SG",
            "endpoint": "139.59.1.1:443",
            "public_key": "x25519_key_123",
            "load": 24,
            "latency": 15,
            "is_online": true
        }
    ]"#;

    let bytes_buffer = bytes::Bytes::from(raw_nodes_json);
    let nodes: Vec<shadowmesh_core::VPNNode> =
        serde_json::from_slice(&bytes_buffer).expect("Zero-copy slice deserialization failed");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].id, "node-1");
}
