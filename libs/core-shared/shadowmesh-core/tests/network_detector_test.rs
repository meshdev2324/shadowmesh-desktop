use shadowmesh_core::*;
use std::sync::Arc;

#[test]
fn test_network_detector_initialization() {
    let client = create_api_client("https://api.shadowmesh.io".to_string()).unwrap();
    let detector = create_network_detector(client, None);

    // Test that we can create it and it doesn't crash
    assert!(Arc::strong_count(&detector) >= 1);
}

#[test]
fn test_network_report_structure() {
    // This tests the data structure and default values if we were to construct it
    let report = NetworkReport {
        is_connected: true,
        network_type: NetworkType::WiFi,
        latency_ms: Some(25),
        jitter_ms: Some(2),
        packet_loss: Some(0.0),
        speed_test: Some(SpeedTestResult {
            latency_ms: 25.0,
            download_speed_mbps: 100.0,
            upload_speed_mbps: 50.0,
        }),
        server_report: None,
        captive_portal_detected: false,
        dpi_detected: false,
        is_protected: false,
    };

    assert!(report.is_connected);
    if let NetworkType::WiFi = report.network_type {
        // ok
    } else {
        panic!("Wrong network type");
    }
}

#[test]
fn test_detector_with_invalid_url() {
    // Should return an error if it can't even connect to the base URL
    let client = create_api_client("http://invalid.local".to_string()).unwrap();
    let detector = NetworkDetector::new(client, None);

    let result = detector.detect(false);

    // It should still return a report, but marked as not connected
    match result {
        Ok(report) => {
            assert!(!report.is_connected);
            assert!(report.latency_ms.is_none());
        }
        Err(_) => panic!("Detection should return a report even on failure"),
    }
}
