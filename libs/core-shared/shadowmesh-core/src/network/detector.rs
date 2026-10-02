use crate::api_client::{ApiClient, ServerNetworkReport};
use crate::speed_test::{SpeedTest, SpeedTestResult};
use crate::ShadowMeshError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

/// Represents the type of network connection currently active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkType {
    /// The network type could not be determined.
    Unknown,
    /// Connected via Wi-Fi.
    WiFi,
    /// Connected via a cellular network (e.g., LTE, 5G).
    Cellular,
    /// Connected via a wired Ethernet connection.
    Ethernet,
}

/// A comprehensive report on the current network conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkReport {
    /// Whether the device has internet connectivity to the ShadowMesh API.
    pub is_connected: bool,
    /// The type of network connection.
    pub network_type: NetworkType,
    /// Average round-trip latency in milliseconds.
    pub latency_ms: Option<u32>,
    /// Jitter (variation in latency) in milliseconds.
    pub jitter_ms: Option<u32>,
    /// Percentage of packet loss (0.0 to 1.0).
    pub packet_loss: Option<f32>,
    /// Detailed speed test results, if performed.
    pub speed_test: Option<SpeedTestResult>,
    /// Detailed report from the server's perspective.
    pub server_report: Option<ServerNetworkReport>,
    /// Captive portal result: `None` = not checked, `Some(0)` = checked and
    /// clear, `Some(1)` = checked and a portal was found.
    ///
    /// This was a `bool` initialised to `false` and never assigned again, so
    /// the UI rendered "no captive portal" for a check that had never run. A
    /// nullable integer distinguishes the two states; on a censorship tool the
    /// difference between "clear" and "unknown" is the whole point.
    pub captive_portal: Option<u8>,
    /// Local DPI result, same encoding as [NetworkReport::captive_portal].
    /// Core performs no local DPI analysis, so this stays `None`.
    pub dpi_detected: Option<u8>,
    /// Whether [NetworkReport::dpi_detected] reflects the control plane's
    /// heuristic rather than analysis on this device. Reported separately so
    /// the UI can attribute the finding honestly.
    pub dpi_detected_by_server: bool,
    /// Whether the VPN connection is verified "Protected" (Observed IP != Baseline IP).
    pub is_protected: bool,
}

/// A detector for analyzing network connectivity and quality.
pub struct NetworkDetector {
    api_client: Arc<ApiClient>,
    speed_tester: Arc<SpeedTest>,
    vpn_manager: Option<Arc<crate::vpn_manager::VPNManager>>,
}

impl NetworkDetector {
    /// Creates a new `NetworkDetector` using the provided API client.
    pub fn new(
        api_client: Arc<ApiClient>,
        manager: Option<Arc<crate::vpn_manager::VPNManager>>,
    ) -> Self {
        let speed_tester = Arc::new(SpeedTest::new(api_client.clone()));
        Self { api_client, speed_tester, vpn_manager: manager }
    }

    /// Performs a network detection scan.
    ///
    /// If `run_speed_test` is true, a full download/upload speed test will be performed
    /// if connectivity is confirmed.
    pub fn detect(&self, run_speed_test: bool) -> Result<NetworkReport, ShadowMeshError> {
        let mut report = Self::unmeasured_report();

        // 1. Connectivity & Latency Check
        let iterations = 5;
        let mut latencies = Vec::with_capacity(iterations);
        let mut success_count = 0;

        for _ in 0..iterations {
            let start = Instant::now();
            if self.api_client.speedtest_ping().is_ok() {
                latencies.push(start.elapsed().as_millis() as u32);
                success_count += 1;
            }
        }

        if success_count > 0 {
            report.is_connected = true;
            let avg_latency = latencies.iter().sum::<u32>() / success_count as u32;
            report.latency_ms = Some(avg_latency);
            report.packet_loss = Some((iterations - success_count) as f32 / iterations as f32);

            if success_count > 1 {
                report.jitter_ms = Some(Self::calculate_jitter(&latencies));
            }

            // 1.1 Fetch Server Report
            if let Ok(server_report) = self.api_client.detect_network() {
                // The control plane's heuristic, recorded as such. Reporting
                // it as `dpi_detected` implied this device had analysed
                // traffic; it had not.
                report.dpi_detected_by_server = server_report.potential_dpi;
                if server_report.potential_dpi {
                    report.dpi_detected = Some(1);
                }

                // v11.1 Verification Flow: Verify Protected Status
                if let Some(ref manager) = self.vpn_manager {
                    if let Some(baseline) = manager.get_baseline_ip() {
                        if baseline != server_report.client_ip
                            && manager.get_status()
                                == crate::vpn_manager::ConnectionStatus::Connected
                        {
                            report.is_protected = true;
                        }
                    }
                }

                report.server_report = Some(server_report);

                // v5.0 Proactive Telemetry: If DPI detected, log it immediately
                if report.dpi_detected_by_server {
                    let _ = self.api_client.log_security_event(
                        serde_json::json!({
                            "event_type": "DpiDetected",
                            "details": "Network analysis identified characteristic DPI patterns",
                            "success": false
                        })
                        .to_string(),
                    );
                }
            }
        }

        // 2. Speed Test (Optional)
        if run_speed_test && report.is_connected {
            if let Ok(result) = self.speed_tester.run_full_test() {
                report.speed_test = Some(result);
            }
        }

        // 3. Captive portal and 4. local DPI analysis are deliberately NOT
        //    implemented here, and are left at NotChecked.
        //
        //    Both were previously reported as "clear" without ever having been
        //    measured. Detecting a portal requires fetching a known plaintext
        //    HTTP resource and inspecting the response for a redirect, which is
        //    a platform-network operation; local DPI analysis requires packet
        //    inspection this core does not have. Reporting a result we did not
        //    produce is worse than reporting nothing.

        Ok(report)
    }

    /// A report in which nothing has been measured yet.
    ///
    /// Extracted so the "unknown" starting state is directly testable. The
    /// diagnostic fields that no code path actually populates start as `None`
    /// rather than `false`: a false would be indistinguishable from a clean
    /// result, and the client would render an all-clear for checks that never
    /// ran.
    fn unmeasured_report() -> NetworkReport {
        NetworkReport {
            is_connected: false,
            network_type: NetworkType::Unknown,
            latency_ms: None,
            jitter_ms: None,
            packet_loss: None,
            speed_test: None,
            server_report: None,
            captive_portal: None,
            dpi_detected: None,
            dpi_detected_by_server: false,
            is_protected: false,
        }
    }

    fn calculate_jitter(latencies: &[u32]) -> u32 {
        if latencies.len() < 2 {
            return 0;
        }
        let mut jitter = 0;
        for i in 0..latencies.len() - 1 {
            jitter += latencies[i].abs_diff(latencies[i + 1]);
        }
        jitter / (latencies.len() - 1) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmeasured_diagnostics_are_none_not_false() {
        // Regression lock. These fields were `bool` initialised to false and
        // never assigned, so the client rendered "no captive portal" and "no
        // DPI" for checks that had never run -- a permanent false all-clear on
        // a censorship tool. If this test fails, a boolean has crept back in.
        let report = NetworkDetector::unmeasured_report();

        assert_eq!(
            report.captive_portal, None,
            "captive portal must be unknown until a probe actually runs"
        );
        assert_eq!(
            report.dpi_detected, None,
            "local DPI analysis is not implemented; it must not claim to be clear"
        );
        assert!(!report.dpi_detected_by_server, "no server heuristic has been consulted yet");
    }

    #[test]
    fn test_calculate_jitter() {
        let latencies = vec![10, 12, 10, 12];
        // differences: |10-12|=2, |12-10|=2, |10-12|=2. Sum=6. Count=3. Avg=2.
        assert_eq!(NetworkDetector::calculate_jitter(&latencies), 2);

        let latencies = vec![10, 10, 10];
        assert_eq!(NetworkDetector::calculate_jitter(&latencies), 0);

        let latencies = vec![10];
        assert_eq!(NetworkDetector::calculate_jitter(&latencies), 0);
    }
}
