#[cfg(test)]
mod tests {
    use super::super::*;
    use shadowmesh_core::{
        ActivationChallenge, ActivationRequest, ActivationResponse, HealthStatus, HeartbeatRequest,
        HeartbeatResponse, IdentityInfo, ShadowMeshError, VPNConfig, VPNNode,
    };
    use std::sync::Arc;

    struct MockCommandRunner;
    #[async_trait::async_trait]
    impl SystemCommandRunner for MockCommandRunner {
        async fn run_command(&self, _cmd: &str, _args: &[&str]) -> anyhow::Result<String> {
            Ok("mock output".into())
        }
        async fn spawn_tunnel(
            &self,
            _cmd: &str,
            _args: &[&str],
            _name: String,
        ) -> anyhow::Result<Box<dyn VpnTunnel>> {
            struct MockTunnel;
            #[async_trait::async_trait]
            impl VpnTunnel for MockTunnel {
                fn pid(&self) -> Option<u32> {
                    None
                }
                fn try_wait(&mut self) -> anyhow::Result<Option<std::process::ExitStatus>> {
                    Ok(None)
                }
                async fn shutdown(&mut self) -> anyhow::Result<()> {
                    Ok(())
                }
            }
            Ok(Box::new(MockTunnel))
        }
    }

    struct MockApi;
    #[async_trait::async_trait]
    impl ShadowApi for MockApi {
        async fn qr_authorize(&self, _token: String) -> Result<(), ShadowMeshError> {
            Ok(())
        }
        async fn request_activation_challenge(
            &self,
            _device_id: String,
        ) -> Result<ActivationChallenge, ShadowMeshError> {
            Ok(ActivationChallenge { challenge: "".into(), difficulty: 0 })
        }
        async fn activate(
            &self,
            _req: ActivationRequest,
        ) -> Result<ActivationResponse, ShadowMeshError> {
            Ok(ActivationResponse {
                message: "OK".into(),
                token: Some("valid-token".into()),
                plan: Some("Pro".into()),
                expires_at: None,
                remaining_days: 365,
                subscription_notice: "".into(),
                devices_remaining: 4,
                vpn_config: None,
                is_canary: Some(false),
                server_location: None,
            })
        }
        async fn get_nodes(&self) -> Result<Vec<VPNNode>, ShadowMeshError> {
            Ok(vec![])
        }
        async fn get_config(
            &self,
            _n: String,
            _p: String,
            _m: Option<String>,
        ) -> Result<VPNConfig, ShadowMeshError> {
            Ok(VPNConfig::test_fixture())
        }
        async fn heartbeat(
            &self,
            _req: HeartbeatRequest,
        ) -> Result<HeartbeatResponse, ShadowMeshError> {
            Ok(HeartbeatResponse {
                message: "OK".into(),
                device_id: "id".into(),
                session_active: true,
                subscription_notice: "".into(),
                next_heartbeat: "".into(),
            })
        }
        async fn get_identity_info(&self) -> Result<IdentityInfo, ShadowMeshError> {
            Ok(IdentityInfo {
                id: 1,
                public_key: "".into(),
                is_admin: false,
                mfa_enabled: false,
                created_at: "".into(),
            })
        }
        async fn qr_generate(
            &self,
            _device_id: String,
            _device_name: String,
            _os_name: String,
            _os_version: String,
            _arch: String,
        ) -> Result<String, ShadowMeshError> {
            Ok("token".into())
        }
        async fn qr_status(&self, _token: String) -> Result<String, ShadowMeshError> {
            Ok("authorized".into())
        }
        async fn check_health(&self) -> Result<HealthStatus, ShadowMeshError> {
            Ok(HealthStatus { status: "ok".into(), version: "1.0".into(), uptime_seconds: 100 })
        }
        async fn report_compromised(
            &self,
            _device_id: String,
            _reason: String,
        ) -> Result<(), ShadowMeshError> {
            Ok(())
        }
        async fn ping_gateway(&self) -> Result<bool, ShadowMeshError> {
            Ok(true)
        }
        fn set_auth_token(&self, _token: Option<String>) {}
        fn set_pow_solution(&self, _solution: String, _original_challenge: String) {}
        fn set_device_id(&self, _device_id: String) {}
        fn get_core_client(&self) -> Arc<shadowmesh_core::ApiClient> {
            Arc::new(shadowmesh_core::ApiClient::new("http://localhost".into()).unwrap())
        }
    }

    #[tokio::test]
    async fn test_daemon_activation_mock() {
        let api_client = Arc::new(MockApi);
        let file_system = Arc::new(crate::orchestration::RealFileSystem);
        let secure_storage = Arc::new(crate::orchestration::RealSecureStorage);
        let command_runner = Arc::new(MockCommandRunner);

        let daemon = Daemon::new(api_client, file_system, secure_storage, command_runner).unwrap();

        let response = daemon.handle_activate("12345-12345-12345-12345-12345".into()).await;

        assert!(response.success);
        assert_eq!(response.message, "Activated");
    }

    // ── RFC-016 G3: Status must report the live tunnel's endpoint and mode ──

    /// A `VpnTunnel` that is up and carries a PID, so the test can tell a
    /// genuinely-running handle from an absent one.
    struct LiveTunnel(u32);
    #[async_trait::async_trait]
    impl VpnTunnel for LiveTunnel {
        fn pid(&self) -> Option<u32> {
            Some(self.0)
        }
        fn try_wait(&mut self) -> anyhow::Result<Option<std::process::ExitStatus>> {
            Ok(None)
        }
        async fn shutdown(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    async fn status_with_tunnel(tunnel: Option<crate::daemon::TunnelHandle>) -> serde_json::Value {
        let daemon = Arc::new(
            Daemon::new(
                Arc::new(MockApi),
                Arc::new(crate::orchestration::RealFileSystem),
                Arc::new(crate::orchestration::RealSecureStorage),
                Arc::new(MockCommandRunner),
            )
            .unwrap(),
        );

        {
            let mut guard = daemon.active_tunnel.lock().await;
            *guard = tunnel;
        }

        let response = crate::ipc::process_command(
            crate::types::VpnCommand {
                action: crate::types::VpnAction::Status,
                token: "test-token".into(),
            },
            daemon,
        )
        .await;

        assert!(response.success, "Status must answer even with no tunnel up: {response:?}");
        match response.data {
            Some(crate::types::VpnResponseData::Status(v)) => v,
            other => panic!("expected a Status payload, got {other:?}"),
        }
    }

    /// RFC-016 G3 asked for `endpoint` and `mode` **from the daemon's live
    /// tunnel handle**. Neither was emitted: the object carried only
    /// `active`, `name` and `pid`, so an operator could see a tunnel was up and
    /// could not see where it was going or how.
    ///
    /// The values asserted here are deliberately ones the daemon's **config**
    /// does not contain, so a pass cannot come from re-reading config — which
    /// is what the old `mode`-from-config framing would have done.
    #[tokio::test]
    async fn status_reports_endpoint_and_mode_from_the_live_tunnel_handle() {
        let status = status_with_tunnel(Some(crate::daemon::TunnelHandle::new(
            Box::new(LiveTunnel(4242)),
            "wg-quick".to_string(),
            "vpn.example.net:51820".to_string(),
            "fragmented".to_string(),
        )))
        .await;

        let tunnel = &status["tunnel"];
        assert_eq!(tunnel["active"], true, "{tunnel}");
        assert_eq!(tunnel["name"], "wg-quick", "{tunnel}");
        assert_eq!(tunnel["pid"], 4242, "{tunnel}");

        // The two fields RFC-016 G3 named.
        assert_eq!(
            tunnel["endpoint"], "vpn.example.net:51820",
            "RFC-016 G3: endpoint must come from the live tunnel handle: {status}"
        );
        assert_eq!(
            tunnel["mode"], "fragmented",
            "RFC-016 G3: mode must come from the live tunnel handle, not from config: {status}"
        );
    }

    /// The counter-test: with no tunnel up, there is no endpoint and no mode to
    /// report.
    ///
    /// Without this, "always emit `mode: config.traffic_mode`" would satisfy the
    /// test above on a **disconnected** daemon — reporting a mode and an
    /// endpoint for a tunnel that does not exist. That is the same fabrication
    /// this whole change is about, one branch over.
    #[tokio::test]
    async fn status_reports_no_endpoint_or_mode_when_no_tunnel_is_running() {
        let status = status_with_tunnel(None).await;

        let tunnel = &status["tunnel"];
        assert_eq!(tunnel["active"], false, "{tunnel}");
        assert!(
            tunnel["endpoint"].is_null(),
            "a disconnected daemon has no endpoint; it must not invent one: {status}"
        );
        assert!(
            tunnel["mode"].is_null(),
            "a disconnected daemon has no mode; it must not borrow one from config: {status}"
        );
    }

    /// The key shape must stay stable across both branches.
    ///
    /// A consumer that has to branch on "is `endpoint` present or absent?"
    /// because the key only exists when connected is a consumer that will
    /// eventually render a stale value. Both keys are always present; `null`
    /// means "there is no such thing right now".
    #[tokio::test]
    async fn the_tunnel_object_has_the_same_keys_whether_or_not_a_tunnel_is_up() {
        let connected = status_with_tunnel(Some(crate::daemon::TunnelHandle::new(
            Box::new(LiveTunnel(1)),
            "wg-quick".to_string(),
            "vpn.example.net:51820".to_string(),
            "normal".to_string(),
        )))
        .await;
        let disconnected = status_with_tunnel(None).await;

        let keys = |v: &serde_json::Value| -> Vec<String> {
            let mut k: Vec<String> = v["tunnel"].as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };

        assert_eq!(
            keys(&connected),
            keys(&disconnected),
            "the tunnel object must have a stable shape in both branches"
        );
    }
}
