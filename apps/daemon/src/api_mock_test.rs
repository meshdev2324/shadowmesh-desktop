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
            Ok(VPNConfig {
                private_key: None,
                public_key: "".into(),
                address: "".into(),
                endpoint: "".into(),
                dns: "".into(),
                mtu: 1420,
                traffic_mode: "".into(),
                reality_config: None,
            })
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
}
