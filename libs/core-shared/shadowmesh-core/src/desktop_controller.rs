use crate::api_client::ApiClient;
use crate::vpn_manager::VPNManager;
use crate::ShadowMeshError;
use std::sync::Arc;
use tracing::info;

/**
 * Platform-agnostic controller for Desktop environments.
 * SOP 09 §4: Orchestrates high-fidelity desktop logic (Windows/Linux/macOS).
 */
pub struct DesktopController {
    api_client: Arc<ApiClient>,
    vpn_manager: Arc<VPNManager>,
}

impl DesktopController {
    /// Creates a new `DesktopController` with the provided dependencies.
    pub fn new(api_client: Arc<ApiClient>, vpn_manager: Arc<VPNManager>) -> Self {
        Self { api_client, vpn_manager }
    }

    /// Horizon 4: Authenticates a device as a team member.
    pub fn authenticate_member(&self, member_token: String) -> Result<(), ShadowMeshError> {
        let rt = crate::api_client::get_runtime()?;
        rt.block_on(self.authenticate_member_async(member_token))
    }

    async fn authenticate_member_async(&self, member_token: String) -> Result<(), ShadowMeshError> {
        info!("Desktop: Initiating Team Member Authentication");

        // 1. Get challenge
        let device_id = crate::vpn_manager::get_persistent_device_id();
        let challenge = self.api_client.request_activation_challenge_async(device_id).await?;

        // 2. Solve PoW
        let _solution = crate::pow::solve_pow(challenge.challenge, challenge.difficulty)?;

        // 3. Activate using member token as 'code'
        let req = crate::api_client::ActivationRequest {
            code: member_token,
            device_name: "Desktop Mesh Node".into(),
            device_type: "desktop".into(),
            device_id: crate::vpn_manager::get_persistent_device_id(),
            hardware_fingerprint: "desktop-hard-fp".into(),
            public_key: None,
            deep_fingerprint: None,
            oob_nonce: None,
            oob_sig: None,
            oob_ts: None,
        };

        let response = self.api_client.activate_async(req).await?;

        if let Some(token) = response.token {
            self.api_client.set_auth_token(Some(token.clone()));
            self.vpn_manager.activate(
                response.message,
                Some(token),
                response.plan,
                response.devices_remaining,
                response.remaining_days,
            )?;
            info!("Desktop: Team Member Authentication successful");
            Ok(())
        } else {
            Err(ShadowMeshError::Unauthorized(response.message))
        }
    }

    /// Horizon 4: Generates a new member token for a team admin.
    pub fn create_member_token(&self, label: String) -> Result<String, ShadowMeshError> {
        let rt = crate::api_client::get_runtime()?;
        rt.block_on(self.api_client.generate_member_token_async(label))
    }
}
