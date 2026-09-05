use shadowmesh_core::{
    ActivationChallenge, ActivationRequest, ActivationResponse, ApiClient, HealthStatus,
    HeartbeatRequest, HeartbeatResponse, IdentityInfo, ShadowMeshError, VPNConfig, VPNNode,
};
use std::sync::Arc;

#[async_trait::async_trait]
pub trait ShadowApi: Send + Sync {
    async fn request_activation_challenge(
        &self,
        device_id: String,
    ) -> Result<ActivationChallenge, ShadowMeshError>;
    async fn activate(&self, req: ActivationRequest)
    -> Result<ActivationResponse, ShadowMeshError>;
    async fn get_nodes(&self) -> Result<Vec<VPNNode>, ShadowMeshError>;
    async fn get_config(
        &self,
        node_id: String,
        public_key: String,
        mode: Option<String>,
    ) -> Result<VPNConfig, ShadowMeshError>;
    async fn heartbeat(&self, req: HeartbeatRequest) -> Result<HeartbeatResponse, ShadowMeshError>;
    async fn get_identity_info(&self) -> Result<IdentityInfo, ShadowMeshError>;
    async fn qr_generate(
        &self,
        device_id: String,
        device_name: String,
        os_name: String,
        os_version: String,
        arch: String,
    ) -> Result<String, ShadowMeshError>;
    async fn qr_status(&self, token: String) -> Result<String, ShadowMeshError>;
    async fn check_health(&self) -> Result<HealthStatus, ShadowMeshError>;
    async fn report_compromised(
        &self,
        device_id: String,
        reason: String,
    ) -> Result<(), ShadowMeshError>;
    async fn ping_gateway(&self) -> Result<bool, ShadowMeshError>;
    fn set_auth_token(&self, token: Option<String>);
    fn set_pow_solution(&self, solution: String, original_challenge: String);
    fn set_device_id(&self, device_id: String);
    fn get_core_client(&self) -> Arc<ApiClient>;
}

pub struct CoreApiWrapper {
    inner: Arc<ApiClient>,
}

impl CoreApiWrapper {
    pub fn new(inner: Arc<ApiClient>) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl ShadowApi for CoreApiWrapper {
    async fn request_activation_challenge(
        &self,
        device_id: String,
    ) -> Result<ActivationChallenge, ShadowMeshError> {
        self.inner.request_activation_challenge_async(device_id).await
    }
    async fn activate(
        &self,
        req: ActivationRequest,
    ) -> Result<ActivationResponse, ShadowMeshError> {
        self.inner.activate_async(req).await
    }
    async fn get_nodes(&self) -> Result<Vec<VPNNode>, ShadowMeshError> {
        self.inner.get_nodes_async().await
    }
    async fn get_config(
        &self,
        node_id: String,
        public_key: String,
        mode: Option<String>,
    ) -> Result<VPNConfig, ShadowMeshError> {
        self.inner.get_config_async(node_id, public_key, mode).await
    }
    async fn heartbeat(&self, req: HeartbeatRequest) -> Result<HeartbeatResponse, ShadowMeshError> {
        self.inner.heartbeat_async(req).await
    }
    async fn get_identity_info(&self) -> Result<IdentityInfo, ShadowMeshError> {
        self.inner.get_identity_info_async().await
    }
    async fn qr_generate(
        &self,
        device_id: String,
        device_name: String,
        os_name: String,
        os_version: String,
        arch: String,
    ) -> Result<String, ShadowMeshError> {
        self.inner.qr_generate_async(device_id, device_name, os_name, os_version, arch).await
    }
    async fn qr_status(&self, token: String) -> Result<String, ShadowMeshError> {
        self.inner.qr_status_async(token).await
    }
    async fn check_health(&self) -> Result<HealthStatus, ShadowMeshError> {
        self.inner.check_health_async().await
    }
    async fn report_compromised(
        &self,
        device_id: String,
        reason: String,
    ) -> Result<(), ShadowMeshError> {
        self.inner.report_compromised_async(device_id, reason).await
    }
    async fn ping_gateway(&self) -> Result<bool, ShadowMeshError> {
        self.inner.ping_gateway_async().await
    }
    fn set_auth_token(&self, token: Option<String>) {
        self.inner.set_auth_token(token);
    }
    fn set_pow_solution(&self, solution: String, original_challenge: String) {
        self.inner.set_pow_solution(solution, original_challenge);
    }
    fn set_device_id(&self, device_id: String) {
        self.inner.set_device_id(device_id);
    }
    fn get_core_client(&self) -> Arc<ApiClient> {
        self.inner.clone()
    }
}
