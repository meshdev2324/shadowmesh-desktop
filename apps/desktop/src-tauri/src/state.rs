use shadowmesh_core::{ApiClient, SecurityEventLogger, TrafficAnalytics};
use std::sync::Arc;

pub struct SessionToken(pub String);

pub struct CoreState {
    pub analytics: Arc<TrafficAnalytics>,
    pub logger: Arc<SecurityEventLogger>,
    pub api_client: Arc<ApiClient>,
}
