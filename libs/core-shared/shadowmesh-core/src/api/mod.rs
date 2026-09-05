use crate::engine::registry::ConnectionRegistry;
use std::sync::Arc;
use std::time::Instant;
use tonic::{transport::Server, Request, Response, Status};
use tracing::info;

pub mod shadowmesh_proto {
    tonic::include_proto!("shadowmesh");
}

pub use shadowmesh_proto::shadow_mesh_control_server::{
    ShadowMeshControl, ShadowMeshControlServer,
};
pub use shadowmesh_proto::{Empty, ReloadResponse, StatsResponse, StatusResponse};

pub struct ControlApi {
    registry: Arc<ConnectionRegistry>,
    start_time: Instant,
}

impl ControlApi {
    pub fn new(registry: Arc<ConnectionRegistry>) -> Self {
        Self { registry, start_time: Instant::now() }
    }

    pub async fn start(&self, addr: &str) -> anyhow::Result<()> {
        let addr = addr.parse()?;
        let service =
            ControlApiImpl { registry: self.registry.clone(), start_time: self.start_time };

        info!("Control API listening on {}", addr);

        tokio::spawn(async move {
            if let Err(e) = Server::builder()
                .add_service(ShadowMeshControlServer::new(service))
                .serve(addr)
                .await
            {
                tracing::error!("Control API server failed: {:?}", e);
            }
        });

        Ok(())
    }
}

#[derive(Clone)]
struct ControlApiImpl {
    registry: Arc<ConnectionRegistry>,
    start_time: Instant,
}

#[tonic::async_trait]
impl ShadowMeshControl for ControlApiImpl {
    async fn get_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<StatusResponse>, Status> {
        Ok(Response::new(StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: self.start_time.elapsed().as_secs(),
        }))
    }

    async fn get_stats(&self, _request: Request<Empty>) -> Result<Response<StatsResponse>, Status> {
        let (active, up, down) = self.registry.get_stats();
        Ok(Response::new(StatsResponse {
            active_connections: active,
            total_upload: up,
            total_download: down,
        }))
    }

    async fn reload_config(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ReloadResponse>, Status> {
        Ok(Response::new(ReloadResponse {
            success: true,
            message: "Reload triggered (scaffold)".to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::metadata::{ConnectionMetadata, Endpoint, L4Protocol};
    use crate::engine::registry::ConnectionRegistry;

    #[tokio::test]
    async fn test_api_stats() {
        let registry = Arc::new(ConnectionRegistry::new());
        let api = ControlApiImpl { registry: registry.clone(), start_time: Instant::now() };

        let dest = Endpoint::new_ip("8.8.8.8".parse().unwrap(), 53);
        let mut metadata = ConnectionMetadata::new(dest);
        metadata.identity.source = Some(Endpoint::new_ip("127.0.0.1".parse().unwrap(), 12345));
        metadata.l4_protocol = L4Protocol::Udp;
        metadata.environment.inbound_tag = Some("test".to_string());

        let conn = registry.register(metadata);
        use std::sync::atomic::Ordering;
        conn.upload_bytes.fetch_add(100, Ordering::SeqCst);
        conn.download_bytes.fetch_add(200, Ordering::SeqCst);

        let response = api.get_stats(Request::new(Empty {})).await.unwrap();
        let stats = response.into_inner();

        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.total_upload, 100);
        assert_eq!(stats.total_download, 200);

        registry.remove(conn.id);
        let response2 = api.get_stats(Request::new(Empty {})).await.unwrap();
        let stats2 = response2.into_inner();
        assert_eq!(stats2.active_connections, 0);
        assert_eq!(stats2.total_upload, 100);
        assert_eq!(stats2.total_download, 200);
    }
}
