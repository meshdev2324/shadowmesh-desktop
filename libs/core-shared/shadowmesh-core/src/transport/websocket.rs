use super::{AsyncTransport, TransportType};
use crate::ShadowMeshError;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::Mutex;
use tracing::info;

/// WebSocket-based transport implementation for CDN fallback.
///
/// RFC-004: Utilizes WebSocket over TLS 1.3 to bypass aggressive DPI.
/// Can be routed through major CDNs (Cloudflare, CloudFront) to camouflage traffic.
#[derive(Debug)]
pub struct WebSocketTransport {
    server_url: String,
    host_header: String,
    is_connected: Mutex<bool>,
}

impl WebSocketTransport {
    /// Creates a new `WebSocketTransport`.
    pub fn new(server_url: String, host_header: String) -> Self {
        Self { server_url, host_header, is_connected: Mutex::new(false) }
    }
}

#[async_trait]
impl AsyncTransport for WebSocketTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::WebSocket
    }

    async fn connect(&self) -> Result<(), ShadowMeshError> {
        info!(
            "🌐 Connecting to CDN Fallback (WebSocket): {} (Host: {})",
            self.server_url, self.host_header
        );

        // Phase 1 implementation: Mock connection success.
        // In Phase 2, this will use tokio-tungstenite or reqwest-websocket.
        *self.is_connected.lock().await = true;
        Ok(())
    }

    async fn send(&self, _data: Bytes) -> Result<(), ShadowMeshError> {
        if !*self.is_connected.lock().await {
            return Err(ShadowMeshError::Other("WebSocket not connected".into()));
        }
        // Send data over WebSocket...
        Ok(())
    }

    async fn recv(&self) -> Result<Bytes, ShadowMeshError> {
        if !*self.is_connected.lock().await {
            return Err(ShadowMeshError::Other("WebSocket not connected".into()));
        }
        // Receive data from WebSocket...
        // For now, return empty or wait
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(Bytes::new())
    }

    async fn close(&self) -> Result<(), ShadowMeshError> {
        *self.is_connected.lock().await = false;
        Ok(())
    }
}
