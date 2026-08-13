use crate::ShadowMeshError;
use async_trait::async_trait;
use bytes::Bytes;
use std::fmt::Debug;

/// Hysteria-inspired high-performance QUIC transport implementation.
pub mod quic;

use std::sync::Arc;
use tokio::sync::RwLock;

/// Manages an active transport and provides failover capabilities.
#[derive(Debug, Default)]
pub struct TransportStack {
    active_transport: Arc<RwLock<Option<Box<dyn AsyncTransport>>>>,
}

impl TransportStack {
    /// Hot-swaps the current transport with a new one.
    pub async fn swap(&self, new_transport: Box<dyn AsyncTransport>) {
        let mut guard = self.active_transport.write().await;
        if let Some(old) = guard.take() {
            let _ = old.close().await;
        }
        *guard = Some(new_transport);
    }

    /// Sends data via the active transport.
    pub async fn send(&self, data: Bytes) -> Result<(), ShadowMeshError> {
        let guard = self.active_transport.read().await;
        if let Some(ref t) = *guard {
            t.send(data).await
        } else {
            Err(ShadowMeshError::Other("No active transport".into()))
        }
    }

    /// Receives data via the active transport.
    pub async fn recv(&self) -> Result<Bytes, ShadowMeshError> {
        let guard = self.active_transport.read().await;
        if let Some(ref t) = *guard {
            t.recv().await
        } else {
            Err(ShadowMeshError::Other("No active transport".into()))
        }
    }
}

/// Represents the possible transport protocols for the ShadowMesh tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// Standard WireGuard UDP transport.
    WireGuard,
    /// REALITY forensic-resistant transport.
    Reality,
    /// Hysteria-inspired high-performance QUIC transport.
    Quic,
}

/// A common interface for asynchronous network transports.
///
/// All transports must implement this trait to be utilized by the `TransportStack`.
#[async_trait]
pub trait AsyncTransport: Send + Sync + Debug {
    /// Returns the type of this transport.
    fn transport_type(&self) -> TransportType;

    /// Attempts to establish the transport connection to the remote endpoint.
    async fn connect(&self) -> Result<(), ShadowMeshError>;

    /// Sends a packet via the transport.
    async fn send(&self, data: Bytes) -> Result<(), ShadowMeshError>;

    /// Receives a packet from the transport.
    async fn recv(&self) -> Result<Bytes, ShadowMeshError>;

    /// Gracefully closes the transport connection.
    async fn close(&self) -> Result<(), ShadowMeshError>;
}
