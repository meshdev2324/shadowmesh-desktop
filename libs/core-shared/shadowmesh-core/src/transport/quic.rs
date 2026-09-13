use super::{AsyncTransport, TransportType};
use crate::ShadowMeshError;
use async_trait::async_trait;
use bytes::Bytes;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Hysteria-inspired high-performance QUIC transport implementation.
///
/// Utilizes the `quinn` crate for a robust QUIC implementation and optimizes
/// for high-loss networks via aggressive congestion control (simulated).
#[derive(Debug)]
pub struct QuicTransport {
    remote_addr: SocketAddr,
    connection: Mutex<Option<Connection>>,
    send_stream: Mutex<Option<SendStream>>,
    recv_stream: Mutex<Option<RecvStream>>,
}

impl QuicTransport {
    /// Creates a new `QuicTransport` for the specified remote address.
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            connection: Mutex::new(None),
            send_stream: Mutex::new(None),
            recv_stream: Mutex::new(None),
        }
    }

    /// Internal helper to configure the QUIC client.
    fn make_client_config() -> Result<quinn::ClientConfig, ShadowMeshError> {
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        // v5.1: Zero-Panic - utilize try_from if possible or defensive configuration
        Ok(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| ShadowMeshError::Other(e.to_string()))?,
        )))
    }
}

#[async_trait]
impl AsyncTransport for QuicTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Quic
    }

    async fn connect(&self) -> Result<(), ShadowMeshError> {
        let bind_addr: SocketAddr = "0.0.0.0:0"
            .parse()
            .map_err(|_| ShadowMeshError::IoError("Failed to parse local bind address".into()))?;

        let mut endpoint =
            Endpoint::client(bind_addr).map_err(|e| ShadowMeshError::IoError(e.to_string()))?;

        endpoint.set_default_client_config(Self::make_client_config()?);

        let connecting = endpoint
            .connect(self.remote_addr, "localhost")
            .map_err(|_| ShadowMeshError::ConnectionFailed)?;

        let connection = connecting.await.map_err(|_| ShadowMeshError::ConnectionFailed)?;

        // Bi-directional stream for tunnel traffic
        let (send, recv) =
            connection.open_bi().await.map_err(|_| ShadowMeshError::ConnectionFailed)?;

        *self.connection.lock().await = Some(connection);
        *self.send_stream.lock().await = Some(send);
        *self.recv_stream.lock().await = Some(recv);

        Ok(())
    }

    async fn send(&self, data: Bytes) -> Result<(), ShadowMeshError> {
        let mut guard = self.send_stream.lock().await;
        if let Some(ref mut stream) = *guard {
            stream.write_all(&data).await.map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
            Ok(())
        } else {
            Err(ShadowMeshError::Other("Not connected".into()))
        }
    }

    async fn recv(&self) -> Result<Bytes, ShadowMeshError> {
        let mut guard = self.recv_stream.lock().await;
        if let Some(ref mut stream) = *guard {
            // v5.1: High Performance - Use fixed size buffer or dynamic based on MTU
            let mut buf = vec![0u8; 2048];
            let n = stream
                .read(&mut buf)
                .await
                .map_err(|e| ShadowMeshError::IoError(e.to_string()))?
                .ok_or(ShadowMeshError::Other("EOF".into()))?;

            buf.truncate(n);
            Ok(Bytes::from(buf))
        } else {
            Err(ShadowMeshError::Other("Not connected".into()))
        }
    }

    async fn close(&self) -> Result<(), ShadowMeshError> {
        if let Some(conn) = self.connection.lock().await.take() {
            conn.close(0u32.into(), b"Closing transport");
        }
        Ok(())
    }
}
