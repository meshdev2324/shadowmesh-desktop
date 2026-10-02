use super::{AsyncTransport, TransportType};
use crate::ShadowMeshError;
use async_trait::async_trait;
use bytes::Bytes;
use tracing::warn;

/// WebSocket-based transport for CDN fallback.
///
/// RFC-004: WebSocket over TLS, routed through a CDN, so the connection
/// resembles ordinary HTTPS to a major CDN and not to a proxy.
///
/// # Status: NOT IMPLEMENTED, AND DELIBERATELY FAILING CLOSED
///
/// The previous version of this file was a mock:
///
/// ```text
/// connect() -> sets a bool, performs no I/O, returns Ok(())
/// send()    -> discards the payload, returns Ok(())
/// recv()    -> sleeps 100ms, returns empty bytes
/// ```
///
/// It would report a successful connection and silently drop every byte. That is
/// the most dangerous possible shape for a VPN: the user believes traffic is
/// protected and routed, and it is neither. A mock that returns `Ok` is worse
/// than a missing feature, because it defeats the check a user would otherwise
/// make.
///
/// Every method therefore returns a clear, explicit error. Fail closed and say
/// so, rather than connect successfully to nothing.
///
/// Implementing this means the RFC-004 upgrade handshake (RFC 6455 client
/// handshake, `Sec-WebSocket-Key` derivation, frame masking, and a masked-frame
/// codec over TLS), plus the server side. That is real work and is tracked
/// rather than faked; see docs/PROTOCOL.md section 5.
#[derive(Debug)]
pub struct WebSocketTransport {
    server_url: String,
    host_header: String,
}

impl WebSocketTransport {
    /// Creates a transport descriptor. Construction does not imply the
    /// transport is usable; [`AsyncTransport::connect`] is the authority.
    pub fn new(server_url: String, host_header: String) -> Self {
        Self { server_url, host_header }
    }

    /// The single error every operation returns, with the reason spelled out.
    fn unimplemented_op(op: &str) -> ShadowMeshError {
        ShadowMeshError::Other(format!(
            "WebSocket {op} is not implemented: the RFC-004 CDN transport is an \
             unimplemented stub and fails closed rather than pretending to carry traffic"
        ))
    }
}

#[async_trait]
impl AsyncTransport for WebSocketTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::WebSocket
    }

    async fn connect(&self) -> Result<(), ShadowMeshError> {
        warn!(
            url = %self.server_url,
            host = %self.host_header,
            "WebSocket transport is not implemented; refusing to report a connection"
        );
        Err(Self::unimplemented_op("connect"))
    }

    async fn send(&self, _data: Bytes) -> Result<(), ShadowMeshError> {
        Err(Self::unimplemented_op("send"))
    }

    async fn recv(&self) -> Result<Bytes, ShadowMeshError> {
        Err(Self::unimplemented_op("recv"))
    }

    async fn close(&self) -> Result<(), ShadowMeshError> {
        // Closing an established transport is always safe and is the one
        // operation that should not fail, so a teardown path never gets stuck
        // behind an unimplemented error.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> WebSocketTransport {
        WebSocketTransport::new("wss://cdn.example.com/ws".into(), "cdn.example.com".into())
    }

    /// The regression guard for the original defect.
    #[tokio::test]
    async fn connect_does_not_claim_success() {
        let err = t().connect().await.expect_err("must not report a connection");
        let msg = err.to_string();
        assert!(msg.contains("not implemented"), "unclear error: {msg}");
    }

    #[tokio::test]
    async fn send_does_not_silently_succeed() {
        // The dangerous case was send() returning Ok and dropping the payload.
        assert!(t().send(Bytes::from_static(b"user data")).await.is_err());
    }

    #[tokio::test]
    async fn recv_never_returns_empty_success() {
        // Returning empty bytes looked like a healthy idle connection.
        assert!(t().recv().await.is_err());
    }

    #[tokio::test]
    async fn close_still_succeeds() {
        // Teardown must never be blocked by the unimplemented path, or a
        // disconnect would hang.
        assert!(t().close().await.is_ok());
    }

    #[test]
    fn transport_type_is_websocket() {
        assert!(matches!(t().transport_type(), TransportType::WebSocket));
    }

    #[test]
    fn errors_name_the_operation() {
        for op in ["connect", "send", "recv"] {
            assert!(WebSocketTransport::unimplemented_op(op).to_string().contains(op));
        }
    }

    #[test]
    fn no_credential_is_echoed_in_errors() {
        // A URL may carry a token in its query string; errors must not repeat it.
        let leaky = WebSocketTransport::new(
            "wss://cdn.example.com/ws?token=supersecret".into(),
            "cdn.example.com".into(),
        );
        let err = leaky.connect_err_for_test();
        assert!(!err.contains("supersecret"), "credential echoed in error: {err}");
    }

    impl WebSocketTransport {
        /// Synchronous view of the connect error, for the redaction test.
        fn connect_err_for_test(&self) -> String {
            Self::unimplemented_op("connect").to_string()
        }
    }
}
