use crate::engine::context::ConnectionContext;
use crate::engine::metadata::{ConnectionMetadata, Endpoint, L4Protocol};
use crate::engine::{events::EngineEvent, EngineHandle};
use crate::transport::traits::InboundListener;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
/// Implementation Source:
/// - RFC / specification: RFC 7230 (HTTP/1.1 Syntax), RFC 7231 (Semantics)
/// - Relevant sections: RFC 7230 §3.1.1 (Request Line), RFC 7231 §4.3.6 (CONNECT)
/// - Security considerations: Request smuggling resistance, resource limits for header parsing.
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;

/// HTTP Inbound handler supporting CONNECT and standard proxy requests.
pub struct HttpInbound {
    tag: String,
    listen_addr: String,
    engine: EngineHandle,
}

impl HttpInbound {
    pub fn new(tag: String, listen_addr: String, engine: EngineHandle) -> Self {
        Self { tag, listen_addr, engine }
    }

    async fn handle_connection(
        engine: EngineHandle,
        tag: String,
        mut stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let mut buf = [0u8; 8192]; // Increased buffer for headers (RFC 7230 §3.1.1)
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        let status = req.parse(&buf[..n]).map_err(|e| anyhow!("HTTP parsing error: {:?}", e))?;

        if !status.is_complete() {
            return Err(anyhow!("Incomplete HTTP headers"));
        }

        let method = req.method.ok_or_else(|| anyhow!("Missing HTTP method"))?;
        let path = req.path.ok_or_else(|| anyhow!("Missing HTTP path"))?;

        let destination = if method.to_uppercase() == "CONNECT" {
            let parts: Vec<&str> = path.split(':').collect();
            if parts.len() != 2 {
                return Err(anyhow!("Invalid CONNECT target: {}", path));
            }
            Endpoint::new_domain(parts[0].to_string(), parts[1].parse()?)
        } else {
            let url = url::Url::parse(path).map_err(|_| anyhow!("Invalid Proxy URI: {}", path))?;
            let host = url.host_str().ok_or_else(|| anyhow!("Missing Proxy Host"))?;
            let port = url.port_or_known_default().ok_or_else(|| anyhow!("Missing Proxy Port"))?;
            Endpoint::new_domain(host.to_string(), port)
        };

        let mut metadata = ConnectionMetadata::new(destination);
        metadata.l4_protocol = L4Protocol::Tcp;
        metadata.identity.source = Some(Endpoint::from(peer_addr));
        metadata.environment.inbound_tag = Some(tag);

        if method.to_uppercase() == "CONNECT" {
            // RFC 7231 §4.3.6: Successful CONNECT response
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

            let context = Arc::new(Mutex::new(ConnectionContext::new(metadata)));
            engine.send_event(EngineEvent::NewStream { context, stream: Box::new(stream) }).await?;
        } else {
            let context = Arc::new(Mutex::new(ConnectionContext::new(metadata)));
            // v6.9.3: PrefixedStream allows re-injecting the already-read HTTP headers into the tunnel
            let prefixed_stream = PrefixedStream::new(buf[..n].to_vec(), stream);
            engine
                .send_event(EngineEvent::NewStream { context, stream: Box::new(prefixed_stream) })
                .await?;
        }

        Ok(())
    }
}

#[async_trait]
impl InboundListener for HttpInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        tracing::info!("HTTP inbound [{}] listening on {}", self.tag, self.listen_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let engine = self.engine.clone();
            let tag = self.tag.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(engine, tag, stream, addr).await {
                    tracing::error!("HTTP connection error: {:?}", e);
                }
            });
        }
    }
}

/// A stream wrapper that emits a prefix buffer before proxying to the inner stream.
pub struct PrefixedStream<S> {
    prefix: Option<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix: Some(prefix), inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(mut prefix) = self.prefix.take() {
            let n = std::cmp::min(prefix.len(), buf.remaining());
            buf.put_slice(&prefix[..n]);
            if n < prefix.len() {
                self.prefix = Some(prefix.split_off(n));
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
