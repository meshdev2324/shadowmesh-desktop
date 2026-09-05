use crate::engine::context::SharedContext;
use crate::transport::traits::{AsyncIoStream, OutboundDialer};
use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, trace};

/// How long a direct UDP reply wait may block before giving up (RFC-012 G2).
const UDP_REPLY_TIMEOUT_MS: u64 = 2000;

pub struct DirectOutbound {
    tag: String,
}

impl DirectOutbound {
    pub fn new(tag: String) -> Self {
        Self { tag }
    }
}

#[async_trait]
impl OutboundDialer for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, context: SharedContext) -> Result<Box<dyn AsyncIoStream>> {
        let destination = {
            let ctx = context.lock();
            ctx.metadata.identity.destination.clone()
        };

        debug!("Direct outbound [{}] connecting to {}", self.tag, destination);

        let outbound_stream = TcpStream::connect(destination.to_string()).await?;
        Ok(Box::new(outbound_stream))
    }

    async fn send_packet(
        &self,
        context: SharedContext,
        packet: &[u8],
        _source: SocketAddr,
    ) -> Result<Vec<u8>> {
        let destination = {
            let ctx = context.lock();
            ctx.metadata.identity.destination.clone()
        };

        trace!("Direct UDP outbound [{}] sending to {}", self.tag, destination);

        let dest: SocketAddr = match &destination.addr {
            crate::engine::metadata::Addr::Ip(ip) => SocketAddr::new(*ip, destination.port),
            // Domain destinations were resolved upstream; an unresolved
            // domain here is a routing error, not something to resolve ad hoc
            // (would bypass the DNS policy layer).
            crate::engine::metadata::Addr::Domain(_) => {
                anyhow::bail!("Direct UDP requires a resolved IP destination")
            }
        };

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(packet, dest).await?;

        // RFC-012 G2: bounded reply wait. Empty reply = fire-and-forget
        // semantics preserved for one-way protocols.
        let mut buf = [0u8; 65535];
        match tokio::time::timeout(
            std::time::Duration::from_millis(UDP_REPLY_TIMEOUT_MS),
            socket.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((n, _peer))) => Ok(buf[..n].to_vec()),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Ok(Vec::new()),
        }
    }
}
