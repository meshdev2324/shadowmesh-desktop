use crate::engine::context::SharedContext;
use crate::transport::traits::{AsyncIoStream, OutboundDialer};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::net::SocketAddr;

pub struct HysteriaOutbound {
    pub tag: String,
}

#[async_trait]
impl OutboundDialer for HysteriaOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, _context: SharedContext) -> Result<Box<dyn AsyncIoStream>> {
        Err(anyhow!("Not implemented"))
    }

    async fn send_packet(
        &self,
        _context: SharedContext,
        _payload: &[u8],
        _source: SocketAddr,
    ) -> Result<Vec<u8>> {
        Err(anyhow!("Not implemented"))
    }
}
