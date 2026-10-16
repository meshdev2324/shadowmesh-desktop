use crate::engine::context::SharedContext;
use crate::transport::outbound::registry::OutboundRegistry;
use crate::transport::traits::{AsyncIoStream, OutboundDialer};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub enum SelectionStrategy {
    LoadBalance,
    Latency,
    Fallback,
}

pub struct OutboundGroup {
    tag: String,
    outbounds: Vec<String>,
    strategy: SelectionStrategy,
    registry: Arc<OutboundRegistry>,
    counter: AtomicUsize,
}

impl OutboundGroup {
    pub fn new(
        tag: String,
        outbounds: Vec<String>,
        strategy: SelectionStrategy,
        registry: Arc<OutboundRegistry>,
    ) -> Self {
        Self { tag, outbounds, strategy, registry, counter: AtomicUsize::new(0) }
    }

    async fn select_outbound(&self) -> Result<Arc<dyn OutboundDialer>> {
        match self.strategy {
            SelectionStrategy::Fallback => {
                for tag in &self.outbounds {
                    if let Some(outbound) = self.registry.get(tag).await {
                        return Ok(outbound);
                    }
                }
                Err(anyhow!("No available outbounds in group {}", self.tag))
            }
            SelectionStrategy::LoadBalance => {
                let index = self.counter.fetch_add(1, Ordering::SeqCst) % self.outbounds.len();
                let tag = &self.outbounds[index];
                self.registry.get(tag).await.ok_or_else(|| anyhow!("Outbound {} not found", tag))
            }
            SelectionStrategy::Latency => {
                let tag = self.outbounds.first().ok_or_else(|| anyhow!("Empty outbound group"))?;
                self.registry.get(tag).await.ok_or_else(|| anyhow!("Outbound {} not found", tag))
            }
        }
    }
}

#[async_trait]
impl OutboundDialer for OutboundGroup {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn dial_stream(&self, context: SharedContext) -> Result<Box<dyn AsyncIoStream>> {
        let outbound = self.select_outbound().await?;
        outbound.dial_stream(context).await
    }

    async fn send_packet(
        &self,
        context: SharedContext,
        payload: &[u8],
        source: SocketAddr,
    ) -> Result<Vec<u8>> {
        let outbound = self.select_outbound().await?;
        outbound.send_packet(context, payload, source).await
    }
}
