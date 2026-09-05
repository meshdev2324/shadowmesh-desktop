use crate::dns::DnsRouter;
use crate::engine::context::ConnectionContext;
use crate::engine::lifecycle::{Service, Stage};
use crate::engine::metadata::Addr;
use crate::engine::process::ProcessSearcher;
use crate::engine::registry::ConnectionRegistry;
use crate::router::engine::RoutingPipeline;
use crate::router::rule::Action;
use crate::transport::traits::AsyncIoStream;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::copy_bidirectional;
use tracing::{info, instrument, trace};

/// Manages UDP sessions with an idle timeout.
pub struct UdpSessionManager {
    sessions: Mutex<HashMap<String, Instant>>,
    timeout: Duration,
}

impl UdpSessionManager {
    pub fn new(timeout_secs: u64) -> Self {
        Self { sessions: Mutex::new(HashMap::new()), timeout: Duration::from_secs(timeout_secs) }
    }

    pub fn get_session_key(source: SocketAddr, destination: SocketAddr) -> String {
        format!("{}-{}", source, destination)
    }

    pub fn update_session(&self, key: String) {
        let mut sessions = self.sessions.lock();
        sessions.insert(key, Instant::now());
    }

    pub fn cleanup(&self) {
        let mut sessions = self.sessions.lock();
        let now = Instant::now();
        sessions.retain(|_, last_seen| now.duration_since(*last_seen) < self.timeout);
    }
}

pub struct Dispatcher {
    registry: Arc<ConnectionRegistry>,
    pipeline: Arc<RoutingPipeline>,
    dns_router: Arc<DnsRouter>,
    outbounds: Arc<crate::transport::outbound::registry::OutboundRegistry>,
    udp_sessions: Arc<UdpSessionManager>,
}

impl Dispatcher {
    pub fn new(
        registry: Arc<ConnectionRegistry>,
        pipeline: Arc<RoutingPipeline>,
        dns_router: Arc<DnsRouter>,
        outbounds: Arc<crate::transport::outbound::registry::OutboundRegistry>,
    ) -> Self {
        Self {
            registry,
            pipeline,
            dns_router,
            outbounds,
            udp_sessions: Arc::new(UdpSessionManager::new(60)),
        }
    }

    pub fn dns_router(&self) -> Arc<DnsRouter> {
        self.dns_router.clone()
    }

    pub fn cleanup_udp_sessions(&self) {
        self.udp_sessions.cleanup();
    }

    #[instrument(skip(self, inbound_stream), fields(conn_id))]
    pub async fn dispatch(
        &self,
        mut context: ConnectionContext,
        mut inbound_stream: Box<dyn AsyncIoStream>,
    ) -> Result<()> {
        // Step 1: Registry
        let conn_info = self.registry.register(context.metadata.clone());
        let id = conn_info.id;
        tracing::Span::current().record("conn_id", id);

        // Step 2: Metadata Enrichment
        self.enrich_metadata(&mut context).await?;

        // Step 3: Routing
        let action = self.pipeline.route(&mut context).await?;
        let shared_context = Arc::new(Mutex::new(context));

        let result = match action {
            Action::Route(tag) => {
                if let Some(outbound) = self.outbounds.get(&tag).await {
                    let mut outbound_stream = outbound.dial_stream(shared_context).await?;
                    let res = copy_bidirectional(&mut inbound_stream, &mut outbound_stream).await;
                    if let Ok((tx, rx)) = res {
                        info!(
                            "Connection {} finished: {} bytes sent, {} bytes received",
                            id, tx, rx
                        );
                    }
                    res.map_err(|e| anyhow!(e))
                } else {
                    Err(anyhow!("Outbound {} not found", tag))
                }
            }
            Action::Reject => {
                info!("Connection {} rejected", id);
                Ok((0, 0))
            }
            _ => {
                if let Some(outbound) = self.outbounds.get("direct").await {
                    let mut outbound_stream = outbound.dial_stream(shared_context).await?;
                    let res = copy_bidirectional(&mut inbound_stream, &mut outbound_stream).await;
                    if let Ok((tx, rx)) = res {
                        info!(
                            "Connection {} finished (bypass): {} bytes sent, {} bytes received",
                            id, tx, rx
                        );
                    }
                    res.map_err(|e| anyhow!(e))
                } else {
                    Err(anyhow!("Default outbound 'direct' not found"))
                }
            }
        };

        // Step 4: Cleanup
        self.registry.remove(id);

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    #[instrument(skip(self, packet))]
    pub async fn dispatch_udp(
        &self,
        mut context: ConnectionContext,
        packet: &[u8],
        source: SocketAddr,
    ) -> Result<Vec<u8>> {
        // Step 2: Metadata Enrichment
        self.enrich_metadata(&mut context).await?;

        // Step 3: Routing
        let action = self.pipeline.route(&mut context).await?;
        let shared_context = Arc::new(Mutex::new(context));

        let dest = {
            let ctx = shared_context.lock();
            match &ctx.metadata.identity.destination.addr {
                Addr::Ip(ip) => SocketAddr::new(*ip, ctx.metadata.identity.destination.port),
                _ => return Err(anyhow!("UDP destination IP missing or not an IP")),
            }
        };

        let session_key = UdpSessionManager::get_session_key(source, dest);
        self.udp_sessions.update_session(session_key);

        match action {
            Action::Route(tag) => {
                if let Some(outbound) = self.outbounds.get(&tag).await {
                    // RFC-012 G2: send_packet returns the upstream reply (or
                    // empty for fire-and-forget transports); the caller routes
                    // it back to the UDP client.
                    outbound.send_packet(shared_context, packet, source).await
                } else {
                    Err(anyhow!("Outbound {} not found", tag))
                }
            }
            Action::Reject => {
                trace!("UDP Packet from {} rejected", source);
                Ok(Vec::new())
            }
            _ => {
                if let Some(outbound) = self.outbounds.get("direct").await {
                    outbound.send_packet(shared_context, packet, source).await
                } else {
                    Err(anyhow!("Default outbound 'direct' not found"))
                }
            }
        }
    }

    async fn enrich_metadata(&self, context: &mut ConnectionContext) -> Result<()> {
        // Reverse DNS lookup if IP is present but domain is not
        if let Addr::Ip(ip) = &context.metadata.identity.destination.addr {
            if let Some(domain) = self.dns_router.lookup_reverse(*ip).await {
                context.metadata.identity.destination.addr = Addr::Domain(domain);
            }
        }

        // Process discovery
        if context.metadata.identity.process_name.is_none() {
            if let Some(source) = &context.metadata.identity.source {
                if let Some(process_info) = ProcessSearcher::find_process_info(source.port) {
                    context.metadata.identity.process_name = Some(process_info.name);
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Service for Dispatcher {
    fn name(&self) -> &str {
        "dispatcher"
    }

    async fn stage_change(&self, _stage: Stage) -> Result<()> {
        Ok(())
    }
}
