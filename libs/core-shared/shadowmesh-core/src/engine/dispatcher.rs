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
use std::sync::atomic::Ordering;
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

/// Destination guard for relayed traffic (red-team F25/F26 defense).
///
/// Blocks destinations that would let a relayed client reach the node itself:
/// loopback, link-local (which includes the cloud metadata service
/// 169.254.169.254), and unspecified addresses. Private ranges (RFC1918) are
/// deliberately ALLOWED — reaching a remote LAN through the exit node is a
/// supported product feature. Domain destinations pass: they cannot resolve
/// to node-local addresses without also defeating DNS, and the resolver's
/// own guards apply at dial time.
fn validate_relay_destination(
    destination: &crate::engine::metadata::Endpoint,
) -> std::result::Result<(), &'static str> {
    let ip = match &destination.addr {
        Addr::Ip(ip) => *ip,
        Addr::Domain(_) => return Ok(()),
    };
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Err("loopback address")
            } else if v4.is_link_local() {
                // 169.254.0.0/16 — includes 169.254.169.254 metadata services.
                Err("link-local address (metadata service range)")
            } else if v4.is_unspecified() {
                Err("unspecified address")
            } else {
                Ok(())
            }
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Err("IPv6 loopback address")
            } else if v6.is_unspecified() {
                Err("IPv6 unspecified address")
            } else {
                Ok(())
            }
        }
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
        // Observability: connection duration feeds the latency histogram the
        // Command Center requires for every routing path.
        let started = Instant::now();
        // Step 0: Destination guard — a relayed client must never reach the
        // node itself or its cloud metadata service through the tunnel.
        // RFC1918 stays ALLOWED on purpose: reaching a home LAN through the
        // exit node is a supported product feature, not an SSRF.
        if let Err(reason) = validate_relay_destination(&context.metadata.identity.destination) {
            metrics::counter!("shadowmesh_dispatch_total", "outcome" => "blocked_destination")
                .increment(1);
            info!(
                "Connection {} blocked: destination guard ({})",
                context.metadata.environment.inbound_tag.as_deref().unwrap_or("?"),
                reason
            );
            return Err(anyhow!("destination not allowed: {reason}"));
        }
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
                metrics::counter!("shadowmesh_dispatch_total", "outcome" => "route").increment(1);
                if let Some(outbound) = self.outbounds.get(&tag).await {
                    let mut outbound_stream = outbound.dial_stream(shared_context).await?;
                    let res = copy_bidirectional(&mut inbound_stream, &mut outbound_stream).await;
                    if let Ok((tx, rx)) = res {
                        conn_info.upload_bytes.fetch_add(tx, Ordering::SeqCst);
                        conn_info.download_bytes.fetch_add(rx, Ordering::SeqCst);
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
                metrics::counter!("shadowmesh_dispatch_total", "outcome" => "reject").increment(1);
                info!("Connection {} rejected", id);
                Ok((0, 0))
            }
            _ => {
                metrics::counter!("shadowmesh_dispatch_total", "outcome" => "bypass").increment(1);
                if let Some(outbound) = self.outbounds.get("direct").await {
                    let mut outbound_stream = outbound.dial_stream(shared_context).await?;
                    let res = copy_bidirectional(&mut inbound_stream, &mut outbound_stream).await;
                    if let Ok((tx, rx)) = res {
                        conn_info.upload_bytes.fetch_add(tx, Ordering::SeqCst);
                        conn_info.download_bytes.fetch_add(rx, Ordering::SeqCst);
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
        metrics::histogram!("shadowmesh_connection_duration_secs")
            .record(started.elapsed().as_secs_f64());
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                metrics::counter!("shadowmesh_dispatch_total", "outcome" => "error").increment(1);
                Err(e)
            }
        }
    }

    #[instrument(skip(self, packet))]
    pub async fn dispatch_udp(
        &self,
        mut context: ConnectionContext,
        packet: &[u8],
        source: SocketAddr,
    ) -> Result<Vec<u8>> {
        // Same destination guard as TCP: relayed UDP must not reach the node
        // itself or its metadata service (DNS-to-localhost exfil path).
        if let Err(reason) = validate_relay_destination(&context.metadata.identity.destination) {
            trace!("UDP packet from {} blocked: destination guard ({})", source, reason);
            return Ok(Vec::new());
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::metadata::{Addr, Endpoint};

    fn endpoint(addr: &str) -> Endpoint {
        Endpoint { addr: Addr::Ip(addr.parse().unwrap()), port: 443 }
    }

    #[test]
    fn relay_guard_blocks_node_local_destinations() {
        for blocked in ["127.0.0.1", "0.0.0.0", "169.254.169.254", "169.254.42.42"] {
            assert!(
                validate_relay_destination(&endpoint(blocked)).is_err(),
                "{blocked} must be blocked"
            );
        }
        assert!(
            validate_relay_destination(&endpoint("::1")).is_err(),
            "IPv6 loopback must be blocked"
        );
        assert!(
            validate_relay_destination(&endpoint("::")).is_err(),
            "IPv6 unspecified must be blocked"
        );
    }

    #[test]
    fn relay_guard_allows_lan_and_public() {
        // RFC1918 is a product feature (remote LAN via exit node) — allowed.
        for allowed in ["192.168.1.10", "10.0.0.5", "172.16.0.9", "8.8.8.8", "fd00::1"] {
            assert!(
                validate_relay_destination(&endpoint(allowed)).is_ok(),
                "{allowed} must be allowed"
            );
        }
        // Domains pass the guard (resolver-level controls apply at dial).
        assert!(validate_relay_destination(&Endpoint {
            addr: Addr::Domain("example.com".into()),
            port: 443
        })
        .is_ok());
    }
}
