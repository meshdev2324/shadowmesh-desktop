use crate::dns::DnsRouter;
use crate::engine::context::ConnectionContext;
use crate::engine::lifecycle::{Service, Stage};
use crate::engine::metadata::Addr;
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

        // Process discovery. The policy -- *whether* a local lookup means
        // anything here at all -- lives in `attribute_process_identity`; this
        // only records the outcome so an operator can see inbound attribution
        // is now (correctly) absent instead of silently missing.
        let inbound_tag = context.metadata.environment.inbound_tag.clone();
        let attribution =
            crate::engine::process::attribute_process_identity(&mut context.metadata.identity)
                .await;
        metrics::counter!("shadowmesh_process_attribution_total", "outcome" => attribution.label())
            .increment(1);
        if attribution.is_remote_peer() {
            // ZPII: the inbound tag is operator configuration; the peer's
            // address and port are not logged anywhere on this path.
            trace!(
                "No process attribution for inbound [{}]: source is a remote peer",
                inbound_tag.as_deref().unwrap_or("?")
            );
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
    use crate::engine::metadata::{Addr, Endpoint, SourceOrigin};
    use crate::engine::process::ProcessSearcher;
    use crate::engine::registry::ConnectionRegistry;

    fn endpoint(addr: &str) -> Endpoint {
        Endpoint { addr: Addr::Ip(addr.parse().unwrap()), port: 443 }
    }

    fn test_dispatcher() -> Dispatcher {
        Dispatcher::new(
            Arc::new(ConnectionRegistry::new()),
            Arc::new(RoutingPipeline::new(vec![])),
            Arc::new(crate::dns::DnsRouter::new(vec![], crate::dns::ExecutionModel::Serial)),
            Arc::new(crate::transport::outbound::registry::OutboundRegistry::new()),
        )
    }

    /// A local TCP listener that stays bound for the duration of the test, so
    /// its port really does resolve to this process through
    /// `/proc/net/tcp{,6}`.
    ///
    /// TCP rather than UDP because the lookup only ever reads
    /// `/proc/net/tcp{,6}`; a UDP listener is invisible to it.
    fn local_listener() -> std::net::TcpListener {
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind local tcp listener")
    }

    /// TEST-NET-3 (RFC 5737): guaranteed never to be a local interface, so a
    /// peer endpoint built from it can only be an inbound peer's address.
    const REMOTE_PEER: &str = "203.0.113.7";

    /// The defect: an inbound peer whose ephemeral source port happens to equal
    /// a local listener's port was labelled with that listener's process name.
    ///
    /// The port used here is a live local listener, and the precondition below
    /// proves the collision is real -- without it the test would pass for the
    /// wrong reason (nothing to resolve) and prove nothing.
    #[tokio::test]
    async fn inbound_peer_is_never_named_after_a_colliding_local_listener() {
        let listener = local_listener();
        let local_port = listener.local_addr().expect("listener addr").port();

        let collision_is_real = ProcessSearcher::find_process_info(local_port).await;
        assert!(
            collision_is_real.is_some(),
            "port {local_port} must resolve to a local process, otherwise this \
             test would pass without exercising the collision it is about"
        );

        let mut context = ConnectionContext::new(crate::engine::metadata::ConnectionMetadata::new(
            endpoint("198.51.100.9"),
        ));
        context.metadata.environment.inbound_tag = Some("ss-in".to_string());
        context.metadata.identity.set_remote_peer_source(Endpoint::new_ip(
            REMOTE_PEER.parse().expect("remote peer ip"),
            local_port,
        ));

        test_dispatcher().enrich_metadata(&mut context).await.expect("enrich");

        assert_eq!(
            context.metadata.identity.process_name, None,
            "inbound traffic was attributed to process {:?}, which owns port \
             {local_port} locally and has nothing to do with the peer",
            context.metadata.identity.process_name
        );
    }

    /// The other half of the contract: traffic this node originated still
    /// attributes to the process that opened the socket.
    ///
    /// This is the case the feature exists for, and the fix must not have
    /// turned it off. The expected name is read from `/proc/self/comm` rather
    /// than hard-coded, because it is this test binary's name and a literal
    /// would break the moment the binary is renamed.
    #[tokio::test]
    async fn locally_originated_traffic_still_resolves_to_its_process() {
        let listener = local_listener();
        let local_addr = listener.local_addr().expect("listener addr");

        let mut context = ConnectionContext::new(crate::engine::metadata::ConnectionMetadata::new(
            endpoint("198.51.100.9"),
        ));
        context.metadata.environment.interface_name = Some("tun0".to_string());
        context.metadata.identity.set_local_source(Endpoint::from(local_addr));

        test_dispatcher().enrich_metadata(&mut context).await.expect("enrich");

        let expected = std::fs::read_to_string("/proc/self/comm")
            .map(|s| s.trim().to_string())
            .expect("read /proc/self/comm");
        assert_eq!(
            context.metadata.identity.process_name.as_deref(),
            Some(expected.as_str()),
            "locally-originated traffic on {local_addr} lost its process attribution"
        );

        // And the name is one a routing rule can actually act on, which is the
        // whole point of resolving it.
        assert!(crate::router::rule::Condition::ProcessName(expected).matches(&context.metadata));
    }

    /// Fail-closed: a transport that sets a source without stating where it
    /// came from gets no attribution. This is what stops a future listener from
    /// reintroducing the defect by omission.
    #[tokio::test]
    async fn unstated_source_origin_is_treated_as_a_remote_peer() {
        let listener = local_listener();
        let local_port = listener.local_addr().expect("listener addr").port();
        assert!(
            ProcessSearcher::find_process_info(local_port).await.is_some(),
            "port {local_port} must resolve locally, or this test proves nothing"
        );

        let mut metadata =
            crate::engine::metadata::ConnectionMetadata::new(endpoint("198.51.100.9"));
        // Deliberately the old, raw way -- exactly what a transport that has
        // not been updated looks like.
        metadata.identity.source =
            Some(Endpoint::new_ip(REMOTE_PEER.parse().expect("remote ip"), local_port));
        assert_eq!(metadata.identity.source_origin, None, "nothing stated an origin");

        let outcome =
            crate::engine::process::attribute_process_identity(&mut metadata.identity).await;

        assert!(outcome.is_remote_peer(), "got {outcome:?}");
        assert_eq!(metadata.identity.process_name, None);
    }

    /// The outcome enum is the observability contract: a caller can tell an
    /// attribution from a refusal, and both from a failed lookup.
    #[test]
    fn attribution_outcomes_are_distinguishable() {
        assert_eq!(crate::engine::process::ProcessAttribution::RemotePeer.label(), "remote_peer");
        assert_eq!(crate::engine::process::ProcessAttribution::Unresolved.label(), "unresolved");
        assert_eq!(crate::engine::process::ProcessAttribution::NoSource.label(), "no_source");
        assert_eq!(
            crate::engine::process::ProcessAttribution::Resolved(
                crate::engine::process::ProcessInfo { pid: 1, name: "x".into() }
            )
            .label(),
            "resolved"
        );

        let refused = crate::engine::process::ProcessAttribution::RemotePeer;
        let failed = crate::engine::process::ProcessAttribution::Unresolved;
        assert_ne!(refused, failed, "refusal and failure must not collapse");
        assert!(!refused.is_attributed() && !failed.is_attributed());
    }

    /// The two setters are the whole contract with the transports: one records
    /// the origin, the other does not, and that difference is what every
    /// inbound listener now depends on.
    #[test]
    fn source_setters_record_the_origin_they_describe() {
        let mut identity =
            crate::engine::metadata::ConnectionMetadata::new(endpoint("1.1.1.1")).identity;
        let peer = Endpoint::new_ip(REMOTE_PEER.parse().expect("remote ip"), 53_000);

        identity.set_remote_peer_source(peer.clone());
        assert_eq!(identity.source_origin, Some(SourceOrigin::RemotePeer));
        assert_eq!(identity.source, Some(peer));

        identity.set_local_source(Endpoint::new_ip("10.0.0.2".parse().expect("ip"), 40_000));
        assert_eq!(identity.source_origin, Some(SourceOrigin::Local));
    }

    /// A `Domain` source carries no address, and `/proc/net/tcp{,6}` is keyed by
    /// address. Falling back to a port-only lookup here would be the same
    /// collision as the inbound case, so it is reported as unresolved instead.
    #[tokio::test]
    async fn local_domain_source_is_not_resolved_by_port_alone() {
        let listener = local_listener();
        let local_port = listener.local_addr().expect("listener addr").port();

        let mut metadata = crate::engine::metadata::ConnectionMetadata::new(endpoint("1.1.1.1"));
        metadata.identity.set_local_source(Endpoint::new_domain("example.com".into(), local_port));

        let outcome =
            crate::engine::process::attribute_process_identity(&mut metadata.identity).await;

        assert_eq!(outcome, crate::engine::process::ProcessAttribution::Unresolved);
        assert_eq!(metadata.identity.process_name, None);
    }

    /// Nothing to attribute is its own outcome, so it is not confused with
    /// "a local process could not be found".
    #[tokio::test]
    async fn absent_source_is_reported_as_no_source() {
        let mut metadata = crate::engine::metadata::ConnectionMetadata::new(endpoint("1.1.1.1"));
        assert!(metadata.identity.source.is_none(), "precondition");

        let outcome =
            crate::engine::process::attribute_process_identity(&mut metadata.identity).await;

        assert_eq!(outcome, crate::engine::process::ProcessAttribution::NoSource);
    }

    /// An inbound that resolved its own process before dispatch keeps that
    /// name: attribution is additive, never a downgrade of better information.
    #[tokio::test]
    async fn an_existing_process_name_is_preserved_and_reported() {
        let mut metadata = crate::engine::metadata::ConnectionMetadata::new(endpoint("1.1.1.1"));
        metadata.identity.process_name = Some("already-known".to_string());
        metadata
            .identity
            .set_remote_peer_source(Endpoint::new_ip(REMOTE_PEER.parse().expect("ip"), 53_000));

        let outcome =
            crate::engine::process::attribute_process_identity(&mut metadata.identity).await;

        assert_eq!(
            outcome,
            crate::engine::process::ProcessAttribution::AlreadyAttributed("already-known".into())
        );
        assert_eq!(metadata.identity.process_name.as_deref(), Some("already-known"));
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
