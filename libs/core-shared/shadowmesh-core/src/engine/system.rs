use crate::config::Config;
use crate::dns::fakeip::FakeIPEngine;
use crate::dns::upstream::udp::UdpDnsUpstream;
use crate::dns::{DnsResolver, DnsRouter, ExecutionModel};
use crate::engine::actor::{EngineActor, EngineHandle};
use crate::engine::dispatcher::Dispatcher;
use crate::engine::lifecycle::{LifecycleManager, Stage};
use crate::engine::registry::ConnectionRegistry;
use crate::protocol_registry::{InboundPlan, ProtocolRegistry};
use crate::transport::outbound::registry::OutboundRegistry;
use crate::transport::traits::InboundListener;
use anyhow::Result;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{info, warn};

/// High-fidelity ShadowMesh system orchestrator.
///
/// The struct holds exactly one thing: the services registered with the
/// [`LifecycleManager`]. Everything else a session needs is owned by the thing
/// that actually uses it — the dispatcher and its event pump live inside
/// `EngineActor`, and each inbound owns its own `EngineHandle` clone — so there
/// is deliberately no `config`, `dispatcher` or `engine_handle` field here.
/// A retained copy would claim an ownership relationship that does not exist
/// (L18) while changing no behaviour.
pub struct ShadowMeshSystem {
    lifecycle: LifecycleManager,
}

impl ShadowMeshSystem {
    pub async fn new(config: Config) -> Result<Self> {
        // RFC-012 G4: the one protocol table. Built once per composition and
        // handed to both directions of dispatch, so validation and
        // construction cannot disagree about which protocols exist.
        let protocols = ProtocolRegistry::builtin();
        Self::new_with_protocols(config, protocols).await
    }

    /// Composition against an explicit registry — the seam that makes G4's
    /// claim testable: a caller can supply a table with a protocol added to
    /// it and nothing else in the engine changes.
    pub async fn new_with_protocols(config: Config, protocols: ProtocolRegistry) -> Result<Self> {
        // RFC-012 G4: strict typed settings — a typo'd key fails here,
        // before anything binds or dials.
        protocols.validate(&config)?;

        let registry = Arc::new(ConnectionRegistry::new());

        let outbounds = Self::init_outbounds(&config, &protocols).await?;
        let dns_router = Self::init_dns(&config).await?;
        let pipeline = Arc::new(
            crate::router::engine::RoutingPipeline::new(config.routing.rules.clone())
                .with_default_outbound(Some(config.routing.default_outbound.clone())),
        );
        let dispatcher =
            Arc::new(Dispatcher::new(registry.clone(), pipeline, Arc::new(dns_router), outbounds));

        let (event_tx, event_rx) = async_channel::bounded(4096);
        let handle = EngineHandle::new(event_tx);
        // The actor takes ownership of the dispatcher: it is the only thing
        // that ever dispatches through it, and holding a second `Arc` here
        // would outlive the pump while claiming an ownership it does not have.
        let actor = EngineActor::new(event_rx, dispatcher);

        tokio::spawn(async move {
            if let Err(e) = actor.run().await {
                tracing::error!("Engine actor crashed: {:?}", e);
            }
        });

        let mut lifecycle = LifecycleManager::new();
        // `handle` is handed to every inbound, which each keep their own clone:
        // that is what keeps the event channel — and with it the actor —
        // alive for the life of the system. This function deliberately keeps
        // no reference of its own.
        Self::init_inbounds(&config, &protocols, &mut lifecycle, &handle).await?;

        Ok(Self { lifecycle })
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("Starting ShadowMesh System...");
        self.lifecycle.transition_to(Stage::Start).await
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Stopping ShadowMesh System...");
        self.lifecycle.shutdown().await
    }

    async fn init_dns(config: &Config) -> Result<DnsRouter> {
        let mut resolvers: Vec<Arc<dyn DnsResolver>> = Vec::new();
        for server in &config.dns.servers {
            if let Ok(addr) = server.parse() {
                resolvers.push(Arc::new(UdpDnsUpstream::new(addr)));
            }
        }

        let execution_model = match config.dns.execution_model.as_deref() {
            Some("race") => ExecutionModel::Race,
            _ => ExecutionModel::Serial,
        };

        let mut dns_router = DnsRouter::new(resolvers, execution_model);

        if let Some(fake_ip_cfg) = &config.dns.fake_ip {
            if fake_ip_cfg.enabled {
                let base_ip = if let Some(slash_idx) = fake_ip_cfg.range.find('/') {
                    fake_ip_cfg.range[..slash_idx].parse::<Ipv4Addr>()?
                } else {
                    fake_ip_cfg.range.parse::<Ipv4Addr>()?
                };

                let engine = FakeIPEngine::new(
                    base_ip,
                    Ipv4Addr::new(198, 18, 255, 255),
                    fake_ip_cfg.max_size,
                );

                // v6.9.1: Load persistent state if available
                let path = "fakeip.db.json";
                if std::path::Path::new(path).exists() {
                    let _ = engine.load(path);
                }
                dns_router.set_fake_ip(engine);
            }
        }

        Ok(dns_router)
    }

    async fn init_outbounds(
        config: &Config,
        protocols: &ProtocolRegistry,
    ) -> Result<Arc<OutboundRegistry>> {
        let registry = Arc::new(OutboundRegistry::new());

        // RFC-012 G4: dispatch is registry iteration, not a match on
        // `protocol.as_str()`. Each spec parses its settings into a strict
        // typed struct before constructing — a typo'd or missing key is a hard
        // config error here, never a silent default (empty port/password) —
        // and an unknown protocol is a hard error naming the protocol.
        for cfg in &config.outbounds {
            let dialer = protocols.build_outbound(cfg)?;
            registry.register(dialer).await;
        }

        Ok(registry)
    }

    async fn init_inbounds(
        config: &Config,
        protocols: &ProtocolRegistry,
        lifecycle: &mut LifecycleManager,
        handle: &EngineHandle,
    ) -> Result<()> {
        // RFC-012 G4 (server side): same registry, opposite direction. Every
        // protocol parses its settings into a strict typed struct — a typo'd
        // or missing key is a hard config error, never a silently-skipped
        // listener or empty password.
        for cfg in &config.inbounds {
            match protocols.build_inbound(cfg, handle)? {
                InboundPlan::Register(inbound) => {
                    lifecycle.register(Box::new(InboundService { inbound }));
                }
                InboundPlan::Skip => {
                    // Only `tun` with no settings block reaches this. It was
                    // silent before; a port that is not listening must never
                    // be invisible, so it is named here.
                    warn!(
                        "inbound '{}' ({}) registered no listener: the protocol \
                         requires a `settings` block and none was provided",
                        cfg.tag, cfg.protocol
                    );
                }
            }
        }

        Ok(())
    }
}

struct InboundService {
    inbound: Arc<dyn InboundListener>,
}

#[async_trait::async_trait]
impl crate::engine::lifecycle::Service for InboundService {
    fn name(&self) -> &str {
        self.inbound.tag()
    }

    async fn stage_change(&self, stage: crate::engine::lifecycle::Stage) -> Result<()> {
        match stage {
            crate::engine::lifecycle::Stage::Start => {
                let inbound = self.inbound.clone();
                tokio::spawn(async move {
                    if let Err(e) = inbound.listen().await {
                        tracing::error!("Inbound listener error: {:?}", e);
                    }
                });
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, DnsConfig, InboundConfig, OutboundConfig, RoutingConfig};

    /// A structurally valid, side-effect-free configuration: one `direct`
    /// outbound and the inbound under test. Port 0 lets the OS pick, so a
    /// parallel test run cannot collide with the listener.
    fn config_with_inbound(inbound: InboundConfig) -> Config {
        Config {
            inbounds: vec![inbound],
            outbounds: vec![OutboundConfig {
                tag: "direct".into(),
                protocol: "direct".into(),
                settings: Some(serde_json::json!({})),
            }],
            routing: RoutingConfig { rules: vec![], default_outbound: "direct".into() },
            dns: DnsConfig { servers: vec![], fake_ip: None, execution_model: None },
            api: None,
        }
    }

    fn socks_inbound() -> InboundConfig {
        InboundConfig {
            tag: "socks-in".into(),
            protocol: "socks".into(),
            listen: Some("127.0.0.1".into()),
            port: Some(0),
            settings: None,
        }
    }

    // ---- L18: the retained-state claim -----------------------------------
    //
    // `ShadowMeshSystem` used to carry `config`, `dispatcher` and
    // `engine_handle` behind `#[allow(dead_code)]`, with comments asserting an
    // ownership relationship ("owned by the EngineActor event pump",
    // "consumed by the engine event pump wired in RFC-011 follow-up") that did
    // not exist. RFC-011 has landed: the pump runs, and it owns the dispatcher.
    // These tests pin what the deletion had to preserve — namely that the
    // system composes, starts, serves and shuts down with nothing retained
    // beyond the services registered with the lifecycle.

    /// The lifecycle is carried entirely by the registered services. Before the
    /// fix this also held trivially, but with three fields in the struct whose
    /// comments claimed they were load-bearing; now it holds for the right
    /// reason, and the composition is exercised on every run of the edge suite.
    #[tokio::test]
    async fn a_system_with_an_inbound_starts_and_shuts_down() {
        let mut system =
            ShadowMeshSystem::new(config_with_inbound(socks_inbound())).await.expect("composes");
        system.start().await.expect("starts");
        system.shutdown().await.expect("shuts down");
    }

    /// The one case where dropping the system's own `EngineHandle` changes
    /// anything: with no inbound, nothing else holds a sender, so the event
    /// channel closes and the actor's loop ends. That is correct, not a lost
    /// capability — a configuration with no listeners has nothing that could
    /// emit an event — but it is worth pinning, because "the system keeps its
    /// handle so the pump stays alive" was the claim the deleted field used to
    /// make implicitly.
    #[tokio::test]
    async fn a_system_with_no_inbounds_still_composes_and_shuts_down() {
        let mut config = config_with_inbound(socks_inbound());
        config.inbounds.clear();

        let mut system = ShadowMeshSystem::new(config).await.expect("composes");
        system.start().await.expect("starts");
        system.shutdown().await.expect("shuts down");
    }

    /// A configuration that fails validation must still fail before anything is
    /// composed. `new` runs `validate_strict` first precisely so a typo'd
    /// inbound never half-builds a system; that ordering must not regress now
    /// that the struct holds less state to be torn down.
    #[tokio::test]
    async fn an_invalid_inbound_is_rejected_before_composition() {
        let mut bad = socks_inbound();
        bad.protocol = "not-a-protocol".into();

        let err = ShadowMeshSystem::new(config_with_inbound(bad)).await;
        assert!(err.is_err(), "an unknown inbound protocol must be a hard error");
    }

    /// RFC-012 G5 config gating reaches the VMess listener as well as the
    /// outbound: a typo'd flag is still a hard config error, so an operator who
    /// set `padding` never silently runs unpadded.
    #[tokio::test]
    async fn a_vmess_inbound_with_padding_composes() {
        let vmess_inbound = InboundConfig {
            tag: "vmess-in".into(),
            protocol: "vmess".into(),
            listen: Some("127.0.0.1".into()),
            port: Some(0),
            settings: Some(serde_json::json!({
                // Per-run: the VMess inbound parses this into a `Uuid` at
                // construction, so a placeholder string is not enough — and a
                // literal identifier in a test file is exactly what the
                // credential scanner exists to catch.
                "uuid": uuid::Uuid::new_v4().to_string(),
                "padding": true,
            })),
        };

        let mut system = ShadowMeshSystem::new(config_with_inbound(vmess_inbound))
            .await
            .expect("a padded vmess inbound must compose");
        system.start().await.expect("starts");
        system.shutdown().await.expect("shuts down");
    }
}
