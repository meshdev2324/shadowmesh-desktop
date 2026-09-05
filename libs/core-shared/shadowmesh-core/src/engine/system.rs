use crate::config::Config;
use crate::dns::fakeip::FakeIPEngine;
use crate::dns::upstream::udp::UdpDnsUpstream;
use crate::dns::{DnsResolver, DnsRouter, ExecutionModel};
use crate::engine::actor::{EngineActor, EngineHandle};
use crate::engine::dispatcher::Dispatcher;
use crate::engine::lifecycle::{LifecycleManager, Stage};
use crate::engine::registry::ConnectionRegistry;
use crate::transport::outbound::registry::OutboundRegistry;
use crate::transport::traits::InboundListener;
use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{info, warn};

/// High-fidelity ShadowMesh system orchestrator.
pub struct ShadowMeshSystem {
    #[allow(dead_code)]
    // held for the full lifecycle: purge/route-reload consumers land with RFC-011
    config: Config,
    #[allow(dead_code)] // owned by the EngineActor event pump; kept for ownership clarity
    dispatcher: Arc<Dispatcher>,
    lifecycle: LifecycleManager,
    #[allow(dead_code)] // consumed by the engine event pump wired in RFC-011 follow-up
    engine_handle: EngineHandle,
}

impl ShadowMeshSystem {
    pub async fn new(config: Config) -> Result<Self> {
        // RFC-012 G4: strict typed settings — a typo'd key fails here,
        // before anything binds or dials.
        config.validate_strict()?;

        let registry = Arc::new(ConnectionRegistry::new());

        let outbounds = Self::init_outbounds(&config).await?;
        let dns_router = Self::init_dns(&config).await?;
        let pipeline =
            Arc::new(crate::router::engine::RoutingPipeline::new(config.routing.rules.clone()));
        let dispatcher =
            Arc::new(Dispatcher::new(registry.clone(), pipeline, Arc::new(dns_router), outbounds));

        let (event_tx, event_rx) = async_channel::unbounded();
        let handle = EngineHandle::new(event_tx);
        let actor = EngineActor::new(event_rx, dispatcher.clone());

        tokio::spawn(async move {
            if let Err(e) = actor.run().await {
                tracing::error!("Engine actor crashed: {:?}", e);
            }
        });

        let mut lifecycle = LifecycleManager::new();
        Self::init_inbounds(&config, &mut lifecycle, &handle, dispatcher.clone()).await?;

        Ok(Self { config, dispatcher, lifecycle, engine_handle: handle })
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

    async fn init_outbounds(config: &Config) -> Result<Arc<OutboundRegistry>> {
        use crate::config::settings::{
            self, DirectSettings, ShadowsocksSettings, TrojanSettings, VlessSettings,
            VmessSettings, WireGuardSettings,
        };
        use crate::transport::outbound::*;
        let registry = Arc::new(OutboundRegistry::new());

        for cfg in &config.outbounds {
            // RFC-012 G4: every protocol parses its settings into a strict
            // typed struct first — a typo'd or missing key is a hard config
            // error here, never a silent default (empty port/password).
            let raw = cfg.settings.as_ref().ok_or_else(|| {
                anyhow!("outbound '{}' ({}) is missing settings", cfg.tag, cfg.protocol)
            })?;

            let dialer: Arc<dyn crate::transport::traits::OutboundDialer> = match cfg
                .protocol
                .as_str()
            {
                "direct" | "freedom" => {
                    settings::parse_strict::<DirectSettings>(raw, &cfg.protocol)?;
                    Arc::new(DirectOutbound::new(cfg.tag.clone()))
                }
                "shadowsocks" => {
                    let s = settings::parse_strict::<ShadowsocksSettings>(raw, &cfg.protocol)?;
                    Arc::new(ShadowsocksOutbound::new(
                        cfg.tag.clone(),
                        s.server,
                        s.port,
                        s.method,
                        s.password,
                    )?)
                }
                "trojan" => {
                    let s = settings::parse_strict::<TrojanSettings>(raw, &cfg.protocol)?;
                    let tls = s.tls.map(|t| crate::transport::outbound::trojan::TlsClientParams {
                        sni: t.sni,
                        insecure: t.insecure,
                    });
                    Arc::new(TrojanOutbound::with_tls(
                        cfg.tag.clone(),
                        s.server,
                        s.port,
                        &s.password,
                        tls,
                    ))
                }
                "vless" => {
                    let s = settings::parse_strict::<VlessSettings>(raw, &cfg.protocol)?;
                    let reality = s.reality.filter(|r| r.enabled).map(|r| {
                        crate::RealityConfig::new(
                            s.server.clone(),
                            s.port as u32,
                            s.uuid.clone(),
                            r.public_key,
                            r.short_id,
                            r.sni,
                            r.fingerprint,
                        )
                    });
                    Arc::new(VlessOutbound::new(
                        cfg.tag.clone(),
                        s.server,
                        s.port,
                        &s.uuid,
                        s.flow,
                        reality,
                    )?)
                }
                "vmess" => {
                    let s = settings::parse_strict::<VmessSettings>(raw, &cfg.protocol)?;
                    let security = s.security.unwrap_or_else(|| "auto".to_string());
                    Arc::new(VmessOutbound::new(
                        cfg.tag.clone(),
                        s.server,
                        s.port,
                        &s.uuid,
                        security,
                    )?)
                }
                "wireguard" => {
                    let s = settings::parse_strict::<WireGuardSettings>(raw, &cfg.protocol)?;
                    Arc::new(crate::transport::outbound::WireguardOutbound::new(
                        cfg.tag.clone(),
                        s.endpoint,
                        s.private_key,
                        s.public_key,
                    ))
                }
                _ => {
                    warn!("Outbound protocol '{}' not yet supported, using direct", cfg.protocol);
                    Arc::new(DirectOutbound::new(cfg.tag.clone()))
                }
            };
            registry.register(dialer).await;
        }

        Ok(registry)
    }

    async fn init_inbounds(
        config: &Config,
        lifecycle: &mut LifecycleManager,
        handle: &EngineHandle,
        _dispatcher: Arc<Dispatcher>,
    ) -> Result<()> {
        use crate::config::settings::{
            self, HysteriaInboundSettings, ShadowsocksInboundSettings, TrojanInboundSettings,
            VlessInboundSettings, VmessInboundSettings,
        };
        use crate::transport::inbound::*;

        // RFC-012 G4 (server side): every protocol parses its settings into a
        // strict typed struct — a typo'd or missing key is a hard config
        // error here, never a silently-skipped listener or empty password.
        for cfg in &config.inbounds {
            let require_settings = || -> Result<&serde_json::Value> {
                cfg.settings.as_ref().ok_or_else(|| {
                    anyhow!("inbound '{}' ({}) is missing settings", cfg.tag, cfg.protocol)
                })
            };
            match cfg.protocol.as_str() {
                "socks" => {
                    let addr = format!(
                        "{}:{}",
                        cfg.listen.as_deref().unwrap_or("127.0.0.1"),
                        cfg.port.unwrap_or(1080)
                    );
                    let inbound =
                        Arc::new(SocksInbound::new(cfg.tag.clone(), addr, handle.clone()));
                    lifecycle.register(Box::new(InboundService { inbound }));
                }
                "http" => {
                    let addr = format!(
                        "{}:{}",
                        cfg.listen.as_deref().unwrap_or("127.0.0.1"),
                        cfg.port.unwrap_or(8080)
                    );
                    let inbound = Arc::new(HttpInbound::new(cfg.tag.clone(), addr, handle.clone()));
                    lifecycle.register(Box::new(InboundService { inbound }));
                }
                "tun" => {
                    if let Some(s) = &cfg.settings {
                        let name = s["name"].as_str().unwrap_or("utun0").to_string();
                        let address = s["address"].as_str().unwrap_or("198.18.0.1").to_string();
                        let netmask = s["netmask"].as_str().unwrap_or("255.255.255.0").to_string();
                        let inbound = Arc::new(TunInbound::new(
                            cfg.tag.clone(),
                            name.clone(),
                            address.clone(),
                            netmask.clone(),
                            handle.clone(),
                        ));
                        lifecycle.register(Box::new(TunInboundService {
                            inbound,
                            name,
                            address,
                            netmask,
                        }));
                    }
                }
                "trojan" => {
                    let addr = format!(
                        "{}:{}",
                        cfg.listen.as_deref().unwrap_or("0.0.0.0"),
                        cfg.port.unwrap_or(443)
                    );
                    let s: TrojanInboundSettings =
                        settings::parse_strict(require_settings()?, &cfg.protocol)?;
                    let tls = match &s.tls {
                        Some(t) => Some(
                            tls_util::build_server_acceptor(&t.cert_path, &t.key_path).map_err(
                                |e| anyhow!("inbound '{}' TLS setup failed: {e:#}", cfg.tag),
                            )?,
                        ),
                        None => None,
                    };
                    let inbound = Arc::new(TrojanInbound::with_tls(
                        cfg.tag.clone(),
                        addr,
                        &s.password,
                        handle.clone(),
                        tls,
                    ));
                    lifecycle.register(Box::new(InboundService { inbound }));
                }
                "shadowsocks" => {
                    let addr = format!(
                        "{}:{}",
                        cfg.listen.as_deref().unwrap_or("0.0.0.0"),
                        cfg.port.unwrap_or(8388)
                    );
                    let s: ShadowsocksInboundSettings =
                        settings::parse_strict(require_settings()?, &cfg.protocol)?;
                    let inbound = Arc::new(ShadowsocksInbound::new(
                        cfg.tag.clone(),
                        addr,
                        s.method,
                        s.password,
                        handle.clone(),
                    )?);
                    lifecycle.register(Box::new(InboundService { inbound }));
                }
                "vless" => {
                    let addr = format!(
                        "{}:{}",
                        cfg.listen.as_deref().unwrap_or("0.0.0.0"),
                        cfg.port.unwrap_or(443)
                    );
                    let s: VlessInboundSettings =
                        settings::parse_strict(require_settings()?, &cfg.protocol)?;
                    let reality = s.reality.map(|r| crate::RealityServerConfig {
                        private_key: r.private_key,
                        short_ids: r.short_ids,
                        sni_target: r.sni_target,
                    });
                    let inbound = Arc::new(VlessInbound::new(
                        cfg.tag.clone(),
                        addr,
                        &s.uuid,
                        handle.clone(),
                        reality,
                        s.decoy,
                    )?);
                    lifecycle.register(Box::new(InboundService { inbound }));
                }
                "vmess" => {
                    let addr = format!(
                        "{}:{}",
                        cfg.listen.as_deref().unwrap_or("0.0.0.0"),
                        cfg.port.unwrap_or(443)
                    );
                    let s: VmessInboundSettings =
                        settings::parse_strict(require_settings()?, &cfg.protocol)?;
                    let inbound = Arc::new(VmessInbound::new(
                        cfg.tag.clone(),
                        addr,
                        &s.uuid,
                        handle.clone(),
                    )?);
                    lifecycle.register(Box::new(InboundService { inbound }));
                }
                "hysteria" => {
                    let addr = format!(
                        "{}:{}",
                        cfg.listen.as_deref().unwrap_or("0.0.0.0"),
                        cfg.port.unwrap_or(36712)
                    );
                    let s: HysteriaInboundSettings =
                        settings::parse_strict(require_settings()?, &cfg.protocol)?;
                    let inbound = Arc::new(crate::transport::hysteria::HysteriaInbound::new(
                        cfg.tag.clone(),
                        addr,
                        s.password,
                        handle.clone(),
                    ));
                    lifecycle.register(Box::new(InboundService { inbound }));
                }
                other => {
                    // An unknown inbound protocol is a config typo — on an
                    // edge node that means a port silently not listening.
                    // Fail loudly instead.
                    return Err(anyhow!(
                        "inbound '{}' uses unsupported protocol '{other}'",
                        cfg.tag
                    ));
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

struct TunInboundService {
    inbound: Arc<crate::transport::inbound::tun::TunInbound>,
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    address: String,
    #[allow(dead_code)]
    netmask: String,
}

#[async_trait::async_trait]
impl crate::engine::lifecycle::Service for TunInboundService {
    fn name(&self) -> &str {
        self.inbound.tag()
    }

    async fn stage_change(&self, stage: crate::engine::lifecycle::Stage) -> Result<()> {
        match stage {
            crate::engine::lifecycle::Stage::Start => {
                let inbound = self.inbound.clone();
                tokio::spawn(async move {
                    if let Err(e) = inbound.listen().await {
                        tracing::error!("TUN inbound listener error: {:?}", e);
                    }
                });
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
