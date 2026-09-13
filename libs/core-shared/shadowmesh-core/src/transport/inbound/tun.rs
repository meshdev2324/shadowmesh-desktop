use crate::engine::context::ConnectionContext;
use crate::engine::metadata::{ConnectionMetadata, Endpoint, L4Protocol};
use crate::engine::{events::EngineEvent, EngineHandle};
use crate::transport::traits::InboundListener;
use anyhow::Result;
use async_trait::async_trait;
use etherparse::IpHeader;
use parking_lot::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing::{error, info, trace};

pub struct TunInbound {
    tag: String,
    name: String,
    address: String,
    netmask: String,
    engine: EngineHandle,
}

impl TunInbound {
    pub fn new(
        tag: String,
        name: String,
        address: String,
        netmask: String,
        engine: EngineHandle,
    ) -> Self {
        Self { tag, name, address, netmask, engine }
    }
}

#[async_trait]
impl InboundListener for TunInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn listen(&self) -> Result<()> {
        let mut config = tun::Configuration::default();
        config.name(&self.name).address(&self.address).netmask(&self.netmask).up();

        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(true);
        });

        let mut dev = tun::create_as_async(&config)?;
        info!("TUN inbound [{}] listening on interface {}", self.tag, self.name);

        let mut buf = [0u8; 4096];
        loop {
            let n = dev.read(&mut buf).await?;
            let packet = &buf[..n];

            #[cfg(target_os = "linux")]
            let ip_packet = if packet.len() > 4 { &packet[4..] } else { continue };
            #[cfg(not(target_os = "linux"))]
            let ip_packet = packet;

            if let Err(e) = self.handle_packet(ip_packet).await {
                trace!("Failed to handle TUN packet: {:?}", e);
            }
        }
    }
}

impl TunInbound {
    async fn handle_packet(&self, packet: &[u8]) -> Result<()> {
        let header = etherparse::IpHeader::from_slice(packet)?;

        let (source_ip, dest_ip, protocol, header_len) = match header {
            (IpHeader::Version4(h, _), _, _) => (
                IpAddr::V4(h.source.into()),
                IpAddr::V4(h.destination.into()),
                h.protocol,
                h.ihl() as usize * 4,
            ),
            (IpHeader::Version6(h, _), _, _) => {
                (IpAddr::V6(h.source.into()), IpAddr::V6(h.destination.into()), h.next_header, 40)
            }
        };

        let (source_port, dest_port, is_udp) = if protocol == 6 {
            // TCP
            if packet.len() < header_len + 4 {
                return Ok(());
            }
            let tcp = etherparse::TcpHeader::from_slice(&packet[header_len..])?.0;
            (Some(tcp.source_port), Some(tcp.destination_port), false)
        } else if protocol == 17 {
            // UDP
            if packet.len() < header_len + 4 {
                return Ok(());
            }
            let udp = etherparse::UdpHeader::from_slice(&packet[header_len..])?.0;
            (Some(udp.source_port), Some(udp.destination_port), true)
        } else {
            return Ok(());
        };

        let destination = Endpoint::new_ip(dest_ip, dest_port.unwrap_or(0));
        let mut metadata = ConnectionMetadata::new(destination);
        metadata.l4_protocol = if is_udp { L4Protocol::Udp } else { L4Protocol::Tcp };
        metadata.identity.source = Some(Endpoint::new_ip(source_ip, source_port.unwrap_or(0)));
        metadata.environment.inbound_tag = Some(self.tag.clone());
        metadata.environment.interface_name = Some(self.name.clone());

        let context = Arc::new(Mutex::new(ConnectionContext::new(metadata)));

        if is_udp {
            let engine = self.engine.clone();
            let payload = packet[header_len + 8..].to_vec();
            let source = SocketAddr::new(source_ip, source_port.unwrap_or(0));
            tokio::spawn(async move {
                // TUN ingress is fire-and-forget for replies: the TUN write
                // path (not this event) carries data back to the OS.
                if let Err(e) = engine
                    .send_event(EngineEvent::UdpPacket { context, payload, source, reply: None })
                    .await
                {
                    error!("UDP dispatch failed: {:?}", e);
                }
            });
        } else {
            trace!(
                "TCP packet captured via TUN: {}:{} -> {}:{}",
                source_ip,
                source_port.unwrap_or(0),
                dest_ip,
                dest_port.unwrap_or(0)
            );
        }

        Ok(())
    }
}
