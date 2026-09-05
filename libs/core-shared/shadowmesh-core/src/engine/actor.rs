use crate::engine::dispatcher::Dispatcher;
use crate::engine::events::EngineEvent;
use anyhow::{anyhow, Result};
use async_channel::{Receiver, Sender};
use std::sync::Arc;
use tracing::{debug, error, info};

/// The main orchestrator actor for the ShadowMesh engine.
pub struct EngineActor {
    event_rx: Receiver<EngineEvent>,
    dispatcher: Arc<Dispatcher>,
}

impl EngineActor {
    pub fn new(event_rx: Receiver<EngineEvent>, dispatcher: Arc<Dispatcher>) -> Self {
        Self { event_rx, dispatcher }
    }

    /// Starts the actor event loop.
    pub async fn run(&self) -> Result<()> {
        info!("ShadowMesh Engine Actor started");

        while let Ok(event) = self.event_rx.recv().await {
            match event {
                EngineEvent::NewStream { context, stream } => {
                    let dispatcher = self.dispatcher.clone();
                    tokio::spawn(async move {
                        let ctx = {
                            let guard = context.lock();
                            guard.clone()
                        };

                        if let Err(e) = dispatcher.dispatch(ctx, stream).await {
                            error!("Dispatch error: {:?}", e);
                        }
                    });
                }
                EngineEvent::UdpPacket { context, payload, source, reply } => {
                    let dispatcher = self.dispatcher.clone();
                    tokio::spawn(async move {
                        let ctx = {
                            let guard = context.lock();
                            guard.clone()
                        };

                        match dispatcher.dispatch_udp(ctx, &payload, source).await {
                            Ok(reply_payload) => {
                                // RFC-012 G2: hand the upstream reply (or
                                // None for fire-and-forget) to the inbound.
                                if let Some(tx) = reply {
                                    let _ = tx.send(Some(reply_payload));
                                }
                            }
                            Err(e) => {
                                error!("UDP dispatch error: {:?}", e);
                                if let Some(tx) = reply {
                                    let _ = tx.send(None);
                                }
                            }
                        }
                    });
                }
                EngineEvent::ConnectionInitiated { .. } => {
                    debug!("Connection initiated event received");
                }
                EngineEvent::ConnectionEstablished { id, outbound_tag } => {
                    debug!("Connection {} established via {}", id, outbound_tag);
                }
                EngineEvent::ConnectionClosed { id, tx_bytes, rx_bytes, reason } => {
                    info!(
                        "Connection {} closed ({}): tx={}, rx={}",
                        id, reason, tx_bytes, rx_bytes
                    );
                }
            }
        }

        Ok(())
    }
}

/// A handle to send events to the EngineActor.
#[derive(Clone)]
pub struct EngineHandle {
    event_tx: Sender<EngineEvent>,
}

impl EngineHandle {
    pub fn new(event_tx: Sender<EngineEvent>) -> Self {
        Self { event_tx }
    }

    pub async fn send_event(&self, event: EngineEvent) -> Result<()> {
        self.event_tx.send(event).await.map_err(|e| anyhow!("Failed to send engine event: {:?}", e))
    }
}
