use lazy_static::lazy_static;
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref VPN_BYTES_SENT: IntCounter =
        IntCounter::new("vpn_bytes_sent_total", "Total bytes sent through the tunnel")
            .expect("metric can be created");
    pub static ref VPN_BYTES_RECV: IntCounter =
        IntCounter::new("vpn_bytes_recv_total", "Total bytes received through the tunnel")
            .expect("metric can be created");
    pub static ref VPN_TUNNEL_UP: IntGauge = IntGauge::new(
        "vpn_tunnel_active",
        "VPN tunnel connection status (1 = active, 0 = inactive)"
    )
    .expect("metric can be created");
    pub static ref IPC_COMMANDS_TOTAL: IntCounter =
        IntCounter::new("ipc_commands_total", "Total IPC commands processed")
            .expect("metric can be created");
    pub static ref IPC_ERRORS_TOTAL: IntCounter =
        IntCounter::new("ipc_errors_total", "Total IPC processing errors")
            .expect("metric can be created");
}

pub fn register_metrics() {
    REGISTRY.register(Box::new(VPN_BYTES_SENT.clone())).ok();
    REGISTRY.register(Box::new(VPN_BYTES_RECV.clone())).ok();
    REGISTRY.register(Box::new(VPN_TUNNEL_UP.clone())).ok();
    REGISTRY.register(Box::new(IPC_COMMANDS_TOTAL.clone())).ok();
    REGISTRY.register(Box::new(IPC_ERRORS_TOTAL.clone())).ok();
}

pub async fn start_metrics_server(port: u16) -> anyhow::Result<()> {
    use axum::{Router, response::IntoResponse, routing::get};
    use std::net::SocketAddr;

    let app = Router::new().route(
        "/metrics",
        get(move || async {
            let encoder = TextEncoder::new();
            let metric_families = REGISTRY.gather();
            let mut buffer = vec![];
            if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Metric encoding error: {}", e),
                )
                    .into_response();
            }
            String::from_utf8(buffer).unwrap_or_default().into_response()
        }),
    );

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("📊 Prometheus metrics exporter listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
