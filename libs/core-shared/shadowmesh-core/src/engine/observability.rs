use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use std::sync::OnceLock;

/// Handle to the installed Prometheus recorder, so a host process (server,
/// desktop) can render metrics text on its own route without opening an extra
/// network listener.
static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Renders the current metrics in Prometheus exposition format, if the
/// recorder was installed.
pub fn render_metrics() -> Option<String> {
    PROMETHEUS_HANDLE.get().map(|h| h.render())
}

/// Initializes the observability stack including logging and metrics.
///
/// Best-effort: a metrics installation failure is logged and non-fatal so a
/// telemetry regression can never block VPN connectivity.
pub fn setup_observability() {
    // 1. Initialize Tracing with EnvFilter
    tracing_subscriber::registry().with(fmt::layer()).with(EnvFilter::from_default_env()).init();

    // 2. Initialize Prometheus metrics (recorder only — no HTTP listener).
    match PrometheusBuilder::new().install_recorder() {
        Ok(handle) => {
            let _ = PROMETHEUS_HANDLE.set(handle);
            info!("Observability stack initialized (Tracing + Prometheus recorder)");
        }
        Err(e) => {
            tracing::warn!("Prometheus recorder installation failed (metrics disabled): {}", e);
        }
    }
}
