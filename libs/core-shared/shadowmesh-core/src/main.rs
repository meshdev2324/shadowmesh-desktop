/// Implementation Source:
/// - Architecture: Independent Modular CLI Entry Point.
/// - Goals: Specification-driven configuration loading and lifecycle management.
/// - Security considerations: Strict validation of inbound/outbound parameters, safe shutdown.
use clap::{Parser, Subcommand};
use shadowmesh_core::config::Config;
use shadowmesh_core::engine::observability::setup_observability;
use shadowmesh_core::engine::ShadowMeshSystem;
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "shadowmesh")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Absolute or relative path to the JSON configuration file.
    /// Global: accepted before or after the subcommand (`shadowmesh run
    /// --config X` and `shadowmesh --config X run` are equivalent).
    #[arg(short, long, value_name = "FILE", default_value = "config.json", global = true)]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Starts the ShadowMesh Universal Proxy engine.
    Run,
    /// Performs a static validation check of the configuration file.
    Check,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // 1. Initialize High-Fidelity Observability (Tracing + Prometheus metrics)
    setup_observability();

    // 2. Data-Driven Configuration Loading
    let config = match load_and_validate_config(&cli.config).await {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration failure: {}", e);
            std::process::exit(1);
        }
    };

    match cli.command.unwrap_or(Commands::Run) {
        Commands::Check => {
            // G4: typed settings validation — catches typo'd keys offline,
            // exactly as runtime composition would.
            config
                .validate_strict()
                .map_err(|e| anyhow::anyhow!("Typed settings validation failure: {}", e))?;
            info!("Validation successful: Configuration is structurally sound.");
            Ok(())
        }
        Commands::Run => {
            info!("Initializing ShadowMesh Universal Protocol Engine...");

            // 3. Orchestrated System Startup
            let api_config = config.api.clone();
            let mut system = ShadowMeshSystem::new(config).await?;
            system.start().await?;

            // 3b. Metrics surface (RFC-015 F3): /metrics on the ApiConfig
            // listen address when enabled — Prometheus recorder is already
            // installed by setup_observability().
            if let Some(api) = &api_config {
                if api.enabled {
                    spawn_metrics_endpoint(&api.listen).await?;
                }
            }

            info!("ShadowMesh Core established. Processing network events...");

            // 4. Signal Handling for Graceful Termination
            // Containers and process managers send SIGTERM — a ctrl_c-only
            // wait would skip the forensic drain entirely.
            wait_for_termination().await;

            info!("Shutdown signal intercepted. Draining active connections...");
            system.shutdown().await?;
            info!("ShadowMesh stopped safely. Forensic scrub complete.");

            Ok(())
        }
    }
}

/// Minimal HTTP endpoint exposing the Prometheus recorder output. No
/// routing framework — one route, no PII in metrics labels (ZPII).
async fn spawn_metrics_endpoint(listen: &str) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| anyhow::anyhow!("metrics listener bind {listen} failed: {e}"))?;
    info!("Metrics endpoint listening on http://{listen}/metrics");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await; // request line is irrelevant; one-shot endpoint
                let body = shadowmesh_core::engine::observability::render_metrics()
                    .unwrap_or_else(|| "# metrics unavailable\n".to_string());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    Ok(())
}

/// Resolves on SIGINT (interactive) or SIGTERM (Docker/systemd), so the
/// graceful shutdown path always runs on the edge.
async fn wait_for_termination() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to install SIGTERM handler: {e}");
                tokio::signal::ctrl_c().await.ok();
                return;
            }
        };
        let mut int = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to install SIGINT handler: {e}");
                term.recv().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {},
            _ = int.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
}

async fn load_and_validate_config(path: &std::path::Path) -> anyhow::Result<Config> {
    info!("Loading Specification: {:?}", path);

    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read config from {:?}: {}", path, e))?;

    let config: Config =
        serde_json::from_str(&content).map_err(|e| anyhow::anyhow!("JSON Syntax Error: {}", e))?;

    config.validate().map_err(|e| anyhow::anyhow!("Validation Logic Failure: {}", e))?;

    Ok(config)
}
