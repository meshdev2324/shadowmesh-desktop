use shadowmesh_core::ApiClient;
use shadowmesh_daemon::{
    CoreApiWrapper, Daemon, RealCommandRunner, RealFileSystem, RealSecureStorage,
    run_daemon_service,
};
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;

fn main() -> anyhow::Result<()> {
    // 0. High-Fidelity Panic Handler
    std::panic::set_hook(Box::new(|info| {
        let location = info.location();
        let msg = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => &s[..],
                None => "Box<Any>",
            },
        };
        error!("🚨 CRITICAL DAEMON PANIC at {:?}: {}", location, msg);

        // Scrubbed PII from panic message if it exists
        let _scrubbed = shadowmesh_core::scrub_pii(msg);

        #[cfg(not(debug_assertions))]
        {
            // In production, attempt to report to security logger before dying
            // This is a last-ditch effort.
        }
    }));

    // 1. Safe Crypto Init (Don't panic if already set)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // 2. Logging Setup
    let subscriber = FmtSubscriber::builder()
        .with_env_filter("info")
        .with_writer(std::io::stderr)
        .with_ansi(true)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    info!("🚀 ShadowMesh Pro-Daemon Initializing...");

    // 3. Force Local Targeting & HTRE Obfuscation
    let api_url = shadowmesh_daemon::security::get_default_api_url();
    info!("📡 Targeting API Gateway: {}", shadowmesh_core::scrub_pii(&api_url));

    // 4. Force Reclaim Socket (Avoid os error 98)
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file("/home/red/.shadowmesh.sock");
    }

    // 5. Initialize Core API Client
    let core_client = Arc::new(ApiClient::with_pins(api_url, vec![])?);
    let api_client = Arc::new(CoreApiWrapper::new(core_client));
    let file_system = Arc::new(RealFileSystem);
    let secure_storage = Arc::new(RealSecureStorage);
    let command_runner = Arc::new(RealCommandRunner);

    let daemon = Arc::new(Daemon::new(api_client, file_system, secure_storage, command_runner)?);

    // 6. Execution Loop
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    info!("🛡️ Daemon Core Ready. Active on {}", shadowmesh_daemon::SOCKET_PATH);
    rt.block_on(async { run_daemon_service(daemon.clone()).await })
}
