use shadowmesh_core::ApiClient;
use shadowmesh_daemon::{
    CONFIG_DIR, CoreApiWrapper, Daemon, RealCommandRunner, RealFileSystem, RealSecureStorage,
    run_daemon_service,
};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::FmtSubscriber;

// PII Scrubbing engine ported from Server to Daemon Edge
struct LogScrubber;
impl LogScrubber {
    fn scrub(input: &str) -> String {
        shadowmesh_common::logging::scrub_pii(input)
    }
}

struct ScrubbingWriter<W> {
    writer: W,
}
impl<W: std::io::Write> std::io::Write for ScrubbingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let input = String::from_utf8_lossy(buf);
        let scrubbed = LogScrubber::scrub(&input);
        self.writer.write_all(scrubbed.as_bytes())?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

struct ScrubbingMakeWriter<M> {
    make_writer: M,
}
impl<'a, M> tracing_subscriber::fmt::MakeWriter<'a> for ScrubbingMakeWriter<M>
where
    M: tracing_subscriber::fmt::MakeWriter<'a>,
{
    type Writer = ScrubbingWriter<M::Writer>;
    fn make_writer(&'a self) -> Self::Writer {
        ScrubbingWriter { writer: self.make_writer.make_writer() }
    }
}

fn main() -> anyhow::Result<()> {
    // 1. Initialize Crypto Provider (Mandatory for rustls)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    // 2. Initialize Logging
    let _ = std::fs::create_dir_all(CONFIG_DIR);
    let appender = tracing_appender::rolling::daily(CONFIG_DIR, "daemon.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(appender);
    let scrubbing_writer = ScrubbingMakeWriter { make_writer: non_blocking };

    let subscriber = FmtSubscriber::builder()
        .with_env_filter("info")
        .with_writer(scrubbing_writer)
        .with_ansi(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| anyhow::anyhow!("Failed to set tracing subscriber: {}", e))?;

    info!("🚀 ShadowMesh Pro-Daemon Initializing...");

    // 3. Initialize Core API Client and Wrapper
    // v5.8: Critical - Run this entirely outside any Tokio runtime context
    let pinned_hashes = if cfg!(debug_assertions) {
        vec![]
    } else {
        vec![
            "sha256/7H65zK7U8Y+y6/M7u4Z5N8w6v4b2Q8w5N8G4b6c8R7w=".to_string(),
            "sha256/w6b2Q8w5N8G4b6c8R7w7H65zK7U8Y+y6/M7u4Z5N8w6=".to_string(),
        ]
    };

    let core_client =
        Arc::new(ApiClient::with_pins("https://api.shadowmesh.org".into(), pinned_hashes)?);
    let api_client = Arc::new(CoreApiWrapper::new(core_client));
    let file_system = Arc::new(RealFileSystem);
    let secure_storage = Arc::new(RealSecureStorage);
    let command_runner = Arc::new(RealCommandRunner);

    let daemon = Arc::new(Daemon::new(api_client, file_system, secure_storage, command_runner)?);

    // 4. Create and use a dedicated Runtime only for the top-level service.
    // This allows library-internal block_on calls to run on the main thread
    // while async tasks run in the background.
    let rt = tokio::runtime::Runtime::new()?;
    let res = rt.block_on(async {
        run_daemon_service(daemon.clone()).await
    });

    drop(daemon);
    res
}
