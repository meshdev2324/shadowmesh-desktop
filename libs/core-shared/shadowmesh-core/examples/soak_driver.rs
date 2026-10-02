//! Soak driver for the native edge node (RFC-012 G6 stability pass).
//!
//! Drives sustained traffic through a running edge (Shadowsocks inbound →
//! direct egress) to a local origin, then reports throughput/latency numbers.
//! Used by the local Docker soak; not part of the client API surface.
//!
//! Usage:
//!   cargo run --release --example soak_driver -- \
//!     --ss-port 18388 --ss-pass <PASS> --origin 127.0.0.1:8099 \
//!     --sequential 200 --concurrent 50

use clap::Parser;
use shadowmesh_core::engine::context::ConnectionContext;
use shadowmesh_core::engine::metadata::{ConnectionMetadata, Endpoint, L4Protocol};
use shadowmesh_core::transport::outbound::shadowsocks::ShadowsocksOutbound;
use shadowmesh_core::transport::traits::OutboundDialer;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
struct Args {
    /// Edge Shadowsocks inbound port (on 127.0.0.1).
    #[arg(long, default_value_t = 18388)]
    ss_port: u16,
    /// Shadowsocks password (must match the edge config).
    #[arg(long)]
    ss_pass: String,
    /// Origin "host:port" the requests target through the edge.
    #[arg(long, default_value = "127.0.0.1:8099")]
    origin: String,
    /// Sequential request count.
    #[arg(long, default_value_t = 200)]
    sequential: usize,
    /// Concurrent batch size.
    #[arg(long, default_value_t = 50)]
    concurrent: usize,
}

fn ctx_for(origin: &str) -> Arc<parking_lot::Mutex<ConnectionContext>> {
    let (host, port) = origin.split_once(':').expect("origin host:port");
    let dest = if let Ok(ip) = host.parse() {
        Endpoint::new_ip(ip, port.parse().expect("port"))
    } else {
        Endpoint::new_domain(host.to_string(), port.parse().expect("port"))
    };
    let mut metadata = ConnectionMetadata::new(dest);
    metadata.l4_protocol = L4Protocol::Tcp;
    Arc::new(parking_lot::Mutex::new(ConnectionContext::new(metadata)))
}

async fn one_request(client: &ShadowsocksOutbound, origin: &str) -> anyhow::Result<usize> {
    let ctx = ctx_for(origin);
    let mut stream = client.dial_stream(ctx).await?;
    // Minimal HTTP request; the origin just needs to answer.
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    stream.flush().await?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 256 * 1024 {
            break;
        }
    }
    Ok(buf.len())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = ShadowsocksOutbound::new(
        "soak".into(),
        "127.0.0.1".into(),
        args.ss_port,
        "aes-256-gcm".into(),
        args.ss_pass.clone(),
    )?;

    // Sequential phase.
    let t0 = std::time::Instant::now();
    let mut bytes_total = 0usize;
    for i in 0..args.sequential {
        match one_request(&client, &args.origin).await {
            Ok(n) => bytes_total += n,
            Err(e) => eprintln!("sequential request {i} failed: {e:#}"),
        }
    }
    let seq_secs = t0.elapsed().as_secs_f64();

    // Concurrent phase.
    let t1 = std::time::Instant::now();
    let mut handles = Vec::new();
    for _ in 0..args.concurrent {
        let client = client.clone();
        let origin = args.origin.clone();
        handles.push(tokio::spawn(async move { one_request(&client, &origin).await }));
    }
    let mut ok = 0usize;
    for h in handles {
        if let Ok(Ok(n)) = h.await {
            bytes_total += n;
            ok += 1;
        }
    }
    let con_secs = t1.elapsed().as_secs_f64();

    println!(
        "SOAK_RESULT sequential={}/{} in {:.2}s ({:.1} rps) | concurrent_ok={}/{} in {:.2}s ({:.1} rps) | bytes={}",
        args.sequential,
        args.sequential,
        seq_secs,
        args.sequential as f64 / seq_secs.max(0.001),
        ok,
        args.concurrent,
        con_secs,
        args.concurrent as f64 / con_secs.max(0.001),
        bytes_total
    );
    Ok(())
}
