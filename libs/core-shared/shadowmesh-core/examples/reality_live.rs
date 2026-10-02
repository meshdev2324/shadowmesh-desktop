//! Live REALITY handshake probe (development tool, not shipped).
//!
//! Runs the REALITY TLS 1.3 client against a real node and reports how far
//! the handshake got. Correlate with the server side via:
//!   `journalctl -u xray --since "5 min ago" | grep <your egress IP>`
//!
//! Usage: `cargo run --example reality_live --release [-- host port sni pubkey shortid]`
//! Defaults target the repo's recovery node (values already committed in
//! ConnectUseCase.kt — no new secret exposure).

use shadowmesh_core::transport::reality_tls::RealityTlsStream;
use tokio::net::TcpStream;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    while args.len() < 5 {
        args.push(String::new());
    }
    let host = if args[0].is_empty() { "157.245.154.116".into() } else { args[0].clone() };
    let port: u16 = if args[1].is_empty() { 443 } else { args[1].parse().unwrap() };
    let sni = if args[2].is_empty() { "dl.google.com".into() } else { args[2].clone() };
    let pubkey = if args[3].is_empty() {
        "1nf6Pue_IRqOZQv9R2Uj7MIlm1m5DGZA8fD5t8AOjAw".into()
    } else {
        args[3].clone()
    };
    let short_id = if args[4].is_empty() { "fb5304e4438d01ad".into() } else { args[4].clone() };

    // Bad-auth control run: wrong short id must be rejected distinctly.
    let bad = std::env::var("BAD_AUTH").is_ok();

    println!("[probe] tcp connect {host}:{port} …");
    let tcp = TcpStream::connect((host.as_str(), port)).await.expect("tcp connect failed");
    println!("[probe] tcp connected, starting REALITY handshake (sni={sni})");

    let sid = if bad { "0000000000000000".to_string() } else { short_id.clone() };
    match RealityTlsStream::connect(tcp, &pubkey, &sid, &sni).await {
        Ok(mut tls) => {
            println!("[probe] ✅ REALITY TLS 1.3 handshake COMPLETE (authenticated)");
            // Round-trip sanity: VLESS UDP request header for 127.0.0.1:51820.
            let uuid = uuid::Uuid::parse_str("d4f2cdeb-66b3-4e52-a743-b042aa53822b").unwrap();
            let mut header = vec![0x00u8];
            header.extend_from_slice(uuid.as_bytes());
            header.extend_from_slice(&[0x00, 0x02, 0x14, 0x6c, 0x01, 127, 0, 0, 1]);
            match tls.write_app(&header).await {
                Ok(()) => println!("[probe] ✅ VLESS UDP request sent"),
                Err(e) => println!("[probe] ⚠️ VLESS send failed: {e}"),
            }
            match tls.read_app().await {
                Ok(Some(data)) => {
                    println!(
                        "[probe] ✅ VLESS response received ({} bytes): {:02x?}",
                        data.len(),
                        &data[..data.len().min(4)]
                    );
                }
                Ok(None) => println!("[probe] ⚠️ tunnel closed by server after VLESS request"),
                Err(e) => println!("[probe] ⚠️ VLESS response read failed: {e}"),
            }
            let _ = tls.close().await;
        }
        Err(e) => {
            println!("[probe] ❌ handshake failed: {e}");
            println!(
                "[probe] next: check server-side classification in xray logs for this attempt"
            );
            std::process::exit(1);
        }
    }
}
