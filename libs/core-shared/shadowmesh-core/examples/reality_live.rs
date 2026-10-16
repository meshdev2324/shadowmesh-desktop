//! Live REALITY handshake probe (development tool, not shipped).
//!
//! Runs the REALITY TLS 1.3 client against a real node and reports how far
//! the handshake got. Correlate with the server side via:
//!   `journalctl -u xray --since "5 min ago" | grep <your egress IP>`
//!
//! Usage: `cargo run --example reality_live --release -- <host> <pubkey> <shortid> [port] [sni]`
//!
//! # Credentials are arguments, never defaults
//!
//! This tool previously defaulted to a live node's host, X25519 public key,
//! REALITY `short_id` and VLESS UUID, justified as "already committed
//! elsewhere, so no new secret exposure". That reasoning is wrong: those values
//! are in git history, which means they are public and must be treated as
//! compromised. A `short_id` is a 2^64 candidate space, brute-forceable offline
//! against any server presenting it, so a committed one is not a convenience
//! default -- it is an active-probing fingerprint.
//!
//! Supply every credential on the command line. `scripts/ci/scan-credential-literals.sh`
//! rule R2 exists to catch this exact shape.

use shadowmesh_core::transport::reality_tls::RealityTlsStream;
use tokio::net::TcpStream;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // host, pubkey and shortid are mandatory: they are per-deployment secrets.
    // Port and SNI keep safe defaults -- a port number is not a credential, and
    // a pinned REALITY SNI is public by design, since the camouflage only works
    // if it looks like the site it claims to be.
    if args.len() < 3 {
        eprintln!(
            "usage: reality_live <host> <pubkey> <shortid> [port=443] [sni=dl.google.com]\n\n\
             Credentials are read from the command line on purpose. This tool used to\n\
             default to a live node's values; they are in git history, so they must be\n\
             treated as compromised and rotated."
        );
        std::process::exit(2);
    }
    let host = args[0].clone();
    let pubkey = args[1].clone();
    let short_id = args[2].clone();
    let port: u16 = if args.len() > 3 && !args[3].is_empty() {
        args[3].parse().expect("port must be a number")
    } else {
        443
    };
    let sni = if args.len() > 4 && !args[4].is_empty() {
        args[4].clone()
    } else {
        "dl.google.com".to_string()
    };

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
            // The client UUID is a credential too, so it comes from the command
            // line rather than a literal that would land in git history.
            let client_uuid = std::env::var("SHADOWMESH_CLIENT_UUID").ok();
            let Some(client_uuid) = client_uuid else {
                eprintln!(
                    "[probe] handshake authenticated, but skipping the round-trip:\n\
                     set SHADOWMESH_CLIENT_UUID to the VLESS UUID to exercise it."
                );
                return;
            };
            let uuid =
                uuid::Uuid::parse_str(&client_uuid).expect("SHADOWMESH_CLIENT_UUID must be a UUID");
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
