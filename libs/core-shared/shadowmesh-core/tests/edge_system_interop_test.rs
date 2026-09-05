//! Edge-server system interop tests (RFC-012 G6 — native inbounds).
//!
//! Drives the FULL server composition — `ShadowMeshSystem` with real
//! protocol inbounds, the routing pipeline and the direct egress outbound —
//! and connects with real client outbounds through real sockets. This is the
//! acceptance gate for retiring the external (Xray) edge: client and server
//! roles of the same core must interop over the wire.
//!
//! Implementation Source:
//! - Specifications: VLESS / VMess / Trojan / Shadowsocks public docs (SIP007,
//!   SS2022 draft), Trojan-GFW TLS requirement.
//! - Security considerations: credentials are generated per-run (UUID/OS
//!   CSPRNG), never literals; every flow is loopback-only.

use base64::Engine as _;
use parking_lot::Mutex;
use shadowmesh_core::config::Config;
use shadowmesh_core::engine::context::ConnectionContext;
use shadowmesh_core::engine::metadata::{ConnectionMetadata, Endpoint, L4Protocol};
use shadowmesh_core::engine::ShadowMeshSystem;
use shadowmesh_core::transport::outbound::shadowsocks::ShadowsocksOutbound;
use shadowmesh_core::transport::outbound::trojan::TrojanOutbound;
use shadowmesh_core::transport::outbound::vmess::VlessOutbound;
use shadowmesh_core::transport::traits::OutboundDialer;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Per-run credential material (never literals — hygiene by construction).
fn random_password() -> String {
    hex::encode(shadowmesh_core::secure_random_bytes(16).expect("OS CSPRNG"))
}

/// SS2022 requires a base64 identity of exactly 32 raw bytes (aes-256-gcm).
fn random_identity_b64() -> String {
    base64::engine::general_purpose::STANDARD
        .encode(shadowmesh_core::secure_random_bytes(32).expect("OS CSPRNG"))
}

/// Bind an ephemeral listener, record its port, drop it — the standard
/// allocation pattern used across this test suite (a bare listening socket
/// never enters TIME_WAIT, so the inbound can rebind immediately).
async fn reserve_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    l.local_addr().expect("addr").port()
}

fn context_for(destination: Endpoint, l4: L4Protocol) -> Arc<Mutex<ConnectionContext>> {
    let mut metadata = ConnectionMetadata::new(destination);
    metadata.l4_protocol = l4;
    Arc::new(Mutex::new(ConnectionContext::new(metadata)))
}

/// The "internet": a TCP echo server the direct outbound forwards to.
async fn spawn_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, task)
}

/// A UDP echo server for the G2 reply path through the full system.
async fn spawn_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("udp bind");
    let addr = sock.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

/// Credentials + ports for one edge boot. Server settings and client
/// factories are built from the same struct, so both sides always agree.
struct EdgeCreds {
    ss_password: String,
    ss2022_identity: String,
    trojan_password: String,
    ss_port: u16,
    ss2022_port: u16,
    trojan_port: u16,
}

impl EdgeCreds {
    async fn generate() -> Self {
        Self {
            ss_password: random_password(),
            ss2022_identity: random_identity_b64(),
            trojan_password: random_password(),
            ss_port: reserve_port().await,
            ss2022_port: reserve_port().await,
            trojan_port: reserve_port().await,
        }
    }

    fn config(&self) -> Config {
        let raw = serde_json::json!({
            "inbounds": [
                {
                    "tag": "ss-in",
                    "protocol": "shadowsocks",
                    "listen": "127.0.0.1",
                    "port": self.ss_port,
                    "settings": { "method": "aes-256-gcm", "password": self.ss_password }
                },
                {
                    "tag": "ss2022-in",
                    "protocol": "shadowsocks",
                    "listen": "127.0.0.1",
                    "port": self.ss2022_port,
                    "settings": {
                        "method": "2022-blake3-aes-256-gcm",
                        "password": self.ss2022_identity
                    }
                },
                {
                    "tag": "trojan-in",
                    "protocol": "trojan",
                    "listen": "127.0.0.1",
                    "port": self.trojan_port,
                    "settings": { "password": self.trojan_password }
                }
            ],
            "outbounds": [
                { "tag": "direct", "protocol": "direct", "settings": {} }
            ],
            "routing": { "rules": [], "default_outbound": "direct" },
            "dns": { "servers": ["1.1.1.1"] }
        });
        let config: Config = serde_json::from_value(raw).expect("edge config parses");
        config.validate().expect("structural validation");
        config.validate_strict().expect("typed settings validation");
        config
    }
}

/// Boots the edge system; call [`EdgeSystem::shutdown`] at the end of each
/// test. (No `Drop` impl on purpose: a blocking shutdown during unwinding
/// turns any assertion failure into an abort, masking the real failure.)
struct EdgeSystem(ShadowMeshSystem);

impl EdgeSystem {
    async fn boot(config: Config) -> Self {
        let mut system = ShadowMeshSystem::new(config).await.expect("system composes");
        system.start().await.expect("system starts");
        // Give the lifecycle listeners a beat to bind before clients dial.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        Self(system)
    }

    async fn shutdown(mut self) {
        if let Err(e) = self.0.shutdown().await {
            eprintln!("edge shutdown warning: {e:#}");
        }
    }
}

async fn tcp_roundtrip(outbound: &dyn OutboundDialer, echo_port: u16, payload: &[u8]) {
    let dest = Endpoint::new_ip("127.0.0.1".parse().unwrap(), echo_port);
    let ctx = context_for(dest, L4Protocol::Tcp);
    let mut stream = outbound.dial_stream(ctx).await.expect("dial through edge");
    stream.write_all(payload).await.expect("write payload");
    stream.flush().await.expect("flush");
    let mut echo = vec![0u8; payload.len()];
    stream.read_exact(&mut echo).await.expect("read echo");
    assert_eq!(echo, payload, "payload must survive the full edge roundtrip");
}

#[tokio::test]
async fn edge_system_shadowsocks_aead_and_2022_tcp_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();
    let (echo_port, echo_task) = spawn_echo().await;
    let creds = EdgeCreds::generate().await;
    let _edge = EdgeSystem::boot(creds.config()).await;

    let ss_client = ShadowsocksOutbound::new(
        "ss-client".into(),
        "127.0.0.1".into(),
        creds.ss_port,
        "aes-256-gcm".into(),
        creds.ss_password.clone(),
    )
    .expect("ss client");
    tcp_roundtrip(&ss_client, echo_port, b"edge-ss-aead-hello").await;

    let ss2022_client = ShadowsocksOutbound::new(
        "ss2022-client".into(),
        "127.0.0.1".into(),
        creds.ss2022_port,
        "2022-blake3-aes-256-gcm".into(),
        creds.ss2022_identity.clone(),
    )
    .expect("ss2022 client");
    tcp_roundtrip(&ss2022_client, echo_port, b"edge-ss2022-hello").await;

    echo_task.abort();
    _edge.shutdown().await;
}

#[tokio::test]
async fn edge_system_trojan_tcp_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();
    let (echo_port, echo_task) = spawn_echo().await;
    let creds = EdgeCreds::generate().await;
    let _edge = EdgeSystem::boot(creds.config()).await;

    let client = TrojanOutbound::new(
        "trojan-client".into(),
        "127.0.0.1".into(),
        creds.trojan_port,
        &creds.trojan_password,
    );
    tcp_roundtrip(&client, echo_port, b"edge-trojan-hello").await;

    echo_task.abort();
    _edge.shutdown().await;
}

#[tokio::test]
async fn edge_system_ss_udp_reply_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();
    let udp_echo = spawn_udp_echo().await;
    let creds = EdgeCreds::generate().await;
    let _edge = EdgeSystem::boot(creds.config()).await;

    let client = ShadowsocksOutbound::new(
        "ss-udp-client".into(),
        "127.0.0.1".into(),
        creds.ss_port,
        "aes-256-gcm".into(),
        creds.ss_password.clone(),
    )
    .expect("ss client");

    let dest = Endpoint::new_ip(udp_echo.ip(), udp_echo.port());
    let ctx = context_for(dest, L4Protocol::Udp);
    // G2 through the FULL chain: client encrypt → inbound decrypt →
    // dispatcher → direct send_packet → UDP echo → reply re-encrypted back.
    let reply = client
        .send_packet(ctx, b"edge-udp-ping", "127.0.0.1:0".parse().unwrap())
        .await
        .expect("udp through edge");
    assert_eq!(reply, b"edge-udp-ping", "UDP reply must return through the edge");
    _edge.shutdown().await;
}

// ---- RFC-015 acceptance: REALITY-wired VLESS + UDP sessions + Trojan TLS ----

/// Per-run x25519 pair for the REALITY tier (server hex / client b64url).
fn reality_keys() -> (String, String, String) {
    let (priv_raw, pub_raw) = shadowmesh_common::crypto::generate_x25519_keypair();
    (
        hex::encode(&priv_raw), // server: hex private key
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_raw), // client: b64url public key
        hex::encode(shadowmesh_core::secure_random_bytes(8).expect("CSPRNG")), // short_id
    )
}

fn vless_reality_config(
    uuid: &str,
    priv_hex: &str,
    short_id: &str,
    port: u16,
    decoy_port: u16,
) -> Config {
    let raw = serde_json::json!({
        "inbounds": [
            {
                "tag": "vless-reality",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": port,
                "settings": {
                    "uuid": uuid,
                    "decoy": format!("127.0.0.1:{decoy_port}"),
                    "reality": {
                        "private_key": priv_hex,
                        "short_ids": [short_id],
                        "sni_target": format!("127.0.0.1:{decoy_port}")
                    }
                }
            }
        ],
        "outbounds": [ { "tag": "direct", "protocol": "direct", "settings": {} } ],
        "routing": { "rules": [], "default_outbound": "direct" },
        "dns": { "servers": ["1.1.1.1"] }
    });
    let config: Config = serde_json::from_value(raw).expect("vless reality config parses");
    config.validate().expect("structural validation");
    config.validate_strict().expect("typed settings validation");
    config
}

/// THE Android-tier acceptance test: VlessOutbound with a REALITY config
/// (the exact client path the APK's universal engine uses) against the
/// native VlessInbound with REALITY — full encrypted roundtrip.
#[tokio::test]
async fn edge_system_vless_reality_tcp_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();
    let (echo_port, echo_task) = spawn_echo().await;
    let (priv_hex, pub_b64, short_id) = reality_keys();
    let uuid = uuid::Uuid::new_v4().to_string();
    let port = reserve_port().await;
    let _edge =
        EdgeSystem::boot(vless_reality_config(&uuid, &priv_hex, &short_id, port, echo_port)).await;

    let client = VlessOutbound::new(
        "vless-reality-client".into(),
        "127.0.0.1".into(),
        port,
        &uuid,
        String::new(),
        Some(shadowmesh_core::RealityConfig::new(
            "127.0.0.1".into(),
            port as u32,
            uuid.clone(),
            pub_b64,
            short_id,
            "www.example.com".into(),
            None,
        )),
    )
    .expect("vless client");

    tcp_roundtrip(&client, echo_port, b"vless-reality-encrypted").await;
    echo_task.abort();
}

/// cmd=2 (UDP) session: the outbound's UDP tunnel streams [len][payload]
/// frames through the REALITY session; the inbound relays to a UDP echo.
#[tokio::test]
async fn edge_system_vless_reality_udp_session() {
    let _ = tracing_subscriber::fmt::try_init();
    let (echo_port, echo_task) = spawn_echo().await; // TCP echo for the decoy target
    let udp_echo = spawn_udp_echo().await;
    let (priv_hex, pub_b64, short_id) = reality_keys();
    let uuid = uuid::Uuid::new_v4().to_string();
    let port = reserve_port().await;
    let _edge =
        EdgeSystem::boot(vless_reality_config(&uuid, &priv_hex, &short_id, port, echo_port)).await;

    let client = VlessOutbound::new(
        "vless-udp-client".into(),
        "127.0.0.1".into(),
        port,
        &uuid,
        String::new(),
        Some(shadowmesh_core::RealityConfig::new(
            "127.0.0.1".into(),
            port as u32,
            uuid.clone(),
            pub_b64,
            short_id,
            "www.example.com".into(),
            None,
        )),
    )
    .expect("vless client");

    // Dial in UDP mode (cmd=2) targeting the local UDP echo.
    let dest = Endpoint::new_ip(udp_echo.ip(), udp_echo.port());
    let ctx = context_for(dest, L4Protocol::Udp);
    let mut tunnel = client.dial_stream(ctx).await.expect("cmd=2 tunnel");

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let payload = b"vless-udp-frame";
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    tunnel.write_all(&frame).await.expect("frame write");
    tunnel.flush().await.expect("flush");

    // Server relays the frame to the UDP echo and frames the reply back.
    let mut reply = vec![0u8; frame.len()];
    tunnel.read_exact(&mut reply).await.expect("frame read");
    assert_eq!(&reply[2..], payload, "UDP frame must roundtrip the cmd=2 session");
    echo_task.abort();
}

/// Trojan over TLS end to end: self-signed server cert (rcgen, dev-only),
/// server-side termination via the config's `tls` block, client in
/// explicit insecure mode — header + payload through the encrypted session.
#[tokio::test]
async fn edge_system_trojan_tls_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();
    let (echo_port, echo_task) = spawn_echo().await;

    let cert = rcgen::generate_simple_self_signed(vec!["shadowmesh-edge".into()])
        .expect("cert generation");
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");

    let port = reserve_port().await;
    let raw = serde_json::json!({
        "inbounds": [ { "tag": "trojan-tls", "protocol": "trojan",
            "listen": "127.0.0.1", "port": port,
            "settings": { "password": "per-run-password",
                "tls": { "cert_path": cert_path.to_str().unwrap(),
                         "key_path": key_path.to_str().unwrap() } } } ],
        "outbounds": [ { "tag": "direct", "protocol": "direct", "settings": {} } ],
        "routing": { "rules": [], "default_outbound": "direct" },
        "dns": { "servers": ["1.1.1.1"] }
    });
    let config: Config = serde_json::from_value(raw).expect("parses");
    config.validate_strict().expect("strict validation");
    let _edge = EdgeSystem::boot(config).await;

    let client = TrojanOutbound::with_tls(
        "trojan-tls-client".into(),
        "127.0.0.1".into(),
        port,
        "per-run-password",
        Some(shadowmesh_core::transport::outbound::trojan::TlsClientParams {
            sni: "shadowmesh-edge".into(),
            insecure: true,
        }),
    );
    tcp_roundtrip(&client, echo_port, b"trojan-tls-encrypted").await;
    echo_task.abort();
}

/// RFC-015 F3: a VLESS header split across two TCP segments must still
/// parse (the old single-read path would fallback/kill such connections).
#[tokio::test]
async fn edge_system_vless_handshake_split_across_segments() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let _ = tracing_subscriber::fmt::try_init();
    let (echo_port, echo_task) = spawn_echo().await;
    let uuid = uuid::Uuid::new_v4().to_string();
    let port = reserve_port().await;

    // Plaintext VLESS inbound (no reality block).
    let raw = serde_json::json!({
        "inbounds": [ { "tag": "vless-plain", "protocol": "vless",
            "listen": "127.0.0.1", "port": port,
            "settings": { "uuid": uuid, "decoy": format!("127.0.0.1:{echo_port}") } } ],
        "outbounds": [ { "tag": "direct", "protocol": "direct", "settings": {} } ],
        "routing": { "rules": [], "default_outbound": "direct" },
        "dns": { "servers": ["1.1.1.1"] }
    });
    let config: Config = serde_json::from_value(raw).expect("parses");
    config.validate_strict().expect("strict");
    let _edge = EdgeSystem::boot(config).await;

    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.expect("connect");

    // [ver][uuid 16][addons 0][cmd 1][port 2][atyp 4 ip] = 26 bytes; split at 10.
    let mut header = Vec::new();
    header.push(0x00u8);
    header.extend_from_slice(uuid::Uuid::parse_str(&uuid).unwrap().as_bytes());
    header.push(0x00); // addons len
    header.push(0x01); // cmd connect
    header.extend_from_slice(&echo_port.to_be_bytes());
    header.push(0x01); // atyp ipv4
    header.extend_from_slice(&[127, 0, 0, 1]);

    sock.write_all(&header[..10]).await.expect("partial header");
    sock.flush().await.expect("flush partial");
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    sock.write_all(&header[10..]).await.expect("rest of header");
    sock.write_all(b"split-header-payload").await.expect("payload");
    sock.flush().await.expect("flush");

    // Server responds [ver 0][addon_len 0] before proxying.
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).await.expect("response header");
    assert_eq!(resp, [0, 0], "VLESS response header must be [0,0]");
    let mut echo = vec![0u8; b"split-header-payload".len()];
    sock.read_exact(&mut echo).await.expect("echo after split handshake");
    assert_eq!(echo, b"split-header-payload", "split handshake must parse and forward");
    echo_task.abort();
}

#[tokio::test]
async fn edge_config_rejects_typoed_inbound_settings() {
    let raw = serde_json::json!({
        "inbounds": [
            {
                "tag": "ss-in",
                "protocol": "shadowsocks",
                "listen": "127.0.0.1",
                "port": 18388,
                "settings": { "method": "aes-256-gcm", "passwrd": "typo" }
            }
        ],
        "outbounds": [
            { "tag": "direct", "protocol": "direct", "settings": {} }
        ],
        "routing": { "rules": [], "default_outbound": "direct" },
        "dns": { "servers": ["1.1.1.1"] }
    });
    let config: Config = serde_json::from_value(raw).expect("parses");
    assert!(
        config.validate_strict().is_err(),
        "typo'd inbound settings key must fail validation, never start a listener"
    );
}

#[tokio::test]
async fn edge_config_rejects_missing_inbound_settings() {
    let raw = serde_json::json!({
        "inbounds": [
            { "tag": "trojan-in", "protocol": "trojan", "listen": "127.0.0.1", "port": 18443 }
        ],
        "outbounds": [
            { "tag": "direct", "protocol": "direct", "settings": {} }
        ],
        "routing": { "rules": [], "default_outbound": "direct" },
        "dns": { "servers": ["1.1.1.1"] }
    });
    let config: Config = serde_json::from_value(raw).expect("parses");
    assert!(config.validate_strict().is_err(), "missing inbound settings must be a hard error");
}
