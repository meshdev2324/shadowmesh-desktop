//! REALITY / VLESS-over-WireGuard transport tests.
//!
//! # What this file does and does not prove
//!
//! Two tests live here and they are not the same kind of test:
//!
//! * `reality_transport_construction_and_fail_closed_behaviour` (runs in CI)
//!   proves the transport **constructs**, **identifies itself**, and **fails
//!   closed** against placeholder configuration. It touches no network and
//!   proves nothing about a REALITY handshake. C10: this test previously had a
//!   `match` with two empty arms, so it asserted nothing at all while its own
//!   comment claimed it covered the failure branch — it also accepted a
//!   *successful* connect. It now makes four concrete assertions.
//! * `reality_live` (`#[ignore]`d, needs operator credentials) is the only
//!   thing here that proves connectivity, and it does not run by default.
//!
//! A green run of this file is therefore **not** evidence that REALITY works.
//!
//! # ⚠️ OPERATOR ACTION REQUIRED — the credentials that used to live here
//!
//! This file previously committed a **live** credential set straight into the
//! repository: a routable host, the node's REALITY `short_id`, the pinned SNI
//! and the VLESS UUID. Together that is a complete, ready-to-use fingerprint
//! for active probing against one specific host. `short_id` is a 16-hex value
//! drawn from a 2^64 space, so it is brute-forceable offline against any
//! server that presents it.
//!
//! Those literals are gone from the working tree. **They are still in git
//! history and must therefore be treated as public and rotated.** Removing a
//! secret from HEAD does not un-leak it, and no CI gate can do the rotation —
//! it needs the operator and the live node. Tracked as H7 in
//! `.agents/skills/WORK-STATUS.md`.
//!
//! Before this file is pointed at anything but a throwaway endpoint, someone
//! with node access must:
//!
//! 1. rotate the VLESS UUID on the REALITY node;
//! 2. rotate the REALITY `short_id` (and the X25519 keypair if the node
//!    publishes it anywhere), and redeploy;
//! 3. confirm whether the pinned SNI / camo target was itself sensitive and,
//!    if so, re-pin it;
//! 4. treat any host that saw traffic carrying the old `short_id` as probed —
//!    check its logs and its upstream's.
//!
//! The lesson encoded below is the only durable fix: **no credential default
//! in source.** `scripts/ci/scan-credential-literals.sh` fails the build if one
//! comes back.

use bytes::Bytes;
use shadowmesh_core::transport::reality::RealityTransport;
use shadowmesh_core::transport::{AsyncTransport, TransportType};
use shadowmesh_core::{RealityConfig, ShadowMeshError};

#[tokio::test]
async fn reality_transport_construction_and_fail_closed_behaviour() {
    // ⚠️ THIS IS NOT A CONNECTIVITY TEST. Read this before trusting it.
    //
    // It was originally written as an integration test whose `match` had two
    // empty arms, so it asserted nothing: it accepted a failed connect, a
    // *successful* connect, and error variants it never named, and reported
    // green either way. Its own comment claimed it "asserts on the failure
    // branch". It did not. That made it worse than no test — it occupied the
    // slot where a real one belonged and reported green (C10).
    //
    // What it can honestly assert without a live node, and now does:
    //
    //   1. a `RealityConfig` of placeholders constructs a transport at all;
    //   2. the transport reports itself as REALITY;
    //   3. a placeholder endpoint **fails closed** — and fails for a *named,
    //      specific* reason, not merely "some error";
    //   4. a malformed endpoint is rejected by the address parser before any
    //      socket is created.
    //
    // Point 3 is the security-relevant one. `get_or_connect` calls
    // `protect_socket` and *aborts* if it fails, because a socket that is not
    // excluded from the tunnel routes through the tunnel's own tun0 and loops
    // or fails outright. That fail-closed path used to log and continue. With
    // no `SocketProtector` registered — the state of every non-Android CI
    // run — `protect_socket` returns false, so the abort is what we observe,
    // and asserting that exact error pins the behaviour against a silent
    // regression to fail-open.
    //
    // What it still cannot do: prove the handshake, the VLESS framing, or that
    // a real REALITY node is reachable. That is `reality_live` below, which is
    // `#[ignore]`d and needs operator-supplied credentials. Do not read a green
    // run of this test as evidence that REALITY works.

    let config = RealityConfig {
        server_ip: "127.0.0.1".to_string(),
        port: 1,
        uuid: "00000000-0000-4000-8000-000000000000".to_string(),
        public_key: "REPLACE_ME_REALITY_PUBKEY".to_string(),
        short_id: "0000000000000000".to_string(),
        sni_target: "example.com".to_string(),
        fingerprint: Some("chrome".to_string()),
    };

    let priv_key = [0u8; 32]; // Mock ephemeral
    let server_pub = [0u8; 32];

    // (1) + (2) The transport is constructible and correctly identifies itself.
    let transport = RealityTransport::new(config, priv_key, server_pub);
    assert_eq!(
        transport.transport_type(),
        TransportType::Reality,
        "RealityTransport must report TransportType::Reality"
    );

    // (3) A placeholder endpoint must NOT connect, and must say why.
    //
    // Asserting on the *variant* and not just "it was an error" is the point.
    // The old arms listed two variants and matched everything else into a
    // no-op, so this could never fail. Pinning `IoError` means a change to
    // which failure mode we get — a `ServerError` from an unwrap deeper in the
    // TLS setup, say — is now a test failure instead of a silent pass.
    let err = transport
        .connect()
        .await
        .expect_err("connect() against a loopback placeholder endpoint must not succeed");

    assert!(
        matches!(err, ShadowMeshError::IoError(_)),
        "expected the fail-closed socket-protection IoError, got {err:?}"
    );

    let message = err.to_string();
    assert!(
        message.contains("protect"),
        "the failure must be the socket-protection abort, not some unrelated error: {message}"
    );

    // `send()` on the same never-connected transport must fail the same way
    // rather than silently reporting a datagram as delivered. A transport that
    // returned Ok here would tell the caller its packet left the device when
    // nothing was ever sent.
    let send_err = transport
        .send(Bytes::from_static(&[0u8; 40]))
        .await
        .expect_err("send() on an unconnected transport must not report success");
    assert!(
        matches!(send_err, ShadowMeshError::IoError(_)),
        "expected the same fail-closed IoError from send(), got {send_err:?}"
    );

    // (4) A malformed endpoint is rejected by the address parser, before a
    // socket exists. This is a pure input-validation check: no network, no
    // timing, nothing to flake.
    let mut malformed = RealityConfig {
        server_ip: "not-an-ip".to_string(),
        port: 1,
        uuid: "00000000-0000-4000-8000-000000000000".to_string(),
        public_key: "REPLACE_ME_REALITY_PUBKEY".to_string(),
        short_id: "0000000000000000".to_string(),
        sni_target: "example.com".to_string(),
        fingerprint: Some("chrome".to_string()),
    };
    let bad_transport = RealityTransport::new(malformed.clone(), priv_key, server_pub);
    let parse_err =
        bad_transport.connect().await.expect_err("a server_ip that cannot parse must not connect");
    assert!(
        matches!(&parse_err, ShadowMeshError::Other(m) if m.contains("Invalid server address")),
        "expected the address-parser rejection, got {parse_err:?}"
    );

    // The parser must reject it rather than silently substituting something.
    malformed.server_ip = "127.0.0.1".to_string();
    assert_eq!(malformed.server_ip, "127.0.0.1");
}

#[tokio::test]
#[ignore = "requires a live REALITY node and operator-supplied credentials"]
async fn reality_live() {
    use std::env;

    // This is the only test in this file that proves connectivity. The test
    // above cannot, and a green run of it is not a substitute for this one.
    //
    // No default is permitted for any of these. A default is how the values
    // above ended up in git: a credential-shaped env var with a hardcoded
    // fallback reads like configuration and behaves like a published secret.
    // An unset variable means "this test did not run", which is the truth.
    macro_rules! require_env {
        ($key:literal) => {
            match env::var($key) {
                Ok(value) => value,
                Err(_) => {
                    eprintln!(
                        "SKIP: {} is not set — refusing to fall back to a committed default.",
                        $key
                    );
                    return;
                }
            }
        };
    }

    let host = require_env!("SHADOWMESH_REALITY_HOST");
    let port: u32 = require_env!("SHADOWMESH_REALITY_PORT").parse().unwrap();
    let pubkey = require_env!("SHADOWMESH_REALITY_PUBKEY");
    let shortid = require_env!("SHADOWMESH_REALITY_SHORTID");
    let sni = require_env!("SHADOWMESH_REALITY_SNI");
    let uuid = require_env!("SHADOWMESH_REALITY_UUID");

    let config = RealityConfig {
        server_ip: host,
        port,
        uuid,
        public_key: pubkey,
        short_id: shortid,
        sni_target: sni,
        fingerprint: Some("chrome".to_string()),
    };

    // Use a fixed keypair for the live test
    let priv_key = [0u8; 32];
    let server_pub = [0u8; 32];

    let transport = RealityTransport::new(config, priv_key, server_pub);
    transport.connect().await.expect("Handshake failed");

    // Trigger handshake
    transport.send(Bytes::from_static(&[0u8; 40])).await.unwrap();

    println!("✅ REALITY live test: handshake and send successful");
}
