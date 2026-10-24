//! The daemon's IPC union, read **from the wire**.
//!
//! # Why this file exists, and why it is separate from `ipc_arms.rs`
//!
//! `ipc_arms.rs` holds the desktop's readers and tests them by constructing
//! the enum value directly. That proves the **matcher** works. It cannot prove
//! the **decoder** does, and the decoder is where the defect was.
//!
//! `VpnResponseData` is an **untagged** union, so serde tries the arms **in
//! declaration order** and takes the first that matches. Two arms —
//! `Status(serde_json::Value)` and `Generic(serde_json::Value)` — match *any*
//! JSON value, so an arm declared before them is **unreachable on the wire**.
//! While the catch-all sat ahead of `QrToken`, the daemon's `{"token": "…"}`
//! answer was swallowed by it and the desktop's pairing read could only fail,
//! with an error that said nothing about what had arrived.
//!
//! Every assertion below therefore starts from **the JSON the daemon
//! actually sends** and deserialises it, so the arm order is exercised rather
//! than assumed. A test that builds `VpnResponseData::QrToken { .. }` by hand
//! passes no matter how the arms are ordered — it is not a red-proof of
//! anything.
//!
//! # What the daemon sends
//!
//! `apps/daemon/src/ipc.rs` answers a pairing request with
//! `data: Some(VpnResponseData::QrToken { token })`, which serialises to
//! `{"token": "…"}`; and a roster request with the envelope
//! `{"projection": "anonymous" | "full", "nodes": [ … ]}`
//! (RFC-047 §2.3(c)).

use shadowmesh_daemon::types::{NodeProjection, VpnResponse};

/// The daemon's answer to a pairing-token request, verbatim on the wire.
const QR_TOKEN_PAYLOAD: &str = r#"{"success":true,"message":"","data":{"token":"SESSION-TOKEN"}}"#;

/// The daemon's answer to a roster request: the envelope, verbatim.
const ANONYMOUS_ROSTER_PAYLOAD: &str = r#"{"success":true,"message":"","data":{"projection":"anonymous","nodes":[{"id":"3","country":"SG","region":"SG","is_online":true}]}}"#;

/// The daemon's answer to a roster request that carries **no** projection.
const PROJECTIONLESS_ROSTER_PAYLOAD: &str = r#"{"success":true,"message":"","data":{"nodes":[]}}"#;

/// An answer that matches no specific arm.
const OPAQUE_PAYLOAD: &str = r#"{"success":true,"message":"","data":{"unexpected":"shape"}}"#;

fn parse(payload: &str) -> VpnResponse {
    serde_json::from_str(payload)
        .unwrap_or_else(|e| panic!("the daemon's answer must parse: {e}\n{payload}"))
}

/// **The regression guard.** The desktop's pairing read must reach the
/// `QrToken` arm — not the catch-all.
///
/// Before the daemon's arm order was fixed, this payload deserialised into
/// `Status(Value)` and the read failed: the pairing token was unreadable, and
/// nothing said why.
#[test]
fn the_pairing_token_is_read_from_the_daemons_answer() {
    let response = parse(QR_TOKEN_PAYLOAD);
    assert_eq!(
        crate::ipc_arms::qr_token(&response).expect("the daemon answered with a token"),
        "SESSION-TOKEN",
        "the desktop's pairing read must reach the `QrToken` arm; a catch-all that \
         shadows it makes the token unreadable and says nothing about why"
    );
}

/// The roster must arrive as the **roster** arm, carrying the projection —
/// not as an opaque blob.
///
/// This is RFC-043 §3.4's shape, and the thing the arm-order fix un-shadowed:
/// a roster that arrives as `Status` is a roster whose projection no consumer
/// can *match*.
#[test]
fn the_roster_arrives_with_its_projection() {
    let response = parse(ANONYMOUS_ROSTER_PAYLOAD);
    assert_eq!(
        crate::ipc_arms::roster_projection(&response).expect("the daemon answered with a roster"),
        NodeProjection::Anonymous,
        "the roster must carry the projection the server applied"
    );
}

/// **Absent is an error, not a default** (RFC-047 §2.6).
///
/// A roster body with no `projection` must NOT become a roster with a
/// defaulted projection: a defaulted projection would let the client report
/// *"the server narrowed this"* about a roster the server never narrowed.
#[test]
fn a_roster_without_a_projection_is_not_a_roster() {
    let response = parse(PROJECTIONLESS_ROSTER_PAYLOAD);
    let err = crate::ipc_arms::roster_projection(&response)
        .expect_err("a body with no `projection` must not satisfy the roster arm")
        .to_string();
    assert!(
        err.contains("status"),
        "the error must name the arm that arrived instead — `status` is the \
         catch-all that swallowed it: {err}"
    );
}

/// The catch-all must still be reachable — otherwise the union would be
/// *narrower* than the wire, and an unexpected answer would fail to parse
/// instead of arriving as an opaque value.
///
/// (Note: `Generic` sits behind `Status` and is therefore unreachable — both
/// are `serde_json::Value` catch-alls. That is the daemon's tree, not this
/// one's; it is recorded here because a reader of this file will wonder.)
#[test]
fn the_catch_all_still_catches_what_no_specific_arm_matches() {
    let response = parse(OPAQUE_PAYLOAD);
    let err = crate::ipc_arms::roster_projection(&response)
        .expect_err("an opaque blob is not a roster")
        .to_string();
    assert!(
        err.contains("status"),
        "the catch-all must remain reachable, or an unexpected answer fails to parse: {err}"
    );
}
