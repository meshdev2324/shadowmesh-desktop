//! The daemon's IPC response arms, read the way an untagged union has to be
//! read.
//!
//! ## Why this file exists
//!
//! The daemon's response payload is an **untagged** union
//! (`shadowmesh_daemon::types::VpnResponseData`), so serde tries the arms in
//! declaration order and takes the first that matches. Two of the arms —
//! `Status(Value)` and `Generic(Value)` — match *any* JSON value, so an arm
//! declared before them is **unreachable on the wire**.
//!
//! That is not a theoretical hazard, and this tree paid for it: the daemon
//! used to declare `Status` second, which made the desktop's `QrToken` arm
//! unreachable. The pairing request answered `{"token": "…"}`, the daemon's
//! answer was swallowed whole by the catch-all, and the desktop's pairing path
//! could only ever fail — while the daemon reported success. The daemon's arms
//! are ordered now (the catch-alls last), so the desktop reads the arm it
//! means — and this file is where that is done, once, so the next arm cannot
//! be reintroduced silently.
//!
//! ## The two rules this file keeps
//!
//! 1. **An arm is named, never printed.** `Debug` on the union would print
//!    the pairing token, and the payload of a `Status` blob is whatever the
//!    daemon happened to answer with. So every error path here names the arm
//!    and says nothing about its contents.
//! 2. **A projection is read, never inferred.** The roster's projection is the
//!    *server's* statement about what it applied. A client that cannot read it
//!    says so; it does not guess "anonymous because it usually is" (RFC-047
//!    §2.6 — absent must be an error, not a default).

use shadowmesh_daemon::types::{NodeProjection, VpnResponse, VpnResponseData};

/// The name of the arm a response carried.
///
/// **Exhaustive on purpose.** If the daemon adds an arm, this stops compiling
/// rather than naming it "something else" — which is the whole point of an
/// untagged union with catch-alls in it (RFC-043 §3.4: a consumer that has to
/// handle a case must be *forced* to handle it).
pub fn response_arm_name(data: &VpnResponseData) -> &'static str {
    match data {
        VpnResponseData::Version { .. } => "version",
        VpnResponseData::Nodes(_) => "roster",
        VpnResponseData::Identity(_) => "identity",
        VpnResponseData::QrToken { .. } => "qr-token",
        VpnResponseData::Logs(_) => "logs",
        VpnResponseData::Token(_) => "token",
        VpnResponseData::Status(_) => "status",
        VpnResponseData::Generic(_) => "generic",
    }
}

/// The pairing token out of a `QrAuth { Generate }` answer.
///
/// **Why this is not a `match` in the caller.** The desktop's pairing path
/// used to match `VpnResponseData::QrToken { token }` inline and fall through
/// to the daemon's message for everything else. That was wrong twice over
/// while the daemon's arm order shadowed the `QrToken` arm: the answer could
/// not be read, and the error said nothing about what had arrived. Now the
/// arm is reachable, and this function says which arm arrived when it is not
/// the one that was asked for.
///
/// The token itself is never logged or printed — only the arm's name is.
pub fn qr_token(resp: &VpnResponse) -> anyhow::Result<String> {
    let detail = if resp.success { String::new() } else { format!(" ({})", resp.message) };
    match resp.data.as_ref() {
        Some(VpnResponseData::QrToken { token }) => Ok(token.clone()),
        Some(other) => Err(anyhow::anyhow!(
            "the daemon answered the pairing request with a `{}` payload, not a QR token{detail}",
            response_arm_name(other),
        )),
        None => {
            Err(anyhow::anyhow!("the daemon answered the pairing request with no payload{detail}",))
        }
    }
}

/// The projection the server applied to the roster, out of a `ListNodes` answer.
///
/// **The projection is read from the envelope and never inferred.** The daemon
/// publishes the roster as `{"projection": …, "nodes": [ … ]}` (RFC-047
/// §2.3(c)); the projection is the server's own statement, carried through
/// the daemon's IPC hop. If the answer is not a roster, this says which arm
/// arrived instead — and if the roster's projection cannot be read, it says
/// so rather than guessing.
pub fn roster_projection(resp: &VpnResponse) -> anyhow::Result<NodeProjection> {
    match resp.data.as_ref() {
        Some(VpnResponseData::Nodes(roster)) => Ok(roster.projection),
        Some(other) => Err(anyhow::anyhow!(
            "the daemon answered the roster request with a `{}` payload, not a roster",
            response_arm_name(other),
        )),
        None => Err(anyhow::anyhow!(
            "the daemon answered the roster request with no payload ({})",
            resp.message,
        )),
    }
}

/// The projection, as a word the UI can print.
///
/// **This is the DISPLAY form, not the wire name.** The wire name is
/// lowercase — `NodeProjection::as_str()` returns `"anonymous"` / `"full"` —
/// and it *does* exist here: the daemon re-exports core's type
/// (`apps/daemon/src/types.rs:152` — `pub use shadowmesh_core::{NodeProjection,
/// NodeRoster};`), so this crate's `NodeProjection` **is** core's type and
/// carries core's `as_str()`
/// (`libs/core-shared/shadowmesh-core/src/lib.rs:635`).
///
/// ⚠️ **This comment used to say the opposite** — that `NodeProjection::as_str`
/// "does not exist on the daemon's copy of the vocabulary". That was true
/// while the daemon declared its own vocabulary, and it stopped being true
/// when the daemon re-exported core's. A comment that outlives the code it
/// describes is a trap for the next reader, and this one would have had them
/// re-derive a vocabulary that core already owns.
///
/// The uppercase is a **presentation** choice, and only that: the status line
/// reads `MESH SYNCED — ROSTER ANONYMOUS` (`src/main.rs:481`). The word is
/// spelled here — once — rather than in the UI, so that no second place can
/// invent a third spelling.
///
/// ⚠️ **AND THIS FUNCTION NAMES NO VARIANT, ON PURPOSE.**
///
/// It used to be an exhaustive `match` over the enum's two variants. That is a
/// **client-side copy of a vocabulary the CORE owns**, across the FFI
/// boundary, and the core is actively extending it: `NodeProjection` gained a
/// third variant — `LocalFallback`, meaning *"no server was asked"* — while
/// this tree was being built, and the exhaustive match is what made the
/// desktop binary **fail to compile** (`E0004: non-exhaustive patterns:
/// NodeProjection::LocalFallback not covered`). The client-side copy of the
/// vocabulary had not been extended with it.
///
/// ⇒ **The label is DERIVED from core's own wire name**, so a variant this
/// client has never heard of still gets its own word and this function
/// **cannot break when the core's vocabulary grows**. It also means the client
/// cannot *invent* a spelling: the word comes from the one place that owns
/// it.
///
/// ⚠️ **Deriving is not the same as guessing.** A projection this client does
/// not recognise is printed with **its own** name, never with one of the two
/// known ones. Printing "ANONYMOUS" for a projection the server never
/// narrowed is F86's exact failure — *"I did not ask"* recorded as *"this is
/// what there is"* — and it would be wrong precisely when the device is most
/// degraded (RFC-049 §15.3.3).
///
/// ⚠️ **And this function is not where the projection comes from.** The
/// projection is **read** from the roster's envelope ([`roster_projection`]),
/// never inferred: it is the server's own statement about what it applied,
/// and a client that cannot read it says so rather than guessing
/// (RFC-047 §2.6). This function only spells the word the envelope carried.
pub fn projection_label(projection: NodeProjection) -> String {
    projection.as_str().replace('_', " ").to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn response(data: Option<VpnResponseData>) -> VpnResponse {
        VpnResponse { success: true, message: "OK".into(), data }
    }

    #[test]
    fn the_qr_token_arm_is_read() {
        // The red-proof for the arm order: while the daemon declared
        // `Status(Value)` before this arm, `{"token": "…"}` was swallowed by
        // the catch-all and this read could never succeed.
        let resp = response(Some(VpnResponseData::QrToken { token: "tok-123".into() }));
        assert_eq!(qr_token(&resp).expect("the token arm must be readable"), "tok-123");
    }

    #[test]
    fn a_catch_all_blob_is_not_read_as_a_token() {
        // The same payload, delivered through the arm that matches anything.
        // The answer must be refused — and the refusal must not echo the
        // payload, which is where the pairing token lives.
        let resp = response(Some(VpnResponseData::Status(json!({ "token": "tok-secret" }))));
        let err = qr_token(&resp).expect_err("a status blob is not a token").to_string();
        assert!(err.contains("status"), "the error must name the arm: {err}");
        assert!(!err.contains("tok-secret"), "the error must not echo the payload: {err}");
    }

    #[test]
    fn a_missing_payload_is_reported_as_such() {
        let resp =
            VpnResponse { success: false, message: "API Error: no session".into(), data: None };
        let err = qr_token(&resp).expect_err("there is no token to read").to_string();
        assert!(err.contains("no payload"), "{err}");
        assert!(err.contains("no session"), "the daemon's own reason belongs in the error: {err}");
    }

    #[test]
    fn the_roster_projection_is_read_from_the_envelope() {
        let roster = shadowmesh_daemon::types::NodeRoster {
            projection: NodeProjection::Anonymous,
            nodes: Vec::new(),
        };
        let resp = response(Some(VpnResponseData::Nodes(roster)));
        assert_eq!(
            roster_projection(&resp).expect("the roster arm must be readable"),
            NodeProjection::Anonymous
        );
    }

    #[test]
    fn a_catch_all_blob_is_not_read_as_a_roster() {
        // The exact failure RFC-043 §3.4 names: under `untagged`, with the
        // catch-all ahead of the specific arms, the roster came back as an
        // opaque blob and no consumer could match on the projection.
        let resp = response(Some(VpnResponseData::Status(json!({
            "projection": "anonymous",
            "nodes": []
        }))));
        let err = roster_projection(&resp).expect_err("a status blob is not a roster").to_string();
        assert!(err.contains("status"), "the error must name the arm: {err}");
    }

    /// The label the UI prints is the DISPLAY form, and it is not the wire
    /// name.
    ///
    /// The test used to be called `the_projection_label_is_the_wire_name`,
    /// which was wrong twice over: the wire name is lowercase and it lives on
    /// core's `as_str()`, which this crate can call. The name is pinned here
    /// so that the two forms cannot be confused for one another again.
    #[test]
    fn the_projection_label_is_the_display_form_not_the_wire_name() {
        assert_eq!(projection_label(NodeProjection::Anonymous), "ANONYMOUS");
        assert_eq!(projection_label(NodeProjection::Full), "FULL");

        // The wire name exists — core's `as_str()`, on the type the daemon
        // re-exports — and it is NOT what the UI prints.
        assert_eq!(NodeProjection::Anonymous.as_str(), "anonymous");
        assert_eq!(NodeProjection::Full.as_str(), "full");
    }

    /// The label is **derived** from the wire name, and that derivation is
    /// what makes it forward-compatible.
    ///
    /// The invariant, stated so that it is checkable: the display word is the
    /// wire name, uppercased, with the wire's underscores turned into spaces.
    /// A variant this client has never heard of therefore still gets its own
    /// word — derived, not guessed, and never one of the two known ones.
    #[test]
    fn the_projection_label_is_derived_from_the_wire_name() {
        for projection in [NodeProjection::Anonymous, NodeProjection::Full] {
            assert_eq!(
                projection_label(projection),
                projection.as_str().replace('_', " ").to_uppercase(),
                "the display word must be derived from the wire name, not spelled a second time",
            );
        }
    }

    /// The **structural** red-proof: the label function names NO variant.
    ///
    /// This is the guard for the defect this file just fixed. An exhaustive
    /// `match` over the core's vocabulary is a client-side copy of a
    /// vocabulary the core owns and extends — and when the core grew
    /// `LocalFallback`, the desktop binary stopped compiling. A behavioural
    /// test cannot catch that: the function behaves correctly for every
    /// variant it knows and still refuses to build the moment the core adds
    /// one. Only the **source** can say it.
    ///
    /// ⚠️ The test reads its own source file, which is the same shape as the
    /// dashboard's `rosterReaders` gate. It is scoped to the function's own
    /// body, so the `#[cfg(test)]` module below — which necessarily names
    /// variants — does not trip it.
    #[test]
    fn the_projection_label_names_no_variant() {
        let source = include_str!("ipc_arms.rs");
        let start = source
            .find("pub fn projection_label")
            .expect("the projection label function must exist");
        let rest = &source[start..];
        let end = rest.find("\n}").expect("the projection label function must end");
        let body = &rest[..end];

        assert!(
            !body.contains("NodeProjection::"),
            "the projection label must not name a variant of the core's vocabulary: the core \
             owns that vocabulary and extends it, and a client-side copy of the variant set \
             breaks the client the moment the core grows one. The function body was:\n{body}",
        );
    }
}
