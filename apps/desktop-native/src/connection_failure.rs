//! F101 — the desktop's **closed set** of connection failures.
//!
//! ## The rule this module implements
//!
//! L10's roster-disclosure ruling, §4.4 row 8 and gate **RP-2**:
//!
//! > **No server-authored string reaches a client surface.** The client
//! > selects its user-facing text from a **closed set** — which is exactly
//! > what the **Android** client already does (`NodeDirectory.kt`: *"the UI
//! > text is chosen by `message` so that nothing the control plane said is
//! > shown to a user unfiltered"*). **iOS and the desktop must match
//! > Android's discipline.**
//!
//! And the acceptance criteria that make it checkable
//! (`roster-disclosure-ruling.md` §18.1):
//!
//! | # | Criterion | What it means here |
//! | :--- | :--- | :--- |
//! | **AC-2.1** | The client holds a failure **class**, not a string | [`ConnectionFailure`] and [`DisconnectFailure`] |
//! | **AC-2.2** | No server-authored string is **reachable** into a render path | the daemon's `resp.message` is never interpolated, and the gate below asserts it |
//! | **AC-2.3** | The classification never reads the message | there is **no** branch anywhere that matches on the daemon's text |
//! | **AC-2.4** | The **log** carries the class label | the log lines carry `label()`, never the error's `Display` |
//! | **AC-2.5** | No client-visible string carries the account vocabulary | every label below is a **state**, and none of them names an account |
//! | **AC-2.7** | The fix did not become silence | every label says something |
//!
//! ## Why the daemon's message is not inspected
//!
//! L10 permits a server's string to be **inspected** to classify a failure,
//! and forbids it to be **carried**. This module goes one step further and
//! **does not read it at all**.
//!
//! ⇒ The desktop's own knowledge is enough to classify every case:
//!
//! * **no online row in the roster** ⇒ there is no server to dial — the
//!   client's own fact, and the roster's own state line already says why;
//! * **the daemon is not running** ⇒ the transport failed;
//! * **the daemon answered and refused** ⇒ the refusal, whose reason the
//!   client does not read;
//! * **the core's state machine refused** ⇒ classified on the **type**.
//!
//! ⇒ The daemon's message is **never** read, so it cannot leak by accident,
//! and the client's labels are its own.
//!
//! ## The shape this follows
//!
//! `RosterState::from_failure` (`rfc051.rs`) is the same shape for the roster
//! path: a **class**, a closed set of labels, and the server's string
//! classified on the **discriminant** — never on its text.

/// Why a **connect** attempt did not produce a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionFailure {
    /// The daemon answered and refused. The client does not read why — the
    /// reason is the daemon's, and the daemon's own words are not carried
    /// onto a client surface (L10's **M-2**).
    ///
    /// ⚠️ **The daemon's `message` is not read.** There is no branch
    /// anywhere that matches on it, and the gate below asserts that the
    /// field never reaches a render path.
    Refused,

    /// **There is no server to dial.** The client's own knowledge: the
    /// roster holds no **online** row (RFC-050 §2.5's filter).
    ///
    /// ⚠️ This is a fact about the **client's** roster, and the roster's own
    /// state line says which condition the roster is in. It is not a fact
    /// about the control plane, and it names no account.
    NoServers,

    /// The daemon is not running — the transport failed before any answer
    /// arrived.
    DaemonUnreachable,

    /// The core's state machine refused. Classified on the **type** of the
    /// error, never on its text (L10's **AC-2.3**).
    Core,
}

impl ConnectionFailure {
    /// The client's own label for the **status line**.
    ///
    /// ⚠️ **Every one of these is a state, and none of them names an
    /// account** (L10's **R-1**, **AC-2.5**). The set is closed: there is
    /// no way to append a reason, a session word or a timestamp to one.
    pub fn label(self) -> &'static str {
        match self {
            ConnectionFailure::Refused => "CONNECT FAILED",
            ConnectionFailure::NoServers => "NO SERVERS AVAILABLE",
            ConnectionFailure::DaemonUnreachable => {
                "DAEMON UNREACHABLE — start the ShadowMesh daemon"
            }
            ConnectionFailure::Core => "CONNECTION FAILED",
        }
    }
}

/// Why a **disconnect** did not tear the tunnel down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectFailure {
    /// The daemon answered and refused to disconnect.
    Refused,
    /// The daemon is not running — the tunnel is gone with it, and the
    /// client's own state is "disconnected".
    DaemonUnreachable,
    /// The core's state machine refused. Classified on the **type**.
    Core,
}

impl DisconnectFailure {
    /// The client's own label for the **status line**.
    ///
    /// ⚠️ **The set is closed and every label is a different state** (L6's
    /// **V-3**): a label that could be attached to a second failure is
    /// refused, so `Refused` ("the daemon answered and said no") and `Core`
    /// ("the engine's state machine refused") do not share one, even though
    /// *both* end in a not-torn-down tunnel. The user must be able to tell
    /// the two apart from the line alone.
    pub fn label(self) -> &'static str {
        match self {
            DisconnectFailure::Refused => "DISCONNECT FAILED",
            DisconnectFailure::DaemonUnreachable => "DISCONNECTED (daemon offline)",
            DisconnectFailure::Core => "DISCONNECT REFUSED",
        }
    }
}

/// The client's own label for a **pairing** that did not complete.
///
/// ⚠️ **The client's own sentence.** The daemon's pairing message is not
/// carried: it is the control plane's text, and the pairing path is a
/// client surface (L10's **M-2**).
pub const PAIRING_FAILED: &str = "PAIRING FAILED";

#[cfg(test)]
mod tests {
    use super::*;

    /// The Rust source, as it is written — the house form: a gate that cannot
    /// see the thing it gates is a gate nobody has seen go red.
    const MAIN_RS: &str = include_str!("main.rs");

    /// Strips `//` comments from a source, so a gate never fires on prose.
    fn strip_comments(src: &str) -> String {
        src.lines()
            .map(|line| line.split("//").next().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 🔴 **RP-2 — the desktop's connection path carries no server-authored
    /// string.**
    ///
    /// The seven sites this gate covers are the ones L10 named
    /// (`roster-disclosure-ruling.md` §17.3): `main.rs`'s connect,
    /// disconnect and pairing paths, where the daemon's `resp.message` and
    /// the raw transport errors used to be interpolated straight into the
    /// always-visible status line and into the log.
    ///
    /// ⚠️ **The check is structural** (L10's **AC-2.2**): *"no client-visible
    /// string is built by formatting a server-authored value."* ⇒ The gate
    /// reads the source, because a behavioural test cannot see a value that
    /// is formatted into a string.
    ///
    /// **Negative control:** put `format!("ERROR: {}", resp.message)` back
    /// into `main.rs` ⇒ red.
    #[test]
    fn the_connection_path_carries_no_server_authored_string() {
        let src = strip_comments(MAIN_RS);

        // (a) **No status line is built by formatting.** Every `set_status`
        //     takes a literal or a closed-set label.
        assert!(
            !src.contains("set_status(format!("),
            "no client-visible string may be built by formatting a value (L10's AC-2.2): \
             `main.rs` still calls `set_status(format!(...))`. The client holds a failure \
             CLASS and looks the text up from the class.",
        );

        // (b) **The daemon's message is never interpolated.** The one place
        //     it may appear is a CLOSED COMPARISON against a literal, which
        //     carries nothing (L10's §17.3: *"a closed comparison against a
        //     literal, from which nothing is carried"*).
        for line in src.lines() {
            let carries = line.contains("format!")
                || line.contains("error!")
                || line.contains("warn!")
                || line.contains("set_status");
            if carries && line.contains("resp.message") {
                assert!(
                    line.contains("== \"Pairing activated\""),
                    "the daemon's message must never be interpolated into a render path or a \
                     log line (L10's M-2, AC-2.2): `{line}`",
                );
            }
        }

        // (c) **The error's `Display` never reaches a log line** (AC-2.4).
        for line in src.lines() {
            let is_log = line.contains("error!(\"") || line.contains("warn!(\"");
            if is_log {
                assert!(
                    !line.contains("{e}") && !line.contains(", e)") && !line.contains(", e);"),
                    "the log line must carry the client's own LABEL and never the error's \
                     `Display` (L10's M-8, AC-2.4): `{line}`",
                );
            }
        }
    }

    /// The **positive** half of the same rule: the closed set is used.
    ///
    /// A gate that is satisfiable by deleting the error handling is not a
    /// gate (L10 §8: *"each rule gets a negative and a positive"*).
    #[test]
    fn the_closed_set_is_used_on_the_connection_path() {
        let src = strip_comments(MAIN_RS);

        assert!(
            src.contains("ConnectionFailure::"),
            "the connect path must classify its failure into the closed set \
             (`ConnectionFailure`) — L10's AC-2.1",
        );
        assert!(
            src.contains("DisconnectFailure::"),
            "the disconnect path must classify its failure into the closed set \
             (`DisconnectFailure`) — L10's AC-2.1",
        );
    }

    /// The closed set is **closed**: every label is a non-empty string, and
    /// no two failures share one (a label that could be attached to a second
    /// failure is refused — L6's **V-3**).
    #[test]
    fn every_failure_has_its_own_label() {
        let connections = [
            ConnectionFailure::Refused,
            ConnectionFailure::NoServers,
            ConnectionFailure::DaemonUnreachable,
            ConnectionFailure::Core,
        ];
        let labels: Vec<&str> = connections.iter().map(|f| f.label()).collect();
        for label in &labels {
            assert!(!label.is_empty(), "a failure has an empty label");
        }
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            labels.len(),
            "two failures share a label — the user cannot tell them apart",
        );

        let disconnects = [
            DisconnectFailure::Refused,
            DisconnectFailure::DaemonUnreachable,
            DisconnectFailure::Core,
        ];
        let labels: Vec<&str> = disconnects.iter().map(|f| f.label()).collect();
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            labels.len(),
            "two failures share a label — the user cannot tell them apart",
        );
    }

    /// 🔴 **AC-2.5 — no label names the account.**
    ///
    /// The account vocabulary is L10's §2.1 list. A label is a **state**, and
    /// a state never says *"your session expired"*.
    #[test]
    fn no_label_names_the_account() {
        let banned = [
            "session",
            "expired",
            "activate",
            "sign in",
            "re-authenticate",
            "entitlement",
            "lapsed",
            "revoked",
            "not activated",
            "quota",
            "subscription",
        ];

        let mut labels: Vec<&str> = vec![
            ConnectionFailure::Refused.label(),
            ConnectionFailure::NoServers.label(),
            ConnectionFailure::DaemonUnreachable.label(),
            ConnectionFailure::Core.label(),
            DisconnectFailure::Refused.label(),
            DisconnectFailure::DaemonUnreachable.label(),
            DisconnectFailure::Core.label(),
            PAIRING_FAILED,
        ];
        labels.sort_unstable();
        labels.dedup();

        for label in labels {
            let lower = label.to_lowercase();
            for word in banned {
                assert!(
                    !lower.contains(word),
                    "the client-visible label `{label}` names the account (`{word}`) — L10's \
                     R-1 and AC-2.5: a client surface may not assert a fact about the account.",
                );
            }
        }
    }
}
