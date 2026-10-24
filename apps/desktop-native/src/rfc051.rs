//! RFC-051 — the manifest row's read-out contract, and the desktop's gate
//! for it.
//!
//! **Spec:** `docs/rfc/051-manifest-row-readout-contract.md` (L11, 2026-10-21).
//! **Visual spec:** `design-system/ROSTER-ROW-READOUT.md` (L6, 2026-10-21).
//!
//! ## The contract this file enforces
//!
//! RFC-051 §2.1 (**F103-9**) rules that the desktop's manifest matrix is a
//! **listing of `PublicNode`**: the row carries **four** published fields —
//! `id`, `country`, `region`, `is_online` — and **no others, in every
//! projection**. §2.2 (**F103-10**) rules that the three fields this surface
//! does not carry (`name`, `latency`, `is_sovereign`) are **removed** from the
//! Slint row type — **not** defaulted, **not** `Option`.
//!
//! ⚠️ **Why "remove the field" and not "make it optional" — the load-bearing
//! point.** Slint's `bool` has **no third state**: a Rust `Option<bool>`
//! crossing into a Slint `bool` is `None → false`, and a defaulted `bool` is
//! `false`. **Both are the fabrication.** `false` about sovereignty is a
//! jurisdictional claim about a node this client never asked about, and
//! `0ms` is a measurement nobody took. ⇒ The only representation of *"not
//! carried"* that survives into a Slint `bool` is **the absence of the
//! field** (RFC-043 **R1** — "absence, not zero" — one layer below the
//! wire).
//!
//! ⚠️ **And a field this surface does not carry has NO COLUMN.** `WITHHELD`
//! is a **cell-level** rendering — a value the surface *does* carry and
//! cannot fill (L10's **RP-10**, L6's **A-3**). A field the surface does
//! *not* carry has no cell at all, and therefore no `WITHHELD` in it: the
//! dashboard does both, and the desktop's matrix does only the second
//! (`FleetHealthPage.tsx:147` vs `:183-200`).
//!
//! ## The gate — **R12**
//!
//! > **`main.slint`'s `MeshNode` has no `is_sovereign`, `name` or `latency`
//! > field — asserted on the file.**
//!
//! This is the **structural** form, and it is the house form
//! (`src/ipc_arms.rs:255-285` — `the_projection_label_names_no_variant`).
//! ⚠️ **A behavioural test cannot substitute for it:** a `bool` field that is
//! always `false` behaves *identically* to a `bool` field that is absent, so
//! no assertion about rendered behaviour can tell *"not carried"* from
//! *"carried and false"*. Only the **source** can say it.
//!
//! ⇒ The gate reads `main.slint` and asserts the struct's field list.
//! **Negative control:** put `is_sovereign: bool` back into the struct ⇒ red
//! (RFC-051 §6.1).

use shadowmesh_core::{NodeProjection, ShadowMeshError};

/// The roster state the desktop can be in, and L6's reading for each.
///
/// These are the states L6's contract enumerates for a client that reads a
/// roster (`design-system/ROSTER-STATE-CONTRACT.md` §2.1–§2.3): the three
/// the control plane's projection can put the rows in, the two that are
/// true when there are no rows to speak of, and the one pre-roster
/// condition the desktop genuinely has — *the request is outstanding*.
///
/// ⚠️ **This is the READING layer, and it is the only layer this surface
/// carries.** L6's §2.4 names three: the **wire** name (core's — `anonymous`
/// / `full` / `local_fallback`), the **token** (L7's derivation — `ANONYMOUS`
/// / `LOCAL FALLBACK`), and the **reading** (the human short label). The
/// desktop is a **client** surface (L6 §3.4), so it carries the reading
/// **alone**: the wire name does not appear on this surface at all, not even
/// as secondary text (L6's **V-5**; L10's **RP-17**), and a token is never a
/// human label (L6's **V-4**).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterState {
    /// The control plane served the **full** projection, and it is what is on
    /// screen now.
    Full,
    /// The control plane served a **reduced** (anonymous) projection, and it
    /// is what is on screen now.
    Reduced,
    /// **No control plane was asked** — the rows were narrowed on this device.
    Local,
    /// The control plane **answered**, and this client could not read the
    /// answer.
    Unreadable,
    /// The control plane **did not answer**, and this device has no earlier
    /// copy of what it served before.
    Unavailable,
    /// The request is **outstanding** — the control plane has not answered
    /// yet.
    ///
    /// ⚠️ This is L6's §2.2 pre-roster condition `pending`, and it is a
    /// condition and not a roster: *"not asked" is not "asked and refused"*.
    Pending,
}

/// The state ids — the wire between this file and `main.slint`'s
/// `RosterStateLine`.
///
/// ⚠️ **They must match `main.slint`.** The gate
/// `the_state_ids_match_the_slint_states` (below) is what keeps the two in
/// step: renumber one side without the other and the gate goes red.
pub const STATE_ID_FULL: u8 = 0;
pub const STATE_ID_REDUCED: u8 = 1;
pub const STATE_ID_LOCAL: u8 = 2;
pub const STATE_ID_UNREADABLE: u8 = 3;
pub const STATE_ID_UNAVAILABLE: u8 = 4;
pub const STATE_ID_PENDING: u8 = 5;

impl RosterState {
    /// The state the **manifest's** projection names.
    ///
    /// ⚠️ **The manifest's projection, not the daemon's.** The rows on the
    /// desktop's matrix come from the manifest route, so the state must
    /// describe the manifest (RFC-051 §3, requirement 1). The daemon reads
    /// the **roster** route: two surfaces, two projections, and they can
    /// differ.
    ///
    /// ⚠️ **The wire name, never a variant.** The match is on core's own
    /// canonical spelling (`as_str()`), so this function **cannot break** when
    /// the core's vocabulary grows — the defect that stopped the desktop
    /// binary compiling once already
    /// (`src/ipc_arms.rs:122-153`). A wire name the core renames is caught by
    /// the core's own vocabulary-parity gate, not by a client's build.
    pub fn from_projection(projection: NodeProjection) -> Self {
        match projection.as_str() {
            "full" => RosterState::Full,
            "anonymous" => RosterState::Reduced,
            "local_fallback" => RosterState::Local,
            // A projection this client does not read. L6's `unreadable`
            // covers it: *"the control plane answered, and this client could
            // not read the answer"* — the same state as a malformed body.
            _ => RosterState::Unreadable,
        }
    }

    /// The state a **failed** read leaves the roster in.
    ///
    /// ⚠️ **The failure is classified, and the server's string is never
    /// carried** (L10's **M-2**, gate **RP-2**). A parse failure means the
    /// control plane **answered** and the answer did not read — the
    /// `unreadable` state. Everything else means no roster was served, and
    /// the roster is empty: the `unavailable` state. ⚠️ Neither of them says
    /// anything about the **account** — a 401 or a 403 is an *outcome*, not a
    /// cause the client may narrate on a client surface (L10's **R-1**).
    pub fn from_failure(error: &ShadowMeshError) -> Self {
        match error {
            // The control plane ANSWERED and the answer could not be read.
            ShadowMeshError::JsonError(_) => RosterState::Unreadable,
            // No roster was served. Nothing is known about the fleet.
            _ => RosterState::Unavailable,
        }
    }

    /// L6's **short label** for the state — the reading, and the only roster
    /// vocabulary this surface may render (L6 §2.3; L10's **RP-15**).
    ///
    /// ⚠️ **This is the state line's whole content.** L6's §6.2 row 4 drops
    /// the `MESH SYNCED — ` prefix: it is a relationship claim about the
    /// connection (L10's **M-9**), which the status card already states,
    /// and it is false in the states it cannot survive.
    pub fn label(self) -> &'static str {
        match self {
            RosterState::Full => "FULL ROSTER",
            RosterState::Reduced => "REDUCED ROSTER",
            RosterState::Local => "NOT FROM THE CONTROL PLANE",
            RosterState::Unreadable => "ROSTER UNREADABLE",
            RosterState::Unavailable => "UNAVAILABLE",
            RosterState::Pending => "READING THE ROSTER",
        }
    }

    /// L6's §2.3 **long form** — the state line's accessible **description**
    /// (L6 §3.5, A-5).
    ///
    /// ⚠️ **It names the SPEAKER and the DATA, never the ACCOUNT.** The
    /// account attribution is a separate element, and it does not exist on a
    /// client surface (L10's **R-1**).
    pub fn long_form(self) -> &'static str {
        match self {
            RosterState::Full => {
                "The control plane served the full projection, and it is what you are looking at."
            }
            RosterState::Reduced => {
                "The control plane served a reduced roster. The fields it left out are not on \
                 this screen."
            }
            RosterState::Local => {
                "These rows did not come from the control plane. They came from this device, and \
                 no server was asked for them."
            }
            RosterState::Unreadable => {
                "The control plane answered, and this client could not read the answer."
            }
            RosterState::Unavailable => {
                "The control plane did not answer, and this device has no earlier copy of what \
                 it served before."
            }
            RosterState::Pending => {
                "The control plane has not answered yet. The request is still outstanding."
            }
        }
    }

    /// The state's id — the marker shape and the state's tokens are selected
    /// by it on the Slint side (L6 §3.2, §3.3).
    pub fn id(self) -> u8 {
        match self {
            RosterState::Full => STATE_ID_FULL,
            RosterState::Reduced => STATE_ID_REDUCED,
            RosterState::Local => STATE_ID_LOCAL,
            RosterState::Unreadable => STATE_ID_UNREADABLE,
            RosterState::Unavailable => STATE_ID_UNAVAILABLE,
            RosterState::Pending => STATE_ID_PENDING,
        }
    }
}

/// Writes the roster's condition onto **its own line** (L6's
/// `sm.roster.underList`).
///
/// ⚠️ **It does not touch the status card.** The status card is the
/// **connection's** slot; the roster state's slot is the line under the
/// matrix panel. Sharing one slot is **F-7** — the defect this move exists
/// to close: the connection state overwrote the roster state, so the roster
/// state was present only when the last event happened to be a manifest read
/// (a live violation of A-10 and of L10's **RP-19**).
pub fn publish(ui: &crate::AppWindow, state: RosterState) {
    ui.set_roster_state_id(state.id() as i32);
    ui.set_roster_state_label(state.label().into());
    ui.set_roster_state_long_form(state.long_form().into());
}

#[cfg(test)]
mod tests {
    /// The module's own names — `RosterState`, and the core's
    /// `NodeProjection` / `ShadowMeshError` that the module imports.
    ///
    /// ⚠️ **This line is the difference between a gate that runs and a gate
    /// that does not exist.** Without it the whole `mod tests` failed to
    /// compile (`E0433: cannot find type RosterState in this scope`, 46
    /// errors), and a test module that does not compile is not a gate —
    /// it is a comment. Every other module in this crate opens its test
    /// module the same way (`ipc_arms.rs:157`, `attribution.rs:467`,
    /// `rfc011.rs:272`, `qr.rs:54`, `single_instance.rs:152`, `spring.rs:53`).
    use super::*;

    /// The Slint source, as it is written.
    ///
    /// `include_str!` and not a runtime read: the gate must see the file the
    /// build compiled, and it makes the test binary depend on the file — so
    /// a change to `main.slint` rebuilds the test.
    const MAIN_SLINT: &str = include_str!("main.slint");
    /// The Rust source, as it is written — for the gates that read the
    /// call sites (the house form: a gate that cannot see the thing it gates
    /// is a gate nobody has seen go red).
    const MAIN_RS: &str = include_str!("main.rs");

    /// Strips `//` comments from a source, so a gate never fires on prose.
    fn strip_comments(src: &str) -> String {
        src.lines()
            .map(|line| line.split("//").next().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The body of the balanced-brace block whose opening brace is at
    /// `brace`. Returns `None` when the block is not closed.
    fn block_after(src: &str, brace: usize) -> Option<&str> {
        let bytes = src.as_bytes();
        let mut depth = 0i32;
        let mut i = brace;
        while i < bytes.len() {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&src[brace + 1..i]);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    /// The source of one component, comments stripped.
    fn component_source(src: &str, name: &str) -> String {
        let stripped = strip_comments(src);
        let start = stripped
            .find(&format!("component {name} inherits"))
            .unwrap_or_else(|| panic!("the component `{name}` must exist"));
        let brace = start + stripped[start..].find('{').expect("a component has a body");
        block_after(&stripped, brace)
            .unwrap_or_else(|| panic!("the component `{name}` must have a closed body"))
            .to_string()
    }

    /// The field names of the Slint `MeshNode` struct, read from `main.slint`.
    ///
    /// ⚠️ **Comments are stripped before the fields are read.** A field name
    /// in a comment is a comment, and a gate that cannot tell the two is a
    /// gate that fires on prose.
    fn mesh_node_fields(slint: &str) -> Vec<&str> {
        let start = slint.find("export struct MeshNode").expect("the Slint row type must exist");
        let rest = &slint[start..];
        let end = rest.find("\n}").expect("the Slint row type must end");
        let body = &rest[..end];

        body.lines()
            .filter_map(|line| {
                let code = line.split("//").next().unwrap_or_default();
                // `match` and not `?`: the closure's return type is inferred,
                // and an operator that needs a known return type does not
                // belong in an inferred one.
                match code.trim().split_once(':') {
                    Some((name, _ty)) => {
                        let name = name.trim();
                        if name.is_empty()
                            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        {
                            return None;
                        }
                        Some(name)
                    }
                    None => None,
                }
            })
            .collect()
    }

    /// Every `#rrggbb` / `#rrggbbaa` literal in a source, upper-cased.
    fn hex_literals(src: &str) -> Vec<String> {
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'#' {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && j - start < 8 && bytes[j].is_ascii_hexdigit() {
                    j += 1;
                }
                if j > start {
                    out.push(src[start..j].to_ascii_uppercase());
                    i = j;
                    continue;
                }
            }
            i += 1;
        }
        out
    }

    /// Every `font-size:` value in a source, in px.
    fn font_sizes(src: &str) -> Vec<f32> {
        let mut out = Vec::new();
        for (idx, _) in src.match_indices("font-size:") {
            let after = &src[idx + "font-size:".len()..];
            let digits: String = after
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(value) = digits.parse::<f32>() {
                out.push(value);
            }
        }
        out
    }

    /// Every `set_status(...)` call's argument text.
    fn set_status_calls(src: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (idx, _) in src.match_indices("set_status(") {
            let after = &src[idx + "set_status(".len()..];
            let end = after.find(';').unwrap_or(after.len());
            out.push(after[..end].to_string());
        }
        out
    }

    /// **R12 — the structural gate.** The row type carries **none** of the
    /// three fields this surface does not hold.
    ///
    /// ⚠️ This is the gate that makes the fabrication **impossible** rather
    /// than **absent** (RFC-051 §10): a `bool` that is always `false` and a
    /// `bool` that is not there behave identically, so only the source can
    /// tell them apart.
    #[test]
    fn the_row_type_names_no_field_the_surface_does_not_carry() {
        let fields = mesh_node_fields(MAIN_SLINT);

        for forbidden in ["is_sovereign", "name", "latency"] {
            assert!(
                !fields.contains(&forbidden),
                "the Slint row type must not carry `{forbidden}`: the manifest row is a listing \
                 of four published fields (RFC-051 §2.1), and a boolean this surface cannot fill \
                 is `false` — which IS the fabrication (RFC-051 §2.2). The struct's fields are: \
                 {fields:?}",
            );
        }
    }

    /// The **positive** half of the same rule.
    ///
    /// L10 §8: *"Each rule gets a negative (the withheld item is absent) and a
    /// positive (the state still lands)."* ⇒ The gate must not be
    /// satisfiable by emptying the struct: the row still carries the four
    /// **published** fields.
    #[test]
    fn the_row_type_carries_the_published_fields() {
        let fields = mesh_node_fields(MAIN_SLINT);

        for published in ["id", "country", "region", "is_online"] {
            assert!(
                fields.contains(&published),
                "the Slint row type must carry the published field `{published}`: the manifest \
                 row is a listing of four published fields and no others (RFC-051 §2.1). The \
                 struct's fields are: {fields:?}",
            );
        }
    }

    /// The **reading** is L6's short label, and it is the *only* vocabulary
    /// this surface renders (L6 §2.3; L10's **RP-15**).
    #[test]
    fn the_reading_is_l6s_short_label() {
        assert_eq!(RosterState::from_projection(NodeProjection::Full).label(), "FULL ROSTER");
        assert_eq!(
            RosterState::from_projection(NodeProjection::Anonymous).label(),
            "REDUCED ROSTER"
        );
        assert_eq!(
            RosterState::from_projection(NodeProjection::LocalFallback).label(),
            "NOT FROM THE CONTROL PLANE"
        );
        assert_eq!(RosterState::Unreadable.label(), "ROSTER UNREADABLE");
        assert_eq!(RosterState::Unavailable.label(), "UNAVAILABLE");
        assert_eq!(RosterState::Pending.label(), "READING THE ROSTER");
    }

    /// The long form is L6's §2.3 canonical text, **verbatim** — it is the
    /// state line's accessible description, and a client-selected string is
    /// the only thing that may reach it (L10's **M-2**).
    #[test]
    fn the_long_form_is_l6s_canonical_text() {
        assert_eq!(
            RosterState::Full.long_form(),
            "The control plane served the full projection, and it is what you are looking at."
        );
        assert_eq!(
            RosterState::Reduced.long_form(),
            "The control plane served a reduced roster. The fields it left out are not on this \
             screen."
        );
        assert_eq!(
            RosterState::Local.long_form(),
            "These rows did not come from the control plane. They came from this device, and no \
             server was asked for them."
        );
        assert_eq!(
            RosterState::Unreadable.long_form(),
            "The control plane answered, and this client could not read the answer."
        );
        assert_eq!(
            RosterState::Unavailable.long_form(),
            "The control plane did not answer, and this device has no earlier copy of what it \
             served before."
        );
        assert_eq!(
            RosterState::Pending.long_form(),
            "The control plane has not answered yet. The request is still outstanding."
        );
    }

    /// **RP-17** — the token layer is never a human label, and on a client
    /// surface the wire name does not appear at all (L6's **V-4**, **V-5**).
    ///
    /// ⚠️ The check is the **shape** of the line: it is the reading, alone.
    /// The substring form of this test cannot be used for `full`: `FULL` is
    /// both a token and the first word of `FULL ROSTER`, and the shape test
    /// tells the two apart where the substring test cannot.
    #[test]
    fn the_state_line_is_the_reading_and_never_the_token() {
        for projection in
            [NodeProjection::Full, NodeProjection::Anonymous, NodeProjection::LocalFallback]
        {
            let state = RosterState::from_projection(projection);
            for token in ["ANONYMOUS", "LOCAL FALLBACK", "CONFIRMED"] {
                assert!(
                    !state.label().contains(token),
                    "the token layer must never be a human label (L6's V-4; L10's RP-17): the \
                     line was `{}`",
                    state.label(),
                );
            }
            // And the line is the SHORT LABEL ALONE — no prefix, no suffix.
            assert!(
                state.label() == state.label().trim(),
                "the state line is the short label, alone (L6's §6.2 row 4): `{}`",
                state.label(),
            );
        }
    }

    /// **M-9** — the `MESH SYNCED` relationship claim is DROPPED.
    ///
    /// ⚠️ L6's §6.2 row 4: *"the `MESH SYNCED — ` prefix is DROPPED … it is
    /// a relationship claim about the connection, which the status card
    /// already states, and it is false in the states it cannot survive."*
    ///
    /// ⇒ The state line is the **short label alone**, in every state.
    #[test]
    fn the_state_line_never_claims_a_relationship() {
        for state in [
            RosterState::Full,
            RosterState::Reduced,
            RosterState::Local,
            RosterState::Unreadable,
            RosterState::Unavailable,
            RosterState::Pending,
        ] {
            assert!(
                !state.label().contains("SYNCED"),
                "the state line must not claim a relationship with the control plane (L10's \
                 M-9; L6's §6.2 row 4): {}",
                state.label(),
            );
        }
        assert!(
            !MAIN_RS.contains("MESH SYNCED"),
            "the `MESH SYNCED` prefix is dropped from the desktop (L6's §6.2 row 4): it is a \
             relationship claim about the connection, which the status card already states.",
        );
    }

    /// 🔴 **F-7 — the roster state must never be written into the
    /// connection's status slot.**
    ///
    /// The desktop's status area is **single-slot**: every status went into
    /// one string, rendered as the status card's 20px main line — the same
    /// slot the roster state was written into. ⇒ The roster state line was
    /// present only when the last event happened to be a manifest read, which
    /// is a live violation of A-10 and L10's **RP-19**.
    ///
    /// **Negative control:** write `ui.set_status(state.label().into())` ⇒ red.
    #[test]
    fn the_roster_state_is_never_written_into_the_connection_status() {
        for call in set_status_calls(MAIN_RS) {
            assert!(
                !call.contains("roster")
                    && !call.contains("Roster")
                    && !call.contains("status_line"),
                "the roster state must be published on its OWN line, never into the connection's \
                 status slot (F-7; L6's §6.2 row 1): the call was `set_status({call})`.",
            );
        }
    }

    /// **R10** — no `MeshNode` literal names a field the surface does not
    /// carry, and the fabricated startup row does not come back.
    ///
    /// The literal in the refresh handler is the legitimate builder (the four
    /// published fields); what must not exist is a *hand-built* row.
    #[test]
    fn no_mesh_node_literal_names_a_field_the_surface_does_not_carry() {
        for (idx, _) in MAIN_RS.match_indices("MeshNode {") {
            let after = &MAIN_RS[idx + "MeshNode {".len()..];
            let end = after.find('}').unwrap_or(after.len());
            let literal = &after[..end];
            for forbidden in ["name:", "latency:", "is_sovereign:"] {
                assert!(
                    !literal.contains(forbidden),
                    "a `MeshNode` literal must not name `{forbidden}`: the row is a listing of \
                     four published fields (RFC-051 §2.1). The literal was: {{{literal}}}",
                );
            }
        }
    }

    /// **AC-12.4** — a failed read leaves the roster **EMPTY**, not standing.
    #[test]
    fn a_failed_read_leaves_the_matrix_empty() {
        let marker = MAIN_RS.find("Manifest read failed").expect("the failure arm must log");
        // The arm's own start, so the window is the ERROR arm and not the
        // success arm above it.
        let arm_start = MAIN_RS[..marker].rfind("Err(e) =>").unwrap_or(0);
        let arm = &MAIN_RS[arm_start..];
        let arm = &arm[..arm.len().min(4000)];
        assert!(
            arm.contains("set_nodes("),
            "a failed manifest read must CLEAR the roster: the rows on screen would otherwise be \
             the previous fetch's rows, which says the control plane served them NOW \
             (RFC-051 §5, fact 2; L10's AC-12.4).",
        );
        assert!(
            arm.contains("set_country_groups("),
            "a failed manifest read must clear the grouped view too, or the section headers would \
             outlive their rows (L10's AC-12.4).",
        );
    }

    /// 🔴 **L6's gate 1** — the manifest matrix renders **no** `WITHHELD`,
    /// **no** `false`, **no** `0ms`, **no** em dash, and **no** empty
    /// primary line.
    ///
    /// ⚠️ These are **string** gates, not colour gates: a colour gate cannot
    /// see a word, and a state is a word.
    #[test]
    fn the_row_renders_no_forbidden_word() {
        let row = component_source(MAIN_SLINT, "NodeRow");
        for forbidden in ["WITHHELD", "0ms", "false", "—", "latency", "sovereign"] {
            assert!(
                !row.contains(forbidden),
                "the row must render no `{forbidden}`: a field this surface does not carry has NO \
                 COLUMN (RFC-051 §2.3; L10's RP-10), and a latency is a measurement nobody took.",
            );
        }
    }

    /// 🔴 **L6's gate 2** — the row renders **no** latency, **no** peer name,
    /// and **no** sovereignty marker.
    ///
    /// **Negative control:** add the stripe back ⇒ red.
    #[test]
    fn the_row_renders_no_latency_no_name_and_no_sovereignty_marker() {
        let row = component_source(MAIN_SLINT, "NodeRow");
        for forbidden in ["node.name", "node.latency", "node.is_sovereign"] {
            assert!(
                !row.contains(forbidden),
                "the row must not render `{forbidden}`: it is a field this surface does not carry \
                 (RFC-051 §2.1).",
            );
        }
    }

    /// 🔴 **L6's gate 4** — the hex values `main.slint` uses for the row are
    /// the **token values** in `tokens.json`, and there are **no new
    /// colours**.
    ///
    /// The desktop has no token layer of its own (`tokens.json` → OQ-4), so
    /// the rule is on the **value**: the desktop renders the token's value,
    /// and the value in `main.slint` must be the token's value.
    #[test]
    fn the_row_uses_the_token_values_and_no_new_colour() {
        let row = component_source(MAIN_SLINT, "NodeRow");
        let header = component_source(MAIN_SLINT, "CountryHeader");

        // The six tokens L6's §8.1 names, and the row's own surface literals.
        let row_allowed = [
            "F1F5F9",   // --cmd-text-strong — the id
            "B6C2CF",   // --cmd-text-aaa-dim — the region
            "10B981",   // --cmd-online — the ONLINE marker
            "EF4444",   // --cmd-offline — the OFFLINE marker
            "34D399",   // --cmd-online-aaa — the ONLINE word
            "FCA5A5",   // --cmd-offline-aaa — the OFFLINE word
            "FFFFFF05", // the row's fill at rest
            "FFFFFF0D", // the row's fill, hovered
            "FFFFFF0A", // the row's border at rest
            "6366F155", // the row's border, hovered
        ];
        let header_allowed = ["B6C2CF", "1E293B"]; // the dim text and the decorative rule

        for literal in hex_literals(&row) {
            assert!(
                row_allowed.contains(&literal.as_str()),
                "the row must use L6's token values and nothing else — a new colour is a new \
                 unmeasured claim (L6's §8.1, §8.3). The literal was `#{literal}`.",
            );
        }
        for literal in hex_literals(&header) {
            assert!(
                header_allowed.contains(&literal.as_str()),
                "the section header must use L6's token values and nothing else. The literal \
                 was `#{literal}`.",
            );
        }

        // And the six tokens are all actually used.
        for token in ["F1F5F9", "B6C2CF", "10B981", "EF4444", "34D399", "FCA5A5"] {
            assert!(
                row.to_ascii_uppercase().contains(token),
                "the row must carry the `{token}` token (L6's §8.1).",
            );
        }
    }

    /// 🔴 **A-4 — the type floor.** Every text element in the row and in the
    /// section header is **12px**.
    ///
    /// ⚠️ This is the gate for the defect L6's measurement found: the region
    /// line was **8px at 3.76:1** and the id was **11px** — both under the
    /// floor, and both pre-existing (L6's §7.1).
    #[test]
    fn the_row_and_the_header_meet_the_type_floor() {
        let row = component_source(MAIN_SLINT, "NodeRow");
        let header = component_source(MAIN_SLINT, "CountryHeader");

        for (what, source) in [("the row", &row), ("the section header", &header)] {
            for size in font_sizes(source) {
                assert!(
                    size >= 12.0,
                    "{what} must be at least 12px (WCAG 1.4.6 AAA, A-4): a text element below \
                     the floor is a legibility failure whatever its contrast. The size was \
                     {size}px.",
                );
            }
        }
    }

    /// **A-5** — the row is **one merged accessible node** whose name carries
    /// the visible words, and the loose text fragments inside it are not
    /// separate nodes.
    #[test]
    fn the_row_is_one_merged_accessible_node() {
        let row = component_source(MAIN_SLINT, "NodeRow");

        assert!(row.contains("accessible-role:"), "the row must be one accessible node (A-5).",);
        assert!(
            row.contains("accessible-label:"),
            "the row's accessible name must carry the visible words — `<id>, <region>, ONLINE` \
             (A-5).",
        );

        let texts = row.matches("Text {").count();
        let silenced = row.matches("accessible-role: none").count();
        assert!(
            texts > 0 && silenced >= texts,
            "every Text inside the row must carry `accessible-role: none`, or the row is \
             announced as loose fragments instead of one merged node (A-5). Found {texts} Text \
             elements and {silenced} silenced ones.",
        );
    }

    /// **A-6 / RP-14** — no live region, anywhere.
    #[test]
    fn no_surface_is_a_live_region() {
        assert!(
            !MAIN_SLINT.contains("accessible-live-region"),
            "the roster surface must carry NO live region (A-6; L10's RP-14): a screen-reader \
             announcement is audible in a café, and is the worst possible surface for \
             shoulder-surfing.",
        );
    }

    /// 🔴 **M-7 / RP-20** — a disguised posture suppresses the roster state
    /// line **whole**.
    ///
    /// ⚠️ This is a posture-level suppression of the **surface**, never a
    /// state-level removal of a state: the line is present in every state
    /// otherwise (A-10, M-6, RP-19).
    ///
    /// **Negative control:** render the line anyway ⇒ red.
    #[test]
    fn a_disguised_posture_suppresses_the_state_line() {
        let stripped = strip_comments(MAIN_SLINT);
        let start =
            stripped.find("RosterStateLine {").expect("the state line must be instantiated");
        let instance = &stripped[start..];
        let end = instance.find('}').expect("the instance must be closed");
        let instance = &instance[..end];

        assert!(
            instance.contains("visible:"),
            "the state line must be bound to `visible` so a disguised posture can suppress it \
             (L10's M-7, RP-20).",
        );
        assert!(
            instance.contains("camouflage_active"),
            "the state line must be suppressed in a disguised posture: a roster-state line under \
             a list reveals the PRODUCT'S PRESENCE (L10's M-7, RP-20).",
        );
    }

    /// **L6's gate 3 / RP-19** — the state line is present in **every** state,
    /// including `FULL ROSTER`, and its content is one of L6's §2.3
    /// readings.
    ///
    /// ⚠️ The line's *presence* carries no information; only its *content*
    /// does (A-10, M-6). **Negative control:** blank the `FULL ROSTER`
    /// label ⇒ red.
    #[test]
    fn the_state_line_is_present_in_every_state() {
        let readings = [
            RosterState::Full,
            RosterState::Reduced,
            RosterState::Local,
            RosterState::Unreadable,
            RosterState::Unavailable,
            RosterState::Pending,
        ];
        for state in readings {
            assert!(
                !state.label().is_empty(),
                "the state line must render in EVERY state, and its content is never empty \
                 (A-10; L10's RP-19).",
            );
            assert!(
                state.long_form().len() > 10,
                "every state must carry the §2.3 long form as its accessible description \
                 (L6's §3.5, A-5).",
            );
        }
    }

    /// The state ids on the Rust side and the state ids in `main.slint` are
    /// the same ids.
    ///
    /// ⚠️ The Slint side selects the marker shape and the state's tokens by
    /// the id, so a renumbering on one side alone would put the WRONG shape
    /// and the WRONG tokens on a state — and the greyscale and contrast
    /// assertions would still be true of the wrong element.
    #[test]
    fn the_state_ids_match_the_slint_states() {
        for state in [
            RosterState::Full,
            RosterState::Reduced,
            RosterState::Local,
            RosterState::Unreadable,
            RosterState::Unavailable,
            RosterState::Pending,
        ] {
            let marker = format!("state {} — {}", state.id(), state.label());
            assert!(
                MAIN_SLINT.contains(&marker),
                "`main.slint`'s state line must name state {} as `{}`: the Rust side and the \
                 Slint side number the states the same way, or the marker shape and the state's \
                 tokens would be attached to the wrong state.",
                state.id(),
                state.label(),
            );
        }
    }

    /// The failure is **classified**, and the classification is the honest one
    /// (L6 §2.2): a parse failure means the control plane **answered**.
    #[test]
    fn a_parse_failure_is_unreadable_and_any_other_failure_is_unavailable() {
        assert_eq!(
            RosterState::from_failure(&ShadowMeshError::JsonError("missing field".into())),
            RosterState::Unreadable
        );
        assert_eq!(
            RosterState::from_failure(&ShadowMeshError::ConnectionFailed),
            RosterState::Unavailable
        );
        assert_eq!(
            RosterState::from_failure(&ShadowMeshError::Forbidden("session expired".into())),
            RosterState::Unavailable,
            "a refusal is an outcome, not a roster, and the account event is never narrated on a \
             client surface (L10's R-1)",
        );
    }

    /// 🔴 **R-F103 — the roster NEVER enters the connect surface.**
    ///
    /// RFC-050 §2.1: *a **listing** surface carries `PublicNode`; a **connect**
    /// surface carries `VPNNode`.* The desktop's core `VPNManager` is the
    /// **connect** surface (`set_nodes(sequence<VPNNode>)`, `get_best_node()`,
    /// `initiate_connection(VPNNode, …)` — `shadowmesh.udl:475-479`), and the
    /// manifest's rows are `PublicNode`s.
    ///
    /// ⚠️ **Why this is a source gate and not a compile error.** The two types
    /// do not overlap, so `vpn.set_nodes(manifest.nodes)` was a **type error**
    /// and the tree stopped compiling — which is a loud, temporary gate. The
    /// moment somebody adds a conversion — a `From`, a `map`, a hand-built
    /// `VPNNode` — the type stops complaining and the **fabrication** arrives:
    /// a connect row whose `endpoint` and `public_key` were invented, which
    /// is the defect the Anycast synthesis was removed for (RFC-050 §6 item 6).
    ///
    /// ⇒ The gate reads the call sites. A behavioural assertion cannot catch
    /// this: a synthesised row *behaves* like a row.
    ///
    /// **Negative control:** put `vpn.set_nodes(manifest.nodes.clone());` back
    /// into `main.rs` ⇒ red.
    #[test]
    fn the_roster_never_enters_the_connect_surface() {
        let src = strip_comments(MAIN_RS);

        for forbidden in
            ["set_nodes(", "get_best_node(", "initiate_connection(", "set_selected_node("]
        {
            // `set_nodes` is BOTH the FFI connect surface's accessor
            // (`VPNManager::set_nodes(sequence<VPNNode>)`) and the Slint
            // property the LISTING feeds (`ui.set_nodes(ModelRc<…>)`).
            // Receiver-blind, the gate would refuse the listing's own feeder,
            // which is why the rule is per-line and receiver-aware: only a
            // call whose receiver is the Slint root (`ui.`) may carry that
            // name, because that one takes the listing row — everything else
            // takes or returns a `VPNNode`, the **connect** row.
            if forbidden == "set_nodes(" {
                for line in src.lines() {
                    if !line.contains("set_nodes(") {
                        continue;
                    }
                    assert!(
                        line.trim_start().starts_with("ui.set_nodes("),
                        "the roster must never enter the connect surface (RFC-050 §2.1, §3.3 \
                         item 1): `main.rs` calls `{line}` — a `set_nodes(` whose receiver is \
                         not the Slint root takes a `VPNNode`, the **connect** row. The \
                         manifest's rows are `PublicNode`s, the **listing** row, and turning \
                         one into the other means inventing the connect material the listing \
                         does not carry (RFC-050 §6 item 6). The desktop selects by the \
                         **filter** (RFC-050 §2.5) and hands the daemon an **id**.",
                    );
                }
                continue;
            }
            assert!(
                !src.contains(forbidden),
                "the roster must never enter the connect surface (RFC-050 §2.1, §3.3 item 1): \
                 `main.rs` calls `{forbidden}`, which takes or returns a `VPNNode` — the \
                 **connect** row. The manifest's rows are `PublicNode`s, the **listing** row, \
                 and turning one into the other means inventing the connect material the \
                 listing does not carry (RFC-050 §6 item 6). The desktop selects by the \
                 **filter** (RFC-050 §2.5) and hands the daemon an **id**.",
            );
        }
    }

    /// The **positive** half of the same rule: the desktop **does** apply the
    /// filter, and it does it with the daemon's own function — one
    /// implementation of the rule, not two (RFC-050 §2.5).
    #[test]
    fn the_selection_is_the_filter_and_not_a_ranking() {
        let src = strip_comments(MAIN_RS);

        assert!(
            src.contains("select_best_public_node("),
            "the desktop's selection must be the **filter** (RFC-050 §2.5: the first **online** \
             row, in the server's own SQL order), applied with the daemon's own function — \
             `shadowmesh_daemon::select_best_public_node` — so there is one implementation of \
             the rule and not two.",
        );
        assert!(
            !src.contains("score_node("),
            "the desktop must not rank the roster: a ranking reads score fields the anonymous \
             projection does not carry (RFC-050 §2.5, RFC-043 R3 — *the roster is a filter, \
             never a ranking*).",
        );
    }
}
