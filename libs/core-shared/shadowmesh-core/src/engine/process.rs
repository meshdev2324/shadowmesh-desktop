//! Process attribution for the data path.
//!
//! The implementation moved to the sibling [`crate::engine::procfs`] module
//! when the io_uring backend landed alongside the portable one. This module
//! stays so that `engine::process::{ProcessInfo, ProcessSearcher}` -- the path
//! that predates the move -- keeps resolving for downstream consumers of this
//! `rlib`.
//!
//! It also holds [`attribute_process_identity`], the policy layer that decides
//! *whether* a lookup is meaningful. The dispatcher's `enrich_metadata` calls
//! it, and what it writes into `Identity::process_name` reaches the routing
//! rules and traffic shaping.

use crate::engine::metadata::{Addr, Identity, SourceOrigin};

pub use crate::engine::procfs::{ProcessInfo, ProcessSearcher};

/// The result of one process-attribution attempt.
///
/// Returned rather than logged-and-dropped so a caller can tell the outcomes
/// apart. `Option<String>` alone cannot: an unattributable packet and an
/// unattempted one look identical, which is how a wrong process name on inbound
/// traffic stayed invisible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessAttribution {
    /// The source is a local socket and its owning process was found.
    /// `identity.process_name` has been set.
    Resolved(ProcessInfo),
    /// `process_name` was already set before this point, so no lookup was made.
    /// Carries the name that was already there.
    AlreadyAttributed(String),
    /// The source is the far end of a connection this host accepted, so no
    /// local process can own it. `process_name` stays `None` -- correctly, not
    /// because the lookup failed.
    RemotePeer,
    /// The source is stated to be a local socket, but no local process could be
    /// resolved for it: no matching socket, no readable `/proc/[pid]/fd`, or a
    /// source address that is not an IP at all.
    Unresolved,
    /// There is no source endpoint to attribute.
    NoSource,
}

impl ProcessAttribution {
    /// The short, low-cardinality label used for the
    /// `shadowmesh_process_attribution_total` metric and the log line.
    pub fn label(&self) -> &'static str {
        match self {
            ProcessAttribution::Resolved(_) => "resolved",
            ProcessAttribution::AlreadyAttributed(_) => "already_attributed",
            ProcessAttribution::RemotePeer => "remote_peer",
            ProcessAttribution::Unresolved => "unresolved",
            ProcessAttribution::NoSource => "no_source",
        }
    }

    /// Whether this attempt is responsible for a process name -- either it
    /// resolved one, or one was already there.
    pub fn is_attributed(&self) -> bool {
        matches!(self, ProcessAttribution::Resolved(_) | ProcessAttribution::AlreadyAttributed(_))
    }

    /// Whether this attempt is a confirmed "no local process owns this", as
    /// opposed to a lookup that simply failed.
    pub fn is_remote_peer(&self) -> bool {
        matches!(self, ProcessAttribution::RemotePeer)
    }
}

/// Fill in [`Identity::process_name`] when -- and only when -- `identity.source`
/// is a socket this host owns.
///
/// [`ProcessSearcher`] resolves a port against this host's `/proc/net/tcp{,6}`,
/// so it answers "what is listening *here*", not "who is talking to us". Handing
/// it the source port of an *inbound* connection asks the wrong question: the
/// remote peer picked that port out of its own ephemeral range, and any local
/// listener sitting on the same number comes back as its owner. The resulting
/// name reaches `Condition::ProcessName` in the routing rules, so the wrong
/// answer picks a route and a shaping profile.
///
/// The origin the transport recorded is the discriminator:
///
/// * [`SourceOrigin::RemotePeer`] -- never looked up. This is the inbound case
///   and suppressing it is the fix.
/// * unstated -- also never looked up. A transport that does not state an
///   origin fails closed, so a future listener that forgets to mark itself
///   cannot reintroduce the defect by omission.
/// * [`SourceOrigin::Local`] -- looked up. This is the outbound case the feature
///   exists for: traffic this node originated really is a local socket.
///
/// Returns what happened so the caller can log and count it.
pub async fn attribute_process_identity(identity: &mut Identity) -> ProcessAttribution {
    // Someone upstream already knows. Re-resolving would overwrite a better
    // answer with a port lookup, and the existing name is not ours to drop.
    if let Some(existing) = identity.process_name.clone() {
        return ProcessAttribution::AlreadyAttributed(existing);
    }

    let Some(source) = identity.source.clone() else {
        return ProcessAttribution::NoSource;
    };

    if identity.source_origin != Some(SourceOrigin::Local) {
        return ProcessAttribution::RemotePeer;
    }

    // A local source has to be an IP. `/proc/net/tcp{,6}` is keyed by address,
    // and a `Domain` source has none to match against; falling back to a
    // port-only lookup here is the same collision as the inbound case, rarer.
    if !matches!(source.addr, Addr::Ip(_)) {
        return ProcessAttribution::Unresolved;
    }

    match ProcessSearcher::find_process_info(source.port).await {
        Some(info) => {
            identity.process_name = Some(info.name.clone());
            ProcessAttribution::Resolved(info)
        }
        None => ProcessAttribution::Unresolved,
    }
}
