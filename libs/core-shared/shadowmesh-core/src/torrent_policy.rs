//! BitTorrent traffic policy.
//!
//! ## Why block it at all
//!
//! BitTorrent is the single most fingerprintable protocol on the internet.
//! Peers see the exit IP of whoever fetches, trackers log the full
//! swarm membership, and DHT traffic is recognisable by shape alone on any
//! network that cares to look. For a tool whose entire purpose is that an
//! observer *cannot* link a person to their traffic, letting a stray `.torrent`
//! or `magnet:` link route through the tunnel trades that property away
//! silently -- the user never asked for it, and the failure is invisible
//! because the download still works.
//!
//! ## What this is and is not
//!
//! This module is a *policy*: a pure decision function over a URL or URI, with
//! no I/O, so it can be exhaustively unit tested and reused by every layer
//! (Android download interception, the tunnel's own DNS filter, and the
//! diagnostic reporter).
//!
//! It is deliberately **not** a torrent client, nor a protocol filter, and it
//! does not inspect packets. It answers one question: should this request be
//! refused before it is made? Anything that gets past it is not our concern
//! here; a determined user can always run their own client outside the tunnel,
//! which is a freedom we are not trying to take away.
//!
//! The honest limitation, stated up front: matching on extension and URI scheme
//! catches the realistic accidental cases. It cannot catch a user who renames a
//! file or dials an IP directly, and it does not attempt to. A policy that
//! claimed to block all torrent traffic would be lying in the same way the
//! diagnostics panel used to.

/// The verdict for a single request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorrentDecision {
    /// Not torrent-related. Proceed normally.
    Allow,
    /// A `.torrent` file download.
    BlockTorrentFile,
    /// A `magnet:` link, which would launch or instruct a torrent client.
    BlockMagnetLink,
    /// A known BitTorrent tracker, DHT bootstrap node, or torrent CDN.
    BlockTracker,
}

impl TorrentDecision {
    /// Whether the request may proceed.
    pub fn is_allowed(self) -> bool {
        matches!(self, TorrentDecision::Allow)
    }

    /// A short, user-facing reason. Never includes the offending URL.
    pub fn reason(self) -> &'static str {
        match self {
            TorrentDecision::Allow => "",
            TorrentDecision::BlockTorrentFile => {
                "Torrent files are blocked. Downloading them would expose this \
                 connection to tracker logging."
            }
            TorrentDecision::BlockMagnetLink => {
                "Magnet links are blocked. They start peer-to-peer transfers \
                 that identify your exit IP to every peer."
            }
            TorrentDecision::BlockTracker => {
                "Torrent trackers are blocked. Peer-to-peer traffic is highly \
                 fingerprintable and undermines the tunnel."
            }
        }
    }
}

/// Hosts that exist to serve BitTorrent swarms.
///
/// This is intentionally a small, high-confidence list rather than an attempt
/// at completeness. A blocklist of trackers is a losing game: the set changes
/// daily, and a long list is indistinguishable from an arbitrary one. Blocking
/// the handful of infrastructure hosts below, plus the far more reliable
/// scheme and extension checks, catches accidental use without pretending to
/// be exhaustive.
const TRACKER_HOSTS: &[&str] = &[
    "tracker.openbittorrent.com",
    "tracker.opentrackr.org",
    "tracker.torrent.eu.org",
    "tracker.arcomar.fi",
    "tracker.btorrent.xyz",
    "announce trackers",
    "dht.transmissionbt.com",
    "router.bittorrent.com",
    "dht.libtorrent.org",
    "router.utorrent.com",
];

/// Decide whether `uri` may be fetched.
///
/// Accepts a full URL, a bare `magnet:` URI, or a bare hostname. Scheme and
/// host matching is case-insensitive, as both are per RFC 3986.
pub fn evaluate(uri: &str) -> TorrentDecision {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return TorrentDecision::Allow;
    }
    let lower = trimmed.to_ascii_lowercase();

    // 1. magnet: is unambiguous and has no legitimate use in this app.
    if lower.starts_with("magnet:") {
        return TorrentDecision::BlockMagnetLink;
    }

    // 2. A .torrent file, whether referenced by path or query string.
    //    Checked before host matching because a tracker URL can carry one.
    if looks_like_torrent_file(&lower) {
        return TorrentDecision::BlockTorrentFile;
    }

    // 3. Known tracker / DHT infrastructure.
    if let Some(host) = extract_host(&lower) {
        if TRACKER_HOSTS.iter().any(|t| host == *t || host.ends_with(&format!(".{t}"))) {
            return TorrentDecision::BlockTracker;
        }
    }

    TorrentDecision::Allow
}

/// True when the URL names a `.torrent` payload anywhere in it.
///
/// Scans the path *and* the query string. An earlier version truncated at the
/// first `?`, so `https://example.com/get?file=movie.torrent` slipped through;
/// the unit test for exactly that case caught it. Query-borne `.torrent`
/// references are common in download portals, so they have to be covered.
fn looks_like_torrent_file(lower_uri: &str) -> bool {
    // Strip the scheme so a host that merely contains the word is not matched.
    let after_scheme = match lower_uri.find("://") {
        Some(idx) => &lower_uri[idx + 3..],
        None => lower_uri,
    };

    // Treat path separators, query separators and the equals sign as
    // delimiters so `a/b.torrent`, `?f=c.torrent` and `f=c.torrent` all match,
    // while `torrents.html` and `example.com/x` do not.
    after_scheme.split(['/', '\\', '?', '&', '=', '#']).filter(|seg| !seg.is_empty()).any(|seg| {
        let seg = seg.trim_end_matches(['.', ' ']);
        seg.ends_with(".torrent") && seg.len() > ".torrent".len() || seg == ".torrent"
    })
}

/// Extract a lowercased host from a URL or bare hostname.
fn extract_host(lower_uri: &str) -> Option<String> {
    let rest = match lower_uri.find("://") {
        Some(idx) => &lower_uri[idx + 3..],
        None => lower_uri,
    };
    // Credentials in the authority are irrelevant and must not confuse us.
    let rest = rest.rsplit('@').next().unwrap_or(rest);
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..host_end];
    // Strip an explicit port.
    let host = authority.split(':').next().unwrap_or(authority);
    if host.is_empty() {
        None
    } else {
        Some(host.trim_end_matches('.').to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_ordinary_https() {
        assert_eq!(evaluate("https://example.com/page"), TorrentDecision::Allow);
        assert_eq!(evaluate("https://news.ycombinator.com/"), TorrentDecision::Allow);
        assert_eq!(evaluate("example.com"), TorrentDecision::Allow);
        assert!(evaluate("https://example.com").is_allowed());
    }

    #[test]
    fn blocks_magnet_links_regardless_of_case() {
        assert_eq!(
            evaluate("magnet:?xt=urn:btih:0123456789abcdef"),
            TorrentDecision::BlockMagnetLink
        );
        assert_eq!(evaluate("MAGNET:?xt=urn:btih:abc"), TorrentDecision::BlockMagnetLink);
        assert_eq!(evaluate("  magnet:?dn=x  "), TorrentDecision::BlockMagnetLink);
    }

    #[test]
    fn blocks_torrent_files_in_path() {
        assert_eq!(
            evaluate("https://example.com/files/ubuntu.torrent"),
            TorrentDecision::BlockTorrentFile
        );
        assert_eq!(
            evaluate("http://cdn.example.org/a/b/c/debian.torrent"),
            TorrentDecision::BlockTorrentFile
        );
        // Download managers sometimes append a trailing dot or space.
        assert_eq!(evaluate("https://example.com/x.torrent."), TorrentDecision::BlockTorrentFile);
    }

    #[test]
    fn blocks_torrent_files_in_query_string() {
        assert_eq!(
            evaluate("https://example.com/get?file=movie.torrent&x=1"),
            TorrentDecision::BlockTorrentFile
        );
    }

    #[test]
    fn blocks_known_trackers_and_subdomains() {
        assert_eq!(
            evaluate("https://tracker.opentrackr.org:1337/announce"),
            TorrentDecision::BlockTracker
        );
        assert_eq!(
            evaluate("https://dht.transmissionbt.com/announce"),
            TorrentDecision::BlockTracker
        );
    }

    #[test]
    fn does_not_block_hosts_that_merely_look_similar() {
        // Substring matching would produce false positives here, which for a
        // censorship tool means breaking legitimate sites.
        assert_eq!(evaluate("https://notatracker.example.com/x"), TorrentDecision::Allow);
        assert_eq!(evaluate("https://tracker.example.com/announce"), TorrentDecision::Allow);
        assert_eq!(evaluate("https://example.com/torrents.html"), TorrentDecision::Allow);
    }

    #[test]
    fn empty_input_is_allowed() {
        assert_eq!(evaluate(""), TorrentDecision::Allow);
        assert_eq!(evaluate("   "), TorrentDecision::Allow);
    }

    #[test]
    fn every_block_verdict_explains_itself() {
        for d in [
            TorrentDecision::BlockTorrentFile,
            TorrentDecision::BlockMagnetLink,
            TorrentDecision::BlockTracker,
        ] {
            let reason = d.reason();
            assert!(!reason.is_empty(), "a refusal must explain itself");
            assert!(!d.is_allowed());
        }
        assert_eq!(TorrentDecision::Allow.reason(), "");
    }
}
