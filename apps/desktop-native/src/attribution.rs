//! F40 — the Slint §2 attribution condition, and the checks that enforce it.
//!
//! # The licence condition
//!
//! The desktop client declares `license = "LicenseRef-Slint-Royalty-free-2.0"`
//! (`Cargo.toml:11`). The vendored licence text is
//! `LICENSES/LicenseRef-Slint-Royalty-free-2.0.md`, and §2 of it reads:
//!
//! > ## 2. License Conditions - Attribution
//! >
//! > You may distribute the Software as part of an Application, modified or
//! > unmodified, provided that You do either of the following:
//! >
//! > (a) Display the [`AboutSlint`] widget in an "About" screen or dialog that
//! > is accessible from the top level menu of the Application. In the absence
//! > of such a screen or dialog, display the widget in the "Splash Screen" of
//! > the Application.
//! >
//! > (b) Display the [Slint attribution badge] on a public webpage, preferably
//! > where the binaries of your Application can be downloaded from, in such
//! > a way that it can be easily found by any visitor to that page.
//!
//! The condition is disjunctive ("do **either** of the following") and is a
//! proviso on *distribution*. This tree implements **§2(a)**, in its primary
//! form: an About screen (`AboutWindow` in `src/main.slint`) that displays the
//! upstream `AboutSlint` widget and is reachable from the application's top
//! level menu (`MenuBar` > `Help` > `About ShadowMesh`).
//!
//! §2(b) is not implemented and is not relied on: the tree has no public
//! download page to host the badge (binaries ship as GitHub Releases), and
//! §2(b) cannot discharge the condition for a distribution that has no public
//! page at all. §2(a) travels inside the binary, which is why it is the form
//! this tree takes.
//!
//! # R1 — the attribution must be in the LINKED BINARY
//!
//! A source-level grep does **not** discharge the condition. It is satisfied
//! by an import, by a comment, or by a component that is never instantiated,
//! and it does not survive dead-code elimination or `strip = true` (which the
//! workspace release profile sets — `Cargo.toml` `[profile.release]`). The
//! only place the check is meaningful is the artefact that is about to be
//! published, so [`verify_artefact`] reads the built executable.
//!
//! ⚠️ **The checker must not be inside the thing it checks.** The marker
//! strings below are literals; if this module were compiled into the shipped
//! binary, the binary would carry "MadeWithSlint" and "https://slint.dev/"
//! *because the checker is there*, and the R1 assertion would be satisfied by
//! the checker's own constants rather than by the upstream widget — a check
//! that cannot fail. The module is therefore `#[cfg(test)]` (see
//! `src/main.rs`), so the shipped binary contains the markers only if the
//! upstream `AboutSlint` widget really is in it.
//!
//! The marker strings are not guessed. They are read out of the upstream
//! widget source itself — `i-slint-compiler-1.17.1/widgets/common/about-slint.slint`:
//!
//! | line | upstream source | marker it yields |
//! | :--- | :--- | :--- |
//! | `:21` | `accessible-label: "#MadeWithSlint"` | `MadeWithSlint` |
//! | `:25` | `text: "Version 1.17.1\nhttps://slint.dev/"` | `https://slint.dev/` |
//! | `:31` | `Platform.open-url("https://slint.dev")` | `https://slint.dev` |
//!
//! Neither marker is tied to a Slint version number: the version literal at
//! `:25` is baked into the upstream widget at build time and changes on every
//! Slint release, so a version-bearing marker would silently rot.
//!
//! # R2 — the attribution must be reachable
//!
//! Two halves, because they can be proved in two different ways:
//!
//! * **R2-a (runtime).** `AboutWindow` latches a flag from the `AboutSlint`
//!   element's own `init` handler (`src/main.slint`). Instantiating the
//!   component and reading the latch proves the upstream widget was really
//!   *instantiated*, not merely imported. Delete the `AboutSlint` element and
//!   the latch stays false — that is the red-proof.
//! * **R2-b (structural).** Slint 1.17 exposes no public API to enumerate or
//!   programmatically activate the entries of a `MenuBar` — `MenuEntry` is not
//!   part of `slint::`'s public API — so "a top level menu item exists whose
//!   activation opens it" cannot be asserted at runtime. It is asserted here
//!   against the component tree in `src/main.slint` instead.
//!
//! # R3 — the artefact must be the one THIS SOURCE produces
//!
//! R1 says *what* is measured: the linked binary, not the source. R3 says
//! **which** linked binary, and it exists because the first version of this
//! check measured the wrong one.
//!
//! `cargo nextest` builds the **test harness**, not the runnable binary. The
//! binary the check found in the build directory was therefore whatever had
//! been built last — on the run that found the defect, a binary from
//! `2026-10-20 01:31` against a `src/main.slint` edited at `02:23` the next
//! day. The check was asserting on an artefact that had nothing to do with
//! the source it claimed to reflect, and it could pass or fail for reasons
//! that had nothing to do with the code. **A control that measures something
//! other than what it names is a check that cannot fail** — the "F57" class.
//!
//! The fix is a **source stamp**, and it is deliberately not a timestamp:
//!
//! | | |
//! | :--- | :--- |
//! | **what** | `build.rs` digests every source file that determines the binary (all of `src/**`, `assets/**`, `Cargo.toml`, `build.rs`) with FNV-1a |
//! | **where it goes** | into `OUT_DIR/shadowmesh-source-stamp.txt` (read by this check) **and** into the binary itself (found by this check) |
//! | **the gate** | the artefact must carry the stamp of the sources as they are **now**, or the check fails **loudly** and says how to rebuild |
//!
//! Why not compare modification times? A timestamp says "the artefact is older
//! than the sources", which is a *proxy* for the thing that matters, and the
//! proxy leaks in both directions: a rebuild does not always bump an mtime
//! (a restored file, a copied artefact, a checkout of an older branch), and a
//! touched file does not always change the artefact. The stamp is a digest of
//! the **content**: it is right for the reason that matters, and it cannot be
//! satisfied by a binary that happens to be newer.
//!
//! ⚠️ **The stamp gate runs BEFORE the marker assertion, and it is not a
//! skip.** A stale artefact that happens to contain the markers must be
//! REFUSED, not excused — that is the whole point of the gate, and the test
//! `a_stale_artefact_that_carries_the_markers_is_refused` is its red-proof.
//! A check that skips when it cannot measure is a check that passes.
//!
//! ⚠️ **R1 is not weakened by any of this.** The attribution is still
//! measured *in the linked binary*. The stamp does not stand in for the
//! markers; it only establishes that the binary being measured is the binary
//! this source produces.

use std::path::{Path, PathBuf};

/// The marker strings that must be present in the linked binary.
///
/// Read from the upstream `AboutSlint` widget source; see the module docs for
/// the line-by-line citation.
pub const ATTRIBUTION_MARKERS: &[&str] = &["MadeWithSlint", "https://slint.dev/"];

/// The name of the built executable, as declared by `[[bin]]` in `Cargo.toml`.
pub const BINARY_NAME: &str = "shadowmesh-desktop";

/// Environment variable that points the check at a specific artefact.
///
/// The release job sets this to the exact binary it is about to publish, so
/// the check runs against the artefact and not against whatever happens to be
/// in the build directory.
pub const BINARY_ENV_VAR: &str = "SHADOWMESH_DESKTOP_BINARY";

/// The prefix of the source stamp that `build.rs` writes into the binary.
///
/// See the module docs, "R3". The prefix is what the scan looks for; the
/// digest follows it.
pub const STAMP_PREFIX: &str = "smf1:";

/// The file `build.rs` writes the current source's stamp into (`OUT_DIR`).
pub const STAMP_FILE: &str = "shadowmesh-source-stamp.txt";

/// The file `build.rs` writes the DIGESTED FILE LIST into (`OUT_DIR`).
///
/// The list is the digest's receipt: which files went into the stamp, and in
/// the order they went in. It is what lets the check recompute the digest
/// from the files themselves — proving the stamp describes the tree as it is
/// **now** — and what lets the coverage be asserted rather than assumed.
pub const SOURCE_FILES_FILE: &str = "shadowmesh-source-files.txt";

/// The number of hex digits in a stamp (a 64-bit FNV-1a digest).
pub const STAMP_DIGITS: usize = 16;

/// The chunk size of the streaming artefact scan.
///
/// The file is never held in memory in full: this crate's debug artefact is
/// ~490 MB, and a test process that maps that much on a 12 GB box is a risk
/// to every other build on it.
const CHUNK: usize = 1 << 20;

/// Why the attribution could not be verified.
#[derive(Debug)]
pub enum AttributionError {
    /// No binary could be located to check.
    BinaryNotFound(PathBuf),
    /// The binary could not be read.
    Io(std::io::Error),
    /// The build's own stamp file could not be read.
    StampMissing(PathBuf),
}

impl std::fmt::Display for AttributionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinaryNotFound(p) => write!(
                f,
                "no built `{}` binary to verify at {}; build it first, or point {} at it",
                BINARY_NAME,
                p.display(),
                BINARY_ENV_VAR
            ),
            Self::Io(e) => write!(f, "could not read the built binary: {e}"),
            Self::StampMissing(p) => write!(
                f,
                "the build's source stamp ({}) could not be read; the build script did not run, \
                 so there is no way to tell whether the artefact corresponds to the current source",
                p.display()
            ),
        }
    }
}

impl std::error::Error for AttributionError {}

/// Whether an artefact was built from the sources it is being checked against.
#[derive(Debug, PartialEq, Eq)]
pub enum StampVerdict {
    /// The artefact carries exactly the expected stamp.
    Current,
    /// The artefact carries a stamp, but a different one: it was built from
    /// some other source.
    Stale {
        /// The stamp the artefact actually carries.
        found: String,
    },
    /// The artefact carries no stamp at all — it was built by a build script
    /// that did not stamp it.
    Absent,
}

impl std::fmt::Display for StampVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Current => write!(f, "current"),
            Self::Stale { found } => write!(f, "stale (the artefact carries `{found}`)"),
            Self::Absent => write!(f, "absent (the artefact carries no source stamp at all)"),
        }
    }
}

/// What the check found in an artefact.
#[derive(Debug)]
pub struct ArtefactVerdict {
    /// Whether the artefact corresponds to the current sources.
    pub stamp: StampVerdict,
    /// The attribution markers the artefact does **not** carry.
    pub missing_markers: Vec<&'static str>,
}

/// Byte-search for `needle` in `haystack`.
///
/// `memchr`-free on purpose: the crate is not worth a dependency for a
/// search this simple. The scan is Boyer–Moore–Horspool rather than
/// `windows().any()` — the naive form cost **70 seconds** on this crate's
/// 490 MB debug artefact, because it compares the needle at every one of
/// half a billion offsets.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    bmh_find(haystack, needle).is_some()
}

/// Boyer–Moore–Horspool substring search.
///
/// Returns the offset of the first occurrence of `needle` in `haystack`.
fn bmh_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    let m = needle.len();
    // The skip table: for every byte that occurs in the needle before its
    // last position, the distance from that occurrence to the end of the
    // needle. A byte that does not occur shifts the window by its whole
    // length. Every entry is therefore >= 1, so the window always advances.
    let mut skip = [m; 256];
    for (i, &byte) in needle[..m - 1].iter().enumerate() {
        skip[byte as usize] = m - 1 - i;
    }
    let limit = haystack.len() - m;
    let mut i = 0usize;
    while i <= limit {
        let mut j = m - 1;
        while j > 0 && haystack[i + j] == needle[j] {
            j -= 1;
        }
        if haystack[i + j] == needle[j] {
            return Some(i);
        }
        i += skip[haystack[i + m - 1] as usize];
    }
    None
}

/// The markers from [`ATTRIBUTION_MARKERS`] that are **absent** from `bytes`.
///
/// Empty result means the attribution is present.
pub fn missing_markers(bytes: &[u8]) -> Vec<&'static str> {
    ATTRIBUTION_MARKERS
        .iter()
        .copied()
        .filter(|marker| !contains_bytes(bytes, marker.as_bytes()))
        .collect()
}

/// The stamp of the sources as they are **now**.
///
/// It is read from the file `build.rs` wrote into `OUT_DIR` — the build that
/// compiled this very test. Comparing it with the stamp found inside the
/// artefact is what turns "the artefact has the markers" into "**the
/// artefact this source produces** has the markers".
pub fn current_source_stamp() -> Result<String, AttributionError> {
    let path = Path::new(env!("OUT_DIR")).join(STAMP_FILE);
    let text = std::fs::read_to_string(&path).map_err(AttributionError::Io)?;
    let stamp = text.trim().to_string();
    if !stamp.starts_with(STAMP_PREFIX) || stamp.len() != STAMP_PREFIX.len() + STAMP_DIGITS {
        return Err(AttributionError::StampMissing(path));
    }
    Ok(stamp)
}

/// Scan `path` for each needle, in ONE streaming pass.
///
/// Returns, for each needle, the offset of its first occurrence, or `None`.
///
/// ⚠️ **Each byte of the file is scanned ONCE.** This function used to scan
/// the **whole buffer** on every iteration while reading only `overlap` new
/// bytes per iteration — so the 1 MiB window was re-scanned roughly 256
/// times over, and a 117 MB artefact took **86 minutes** instead of
/// seconds. Two tests (`linked_binary_contains_the_slint_attribution_markers`
/// and `the_linked_binary_corresponds_to_the_current_sources`) spun on it
/// for over an hour each, and the run had to be killed: **9 of 59 tests ran
/// in 86 minutes and 50 never ran at all.**
///
/// ⇒ The scan region is now the **newly read** bytes only — `buf[scanned..valid]`
/// — and `scanned` tracks how much of the buffer has already been searched.
/// The carry-over of `overlap` bytes still covers a needle that straddles a
/// chunk boundary, because the straddling bytes are exactly the ones the
/// carry keeps.
fn scan_file(path: &Path, needles: &[&[u8]]) -> Result<Vec<Option<u64>>, AttributionError> {
    use std::io::Read;

    let longest = needles.iter().map(|n| n.len()).max().unwrap_or(1).max(1);
    // A needle can straddle a chunk boundary, so the tail of the previous
    // chunk is carried into the next one.
    let overlap = longest - 1;

    let mut found: Vec<Option<u64>> = vec![None; needles.len()];
    let mut file = std::fs::File::open(path).map_err(AttributionError::Io)?;
    let mut buf = vec![0u8; CHUNK + overlap];
    // The file offset of `buf[0]`.
    let mut base: u64 = 0;
    // The number of bytes held in `buf[0..valid]`.
    let mut valid: usize = 0;
    // The number of bytes at the front of the buffer that have been searched.
    let mut scanned: usize = 0;

    loop {
        // Refill. A short read means the end of the file.
        while valid < buf.len() {
            let n = file.read(&mut buf[valid..]).map_err(AttributionError::Io)?;
            if n == 0 {
                break;
            }
            valid += n;
        }

        // ⚠️ **Search only what has not been searched.** The old code
        // searched the whole buffer here, which is what made the scan
        // quadratic in the artefact's size.
        if valid > scanned {
            let window = &buf[scanned..valid];
            for (i, needle) in needles.iter().enumerate() {
                if found[i].is_some() {
                    continue;
                }
                if let Some(pos) = bmh_find(window, needle) {
                    found[i] = Some(base + scanned as u64 + pos as u64);
                }
            }
        }

        // A short read means the end of the file.
        if valid < buf.len() {
            break;
        }

        // ⚠️ **Carry the tail and refill the REST.** The window advances by
        // a whole chunk per iteration; the carry is only the `overlap`
        // bytes a needle could straddle on.
        //
        // ⇒ The previous shape shifted the buffer down by `overlap` and kept
        // `valid - overlap` bytes in it, so the next read filled a
        // **21-byte** gap and the file was searched ~256 times over.
        let carry = overlap.min(valid);
        buf.copy_within(valid - carry..valid, 0);
        base += (valid - carry) as u64;
        valid = carry;
        // The carry is searched again with the next window: a needle may
        // start in the carry and end in the new bytes.
        scanned = 0;
    }
    Ok(found)
}

/// Read the stamp text that starts at `offset` in `path`.
fn read_stamp_at(path: &Path, offset: u64) -> Result<String, AttributionError> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path).map_err(AttributionError::Io)?;
    file.seek(SeekFrom::Start(offset)).map_err(AttributionError::Io)?;
    let want = STAMP_PREFIX.len() + STAMP_DIGITS;
    let mut buf = vec![0u8; want];
    let mut read = 0usize;
    while read < want {
        let n = file.read(&mut buf[read..]).map_err(AttributionError::Io)?;
        if n == 0 {
            break;
        }
        read += n;
    }
    buf.truncate(read);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Verify an artefact: does it correspond to the current sources, and does it
/// carry the attribution?
///
/// Both halves are computed in ONE streaming pass over the file.
pub fn verify_artefact(
    path: &Path,
    expected_stamp: &str,
) -> Result<ArtefactVerdict, AttributionError> {
    let expected_token = expected_stamp.as_bytes();
    let prefix = STAMP_PREFIX.as_bytes();
    let mut needles: Vec<&[u8]> = Vec::with_capacity(ATTRIBUTION_MARKERS.len() + 2);
    // The EXACT token first: the verdict "current" must depend on finding the
    // current digest and nothing else, so that a stray "smf1:" elsewhere in
    // the artefact cannot manufacture a stale verdict.
    needles.push(expected_token);
    needles.push(prefix);
    for marker in ATTRIBUTION_MARKERS {
        needles.push(marker.as_bytes());
    }

    let hits = scan_file(path, &needles)?;

    let stamp = if hits[0].is_some() {
        StampVerdict::Current
    } else if let Some(offset) = hits[1] {
        StampVerdict::Stale { found: read_stamp_at(path, offset)? }
    } else {
        StampVerdict::Absent
    };

    let missing = ATTRIBUTION_MARKERS
        .iter()
        .zip(hits[2..].iter())
        .filter(|(_, hit)| hit.is_none())
        .map(|(marker, _)| *marker)
        .collect();

    Ok(ArtefactVerdict { stamp, missing_markers: missing })
}

/// Locate the built desktop binary.
///
/// Resolution order:
/// 1. [`BINARY_ENV_VAR`], if set — used by the release job to point at the
///    exact artefact that is about to be published.
/// 2. The executable next to the running test binary, which is where cargo
///    puts the `[[bin]]` target it builds for this test run.
///
/// Returns an error rather than `None`: a check that cannot find its subject
/// must fail, not quietly pass.
pub fn locate_built_binary() -> Result<PathBuf, AttributionError> {
    if let Ok(explicit) = std::env::var(BINARY_ENV_VAR) {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Ok(path);
        }
        return Err(AttributionError::BinaryNotFound(path));
    }

    // `<target>/<profile>/deps/<test-binary>-<hash>` -> `<target>/<profile>/<bin>`
    let exe = std::env::current_exe().map_err(AttributionError::Io)?;
    let candidate = exe
        .parent()
        .and_then(|deps| deps.parent())
        .map(|profile_dir| profile_dir.join(BINARY_NAME));

    // ⚠️ The `Option` is read by REFERENCE here, not by value. Binding
    // `Some(candidate)` by value in the `if let` MOVES the `PathBuf` out of
    // the `Option`, and the `Err` arm below then uses the partially-moved
    // value — E0382, "use of partially moved value: `candidate`".
    //
    // That is not a style preference: E0382 is a HARD COMPILE ERROR, so this
    // function does not compile at all in its current form and the whole R1
    // check — the authoritative artefact-level assertion — is dead code that
    // cannot run. It was found by reading the committed source, not by a
    // build (the crate has never been rebuilt since the attribution surface
    // landed).
    if let Some(candidate) = candidate.as_ref()
        && candidate.is_file()
    {
        return Ok(candidate.clone());
    }

    Err(AttributionError::BinaryNotFound(candidate.unwrap_or_else(|| PathBuf::from(BINARY_NAME))))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The build the artefact must correspond to, and the artefact itself.
    fn subject() -> (PathBuf, String) {
        let binary = locate_built_binary().unwrap_or_else(|e| {
            panic!(
                "cannot verify the Slint attribution: {e}. Build the desktop client \
                 (cargo build -p shadowmesh-desktop-native) before running this test."
            )
        });
        let stamp = current_source_stamp().unwrap_or_else(|e| {
            panic!("cannot verify the Slint attribution: {e}. The build script must have run.")
        });
        (binary, stamp)
    }

    /// R1 — the load-bearing check: the attribution must be present in the
    /// LINKED BINARY, not merely in the source.
    ///
    /// This reads the executable cargo built for this test run. It is not a
    /// source grep and it cannot be satisfied by an import or a comment: the
    /// marker has to survive compilation, dead-code elimination and the
    /// release profile's `strip = true`.
    ///
    /// ⚠️ The **staleness gate comes first** (R3). If the artefact in the
    /// build directory was built from an older source, the marker assertion
    /// below would be measuring the wrong binary — and could pass for reasons
    /// that have nothing to do with the code. The gate turns that into a
    /// loud failure with the rebuild command in the message.
    #[test]
    fn linked_binary_contains_the_slint_attribution_markers() {
        let (binary, expected) = subject();
        let verdict = verify_artefact(&binary, &expected)
            .unwrap_or_else(|e| panic!("cannot read the built binary {}: {e}", binary.display()));

        assert!(
            matches!(&verdict.stamp, StampVerdict::Current),
            "the linked binary {} does not correspond to the current source.\n\
             The artefact: {}\n\
             The current sources stamp as: {expected}\n\
             A check that measured this artefact would be measuring a build of something \
             else. Rebuild it before running this test:\n    \
             cargo build -p shadowmesh-desktop-native --bin shadowmesh-desktop",
            binary.display(),
            verdict.stamp,
        );

        assert!(
            verdict.missing_markers.is_empty(),
            "the Slint §2 attribution is NOT present in the linked binary {}.\n\
             Missing marker(s): {:?}\n\
             §2(a) of the Slint Royalty-free licence requires the upstream \
             `AboutSlint` widget to be displayed in an About screen reachable \
             from the top level menu; the widget must be in the artefact, not \
             only in the source. Check that `AboutSlint` is still instantiated \
             in src/main.slint.",
            binary.display(),
            verdict.missing_markers
        );
    }

    /// R3 — the staleness gate on its own.
    ///
    /// The artefact-level check is only meaningful if the artefact is the one
    /// this source produces. `cargo nextest` builds the test harness and not
    /// the runnable binary, so the binary in the build directory is whatever
    /// was built last — which, on the run that found this defect, was a day
    /// older than the source it was being used to check.
    #[test]
    fn the_linked_binary_corresponds_to_the_current_sources() {
        let (binary, expected) = subject();
        let verdict = verify_artefact(&binary, &expected)
            .unwrap_or_else(|e| panic!("cannot read the built binary {}: {e}", binary.display()));

        assert!(
            matches!(&verdict.stamp, StampVerdict::Current),
            "the linked binary {} does not correspond to the current source.\n\
             The artefact: {}\n\
             The current sources stamp as: {expected}\n\
             Rebuild it before running this test:\n    \
             cargo build -p shadowmesh-desktop-native --bin shadowmesh-desktop",
            binary.display(),
            verdict.stamp,
        );
    }

    /// R3 — the negative control for the staleness gate: an artefact that
    /// carries **both** attribution markers but was built from a *different*
    /// source must be REFUSED.
    ///
    /// This is the red-proof of the whole gate. Without it, a stale binary
    /// that happens to contain the markers would satisfy the attribution
    /// assertion — which is exactly the failure the gate exists to prevent.
    #[test]
    fn a_stale_artefact_that_carries_the_markers_is_refused() {
        let dir = std::env::temp_dir().join(format!("sm-attribution-stale-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("stale-binary");

        let mut bytes = b"an artefact from some other build".to_vec();
        bytes.extend_from_slice(b"smf1:0000000000000000");
        bytes.extend_from_slice(b"MadeWithSlint");
        bytes.extend_from_slice(b"https://slint.dev/");
        std::fs::write(&path, &bytes).expect("the fixture must be writable");

        let expected = current_source_stamp().expect("the build's stamp must be readable");
        let verdict = verify_artefact(&path, &expected).expect("the fixture must be readable");

        assert!(
            verdict.missing_markers.is_empty(),
            "the fixture must carry BOTH attribution markers, or this test proves nothing: {:?}",
            verdict.missing_markers
        );
        assert!(
            matches!(&verdict.stamp, StampVerdict::Stale { .. }),
            "a stale artefact that happens to carry the markers was accepted: {}",
            verdict.stamp,
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R3 — and the other half: an artefact that carries the **current**
    /// stamp must be accepted.
    ///
    /// A gate that refuses everything is not a gate either. This is the
    /// positive control, and it is the pair of the negative control above.
    #[test]
    fn an_artefact_carrying_the_current_stamp_is_accepted() {
        let dir = std::env::temp_dir().join(format!("sm-attribution-fresh-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("fresh-binary");

        let expected = current_source_stamp().expect("the build's stamp must be readable");
        let mut bytes = b"an artefact built from this source".to_vec();
        bytes.extend_from_slice(expected.as_bytes());
        bytes.extend_from_slice(b"MadeWithSlint");
        bytes.extend_from_slice(b"https://slint.dev/");
        std::fs::write(&path, &bytes).expect("the fixture must be writable");

        let verdict = verify_artefact(&path, &expected).expect("the fixture must be readable");

        assert_eq!(verdict.stamp, StampVerdict::Current);
        assert!(
            verdict.missing_markers.is_empty(),
            "the fixture must carry BOTH attribution markers: {:?}",
            verdict.missing_markers
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R1 — the matcher must actually bite.
    ///
    /// A check that cannot fail is not a check. This is the negative control
    /// for the test above: bytes that carry no attribution must be reported
    /// as missing every marker.
    #[test]
    fn a_binary_without_the_attribution_is_rejected() {
        let missing = missing_markers(b"this is not the slint runtime");
        assert_eq!(
            missing,
            ATTRIBUTION_MARKERS.to_vec(),
            "every marker must be reported missing for a binary that carries none of them"
        );
    }

    /// R1 — a binary that carries the attribution must be accepted, and the
    /// marker set must not be satisfied by an unrelated string.
    #[test]
    fn a_binary_with_the_attribution_is_accepted() {
        let mut bytes = b"unrelated content".to_vec();
        bytes.extend_from_slice(b"#MadeWithSlint");
        bytes.extend_from_slice(b"https://slint.dev/");
        assert!(missing_markers(&bytes).is_empty());
    }

    /// 🔴 **The scanner must read every byte ONCE.**
    ///
    /// This is the regression gate for the defect that made the desktop's
    /// test suite **unrunnable**: `scan_file` re-scanned the whole 1 MiB
    /// window on every iteration while reading only `overlap` new bytes per
    /// iteration, so the file was searched ~256 times over. Two tests spun on
    /// it for **86 minutes each**, the run had to be killed, and **50 of the
    /// suite's 59 tests never ran**.
    ///
    /// ⇒ The scan window is the **newly read** bytes — `&buf[scanned..valid]`
    /// — and never the whole buffer.
    ///
    /// ⚠️ **The check is structural**, because the defect's symptom is a
    /// **hang**, and a behavioural assertion about a hang is a timeout rather
    /// than a verdict. ⇒ The gate reads its own source and asserts the window
    /// it searches. (The behavioural half is the test below: a needle past the
    /// first chunk is found, at the right offset.)
    ///
    /// **Negative control:** change the window to `&buf[..valid]` ⇒ red.
    #[test]
    fn the_scanner_searches_only_the_newly_read_bytes() {
        let source = include_str!("attribution.rs");

        assert!(
            source.contains("&buf[scanned..valid]"),
            "the scanner must search only the newly read bytes (`&buf[scanned..valid]`); \
             searching the whole buffer on every iteration makes the scan quadratic in the \
             artefact's size — the defect that made this suite unrunnable.",
        );
        // The banned form is ASSEMBLED here, deliberately not written as one
        // contiguous literal. This gate scans its own file through
        // `include_str!`, and its needle's own text is part of that file: a
        // literal needle that names itself is never passable, because the gate
        // would always find its own prose and stay red forever. Assembled at
        // runtime, the banned form exists in the source only where the code
        // actually writes it.
        let banned = ["let window = &buf[..", "valid];"].concat();
        assert!(
            !source.contains(&banned),
            "the scanner must not search the whole buffer on every iteration — that is the \
             quadratic scan, and it is what made this suite unrunnable (86 minutes per test, \
             50 of 59 tests never run).",
        );
    }

    /// The scanner's own correctness across a chunk boundary.
    ///
    /// A needle **past** the first chunk, and one that **straddles** the
    /// boundary, must both be found — and at the right offset. The carry-over
    /// of `overlap` bytes is what makes the straddling one findable, and a
    /// scanner that dropped it would miss it silently.
    #[test]
    fn the_scanner_finds_needles_past_and_across_the_chunk_boundary() {
        let dir = std::env::temp_dir().join(format!("sm-attribution-scan-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("scanned");

        // A file larger than one chunk, so the scan really does iterate.
        let mut bytes = vec![b'.'; CHUNK + 4096];
        let far = "smf1:0123456789abcdef";
        let far_at = bytes.len() - far.len() - 16;
        bytes[far_at..far_at + far.len()].copy_from_slice(far.as_bytes());

        // A needle that straddles the first chunk's boundary.
        let across = "MadeWithSlint";
        let across_at = CHUNK - across.len() / 2;
        bytes[across_at..across_at + across.len()].copy_from_slice(across.as_bytes());

        std::fs::write(&path, &bytes).expect("the fixture must be writable");

        let hits = scan_file(&path, &[far.as_bytes(), across.as_bytes()])
            .expect("the fixture must be readable");

        assert_eq!(
            hits[0],
            Some(far_at as u64),
            "the far needle was not found, or was found at the wrong offset"
        );
        assert_eq!(
            hits[1],
            Some(across_at as u64),
            "the straddling needle was not found, or was found at the wrong offset"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R2-a — the About surface must really instantiate the upstream widget.
    ///
    /// The About window latches `about-slint-instantiated` from the
    /// `AboutSlint` element's own `init` handler, so this proves
    /// instantiation rather than mere import. Deleting the `AboutSlint`
    /// element from `src/main.slint` turns this test red — that is the
    /// red-proof.
    ///
    /// Note the shape: Slint 1.17 generates Rust code only for exported
    /// components that inherit `Window`, so the About surface is ONE exported
    /// `Window` (the panel is inlined into it) and there is no separate
    /// `AboutPanel` type to instantiate.
    #[test]
    fn about_window_instantiates_the_upstream_about_slint_widget() {
        crate::testing::init_headless();

        let window = crate::AboutWindow::new()
            .expect("the About window must be instantiable without a display");

        assert!(
            window.get_about_slint_instantiated(),
            "the upstream `AboutSlint` widget was NOT instantiated by the About window. \
             §2(a) of the Slint Royalty-free licence requires that widget to be \
             displayed in the About screen; if it is only imported and never \
             instantiated, nothing is displayed and nothing is linked into the binary."
        );
    }

    /// R2-b — the About surface must be reachable from a top level menu entry.
    ///
    /// Slint 1.17 has no public API to enumerate or activate `MenuBar`
    /// entries, so the wiring is asserted against the component tree.
    #[test]
    fn about_surface_is_reachable_from_a_top_level_menu_entry() {
        let source =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.slint"))
                .expect("src/main.slint must be readable");

        let app_window = block_after(&source, "export component AppWindow")
            .expect("AppWindow must exist in src/main.slint");

        // 1. The top level menu exists, and it is a menu bar (Slint's builtin
        //    element) rather than a hand-rolled row of links.
        let menu_bar = block_after(&app_window, "MenuBar {")
            .expect("AppWindow must declare a top level MenuBar");
        assert!(
            block_after(&menu_bar, "Menu {").is_some(),
            "the top level MenuBar must contain a Menu"
        );

        // 2. The menu carries an About entry.
        let menu = block_after(&menu_bar, "Menu {").expect("the MenuBar must contain a Menu");
        let menu_item =
            block_after(&menu, "MenuItem {").expect("the top level menu must contain a MenuItem");
        assert!(
            menu_item.contains("About ShadowMesh"),
            "the top level menu must carry an \"About ShadowMesh\" entry; found: {menu_item}"
        );

        // 3. Activating that entry opens the About surface. The activation
        //    handler raises `request_show_about`, which the Rust side turns
        //    into the About window being shown.
        assert!(
            menu_item.contains("request_show_about"),
            "the \"About ShadowMesh\" menu entry must raise `request_show_about`; found: {menu_item}"
        );
        assert!(
            app_window.contains("callback request_show_about()"),
            "AppWindow must declare the `request_show_about` callback"
        );

        // 4. The About screen really contains the upstream widget.
        let about_window = block_after(&source, "export component AboutWindow")
            .expect("AboutWindow must exist in src/main.slint");
        assert!(
            block_after(&about_window, "AboutSlint {").is_some(),
            "the About screen must instantiate the upstream `AboutSlint` widget"
        );
    }

    /// Extract the `{ ... }` block that `anchor` opens, brace-balanced.
    ///
    /// The anchor may or may not itself end with the opening brace, and the
    /// two cases must be handled DIFFERENTLY:
    ///
    /// * `"export component AppWindow"` — the anchor is a name. The block it
    ///   opens is the first `{` that follows it (`... inherits Window {`).
    /// * `"MenuBar {"` — the anchor already carries the opening brace. The
    ///   block it opens is THAT brace's block.
    ///
    /// ⚠️ Treating both the same — always searching for the first `{` AFTER
    /// the anchor — silently skips one nesting level for the second form:
    /// `block_after(app, "MenuBar {")` returned the `Menu`'s body rather than
    /// the `MenuBar`'s, and the assertion that follows
    /// (`block_after(&menu_bar, "Menu {").is_some()`) then found no `Menu {`
    /// at all inside it and the test failed against a tree that is correct.
    /// A structural test that fails for a reason other than the defect it
    /// names is a test nobody can act on.
    ///
    /// The Slint sources in this crate do not put braces inside string
    /// literals in the blocks this test reads (verified: 0 string literals in
    /// `src/main.slint` contain a brace), so a plain brace counter is
    /// sufficient and keeps the test free of a Slint parser dependency.
    fn block_after(source: &str, anchor: &str) -> Option<String> {
        let start = source.find(anchor)?;
        let after = start + anchor.len();
        // The opening brace of the block this anchor names.
        let open = if anchor.ends_with('{') {
            // The anchor's own trailing brace opens the block.
            after - 1
        } else {
            // The first brace that follows the anchor opens it.
            source[after..].find('{')? + after
        };
        let bytes = source.as_bytes();
        let mut depth = 0usize;
        for (offset, byte) in bytes[open..].iter().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(source[open + 1..open + offset].to_string());
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// The helper must be able to FAIL.
    ///
    /// `block_after` returning `Some` for every input would make every
    /// structural assertion above vacuous. This is the negative control: an
    /// anchor that is not in the source yields `None`.
    #[test]
    fn the_block_helper_reports_a_missing_anchor() {
        let source = "export component Present { body }";
        assert!(
            block_after(source, "export component Absent").is_none(),
            "an anchor that is not in the source must yield None, or every structural \
             assertion built on this helper is vacuous"
        );
        assert!(
            block_after(source, "export component Present {").is_some(),
            "an anchor that carries its own opening brace must still resolve"
        );
    }

    // -----------------------------------------------------------------------
    // R3 — the stamp is CURRENT, and it COVERS what it claims to cover.
    //
    // The gate is a chain of two links, and each link can only be trusted if
    // it is itself checked:
    //
    //   1. the build script's digest == the sources as they are NOW
    //      (`the_source_stamp_describes_the_sources_as_they_are_now`), and
    //   2. the sources as they are NOW == the stamp inside the artefact
    //      (`the_linked_binary_corresponds_to_the_current_sources`).
    //
    // Without link 1 the chain is a loop: a stale `OUT_DIR` stamp compares
    // equal to a stale artefact, and the gate passes on a binary built from a
    // source that no longer exists.
    // -----------------------------------------------------------------------

    /// The digested file list `build.rs` wrote, one path per line.
    fn digested_files() -> Vec<String> {
        let path = Path::new(env!("OUT_DIR")).join(SOURCE_FILES_FILE);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("the digested file list must be readable at {}: {e}", path.display())
        });
        text.lines().map(|line| line.trim().to_string()).filter(|line| !line.is_empty()).collect()
    }

    /// FNV-1a, 64-bit — the same function `build.rs` uses.
    ///
    /// This is a SECOND implementation on purpose: the test's claim is that
    /// the two agree, and a copy of the function under test would make that
    /// claim vacuous. The scheme is written down in `build.rs`:
    /// for each file, in the digested order, hash the path, a zero byte, the
    /// content, and a zero byte.
    fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(PRIME);
        }
        hash
    }

    /// R3 — the stamp must describe the sources AS THEY ARE NOW.
    ///
    /// `build.rs` digested a set of files and wrote the stamp into `OUT_DIR`.
    /// This recomputes that digest from the files themselves and compares it
    /// with the stamp the build wrote.
    ///
    /// ⚠️ **This is the check that makes the stamp "current".** The build
    /// script only re-runs when cargo notices a change, and cargo notices by
    /// **modification time**. A file whose content changed without its mtime
    /// moving would leave the `OUT_DIR` stamp describing a tree that no longer
    /// exists — and the artefact gate would then compare a stale binary
    /// against a stale stamp and call it current. Recomputing the digest from
    /// the files' CURRENT content cannot be fooled that way.
    #[test]
    fn the_source_stamp_describes_the_sources_as_they_are_now() {
        let out_dir = Path::new(env!("OUT_DIR"));
        let stamp_path = out_dir.join(STAMP_FILE);
        let stamp = std::fs::read_to_string(&stamp_path).unwrap_or_else(|e| {
            panic!("the source stamp must be readable at {}: {e}", stamp_path.display())
        });
        let stamp = stamp.trim().to_string();

        let files = digested_files();
        assert!(
            !files.is_empty(),
            "the digested file list must not be empty: a digest over nothing covers nothing"
        );

        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for rel in &files {
            // An unreadable file is hashed as a distinct sentinel rather than
            // as empty content, so "the file vanished" and "the file is empty"
            // do not produce the same digest. This is `build.rs`'s rule, and
            // it has to be the same rule here.
            let content =
                std::fs::read(root.join(rel)).unwrap_or_else(|_| b"<unreadable>".to_vec());
            hash = fnv1a(hash, rel.as_bytes());
            hash = fnv1a(hash, &[0u8]);
            hash = fnv1a(hash, &content);
            hash = fnv1a(hash, &[0u8]);
        }

        let computed = format!("{STAMP_PREFIX}{hash:0width$x}", width = STAMP_DIGITS);
        assert_eq!(
            computed, stamp,
            "the source stamp describes a tree that no longer exists.\n\
             The digested files have changed since the build script ran, so the stamp in \
             OUT_DIR is stale and the artefact gate would be comparing a stale binary \
             against a stale digest.\n\
             Rebuild the crate so the build script re-runs:\n    \
             cargo build -p shadowmesh-desktop-native --bin shadowmesh-desktop"
        );
    }

    /// R3 — the digest must cover every input that determines the artefact.
    ///
    /// The digest is the gate's whole authority. If an input that changes the
    /// binary is missing from it, an artefact built *before* that change still
    /// carries the current stamp, and the gate cannot tell — which is exactly
    /// the failure the stamp exists to prevent.
    ///
    /// The set is pinned in three classes:
    ///
    /// * this crate's own tree — its sources (including `src/main.slint`, the
    ///   file the Slint compiler reads), its assets (which are `include_bytes!`
    ///   -ed into the binary), its manifest and its build script;
    /// * the workspace's manifest and lockfile — the release profile and the
    ///   dependency versions;
    /// * the path dependencies that are **linked into** the binary.
    #[test]
    fn the_source_stamp_covers_every_input_that_determines_the_artefact() {
        let files = digested_files();

        // This crate's own tree.
        for required in [
            "src/main.rs",
            "src/main.slint",
            "src/attribution.rs",
            "assets/icon.png",
            "assets/decoy.png",
            "Cargo.toml",
            "build.rs",
        ] {
            assert!(
                files.iter().any(|file| file == required),
                "the digest must cover {required}; it covers {} file(s)",
                files.len()
            );
        }

        // The inputs that are NOT this crate's own files, and without which a
        // stale artefact could still pass.
        //
        // ⚠️ **The daemon's spelling is the manifestation's own.** The list
        // records each path dependency in the spelling its `path =` line
        // uses — the desktop manifest declares the daemon as
        // `path = "../daemon"`, so that (and only that) is the form its
        // entries arrive in. Requiring any *other* route to the same
        // directory would make this assertion unpassable by construction,
        // while the coverage itself — the daemon's `lib.rs` is hashed, in the
        // manifest's own spelling — is what the gate is about.
        for required in [
            "../../Cargo.toml",
            "../../Cargo.lock",
            "../../libs/core-shared/shadowmesh-core/src/lib.rs",
            "../daemon/src/lib.rs",
        ] {
            assert!(
                files.iter().any(|file| file == required),
                "the digest must cover {required}; it covers {} file(s)",
                files.len()
            );
        }
    }
}
