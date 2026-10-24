use slint_build::CompilerConfiguration;
use std::fs;
use std::path::{Path, PathBuf};

/// The file the source stamp is written into, inside `OUT_DIR`.
///
/// The artefact-level attribution check (`src/attribution.rs`) reads it to
/// learn the stamp of the sources **as they are now**, and compares it with
/// the stamp it finds inside the binary. The two are produced by the same
/// build, so a difference means the artefact was built from something else.
const STAMP_FILE: &str = "shadowmesh-source-stamp.txt";

/// The file the DIGESTED FILE LIST is written into, inside `OUT_DIR`.
///
/// The list is the digest's own receipt: it says which files went into the
/// stamp, and in the order they went in. `src/attribution.rs` reads it to
/// recompute the digest from the files themselves — which is what proves the
/// stamp describes the tree as it is **now** — and to assert that the set
/// covers every input that determines the artefact.
const SOURCE_FILES_FILE: &str = "shadowmesh-source-files.txt";

/// The prefix every source stamp carries.
///
/// Deliberately distinctive: the stamp has to be findable in a ~490 MB
/// artefact by a byte scan, and it must not be mistakable for anything else
/// that happens to be in the binary.
const STAMP_PREFIX: &str = "smf1:";

/// The number of hex digits in a stamp (a 64-bit FNV-1a digest).
const STAMP_DIGITS: usize = 16;

fn main() {
    // Native-adjacent widget styling per platform (design-system: Google-Grade
    // Adaptivity). The truly-native style requires the GPL/Qt backend, which we
    // deliberately avoid — Cupertino matches the Apple-Grade physics mandate,
    // Fluent matches Windows conventions.
    let style = if cfg!(target_os = "windows") { "fluent" } else { "cupertino" };

    let config = CompilerConfiguration::new().with_style(style.into());
    slint_build::compile_with_config("src/main.slint", config).expect("Slint compilation failed");

    stamp_the_sources();
}

/// Writes the stamp of the current sources, and hands it to the compiler.
///
/// # Why this exists
///
/// The attribution check in `src/attribution.rs` reads the **built binary**,
/// because the licence condition is discharged by what is *in the artefact*,
/// not by what is in the source. But `cargo nextest` builds the test harness
/// and **not** the runnable binary, so the file the check finds in the build
/// directory is whatever was built last — possibly days old, and possibly
/// built from a source that no longer exists.
///
/// A check that measures an artefact it did not build is a check that can
/// pass for reasons that have nothing to do with the code (the "F57" class:
/// a control that measures something other than what it claims to).
///
/// The stamp closes that hole without weakening the check into a source grep:
/// it is a digest over every source file that determines the binary, it is
/// written into the artefact at build time, and the check refuses an artefact
/// that does not carry the **current** digest. The artefact is still the thing
/// being measured; it is now also required to *be* the artefact this source
/// produces.
fn stamp_the_sources() {
    let mut files = source_files();
    files.sort();

    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for path in &files {
        hash = fnv1a(hash, path.to_string_lossy().as_bytes());
        hash = fnv1a(hash, &[0u8]);
        // An unreadable file is hashed as a distinct sentinel rather than as
        // empty content, so "the file vanished" and "the file is empty" do not
        // produce the same digest.
        let content = fs::read(path).unwrap_or_else(|_| b"<unreadable>".to_vec());
        hash = fnv1a(hash, &content);
        hash = fnv1a(hash, &[0u8]);

        // The build script must re-run when any of these change, or the stamp
        // would keep describing a source that no longer exists.
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // `width` is bound as a named argument: a format width cannot be a const
    // path, only a literal or a named binding.
    let stamp = format!("{STAMP_PREFIX}{hash:0width$x}", width = STAMP_DIGITS);
    let out_dir =
        PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR for build scripts"));
    fs::write(out_dir.join(STAMP_FILE), &stamp)
        .expect("the source stamp must be writable into OUT_DIR");

    // The receipt: which files went into the digest, and in the order they
    // went in. The check reads it to recompute the digest from the files
    // themselves and to pin the set — a digest whose receipt is not written
    // down cannot be audited, and an unaudited digest is a claim.
    let mut list = String::new();
    for path in &files {
        list.push_str(&path.to_string_lossy());
        list.push('\n');
    }
    fs::write(out_dir.join(SOURCE_FILES_FILE), &list)
        .expect("the digested file list must be writable into OUT_DIR");

    // The stamp goes into the binary as well, so the check can find it there.
    println!("cargo:rustc-env=SHADOWMESH_DESKTOP_SOURCE_STAMP={stamp}");
}

/// Every file whose content determines the binary.
///
/// The set is deliberately **over-inclusive**: it includes files that only
/// affect the test build (a `#[cfg(test)]` module), and it excludes nothing
/// that does. A stamp that is too strict costs a rebuild; a stamp that is too
/// loose would certify an artefact built from a different source, which is
/// the failure this whole mechanism exists to prevent.
///
/// ⚠️ **"Every file whose content determines the binary" is a claim about the
/// ARTEFACT, not about this crate's directory.** Three classes of input sit
/// outside this crate's own tree and were missing from the first version of
/// this set — so an artefact built before a change in any of them still
/// carried the current digest and the gate could not tell:
///
/// | input | why it determines the artefact |
/// | :--- | :--- |
/// | the workspace `Cargo.toml` | it carries `[profile.release]` — `strip = true`, the very reason the check has to run against a built artefact — and `[workspace.dependencies]`, whose versions every crate inherits |
/// | the workspace `Cargo.lock` | it pins the exact version of every dependency that goes into the binary |
/// | the path dependencies' sources | `shadowmesh-core` and `shadowmesh-daemon` are not libraries this app *calls*, they are **linked into the binary** |
///
/// The path dependencies are read out of the manifest rather than hard-coded,
/// so adding one cannot silently fall outside the digest.
fn source_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect(Path::new("src"), &mut files);
    collect(Path::new("assets"), &mut files);
    files.push(PathBuf::from("Cargo.toml"));
    files.push(PathBuf::from("build.rs"));

    // The WORKSPACE's manifest and lockfile — see the table above.
    files.push(PathBuf::from("../../Cargo.toml"));
    files.push(PathBuf::from("../../Cargo.lock"));

    // The PATH DEPENDENCIES, which are compiled into the artefact.
    for dep in path_dependencies() {
        // The compiled sources.
        collect(&dep.join("src"), &mut files);
        // Its own manifest and build script.
        for extra in ["Cargo.toml", "build.rs", "uniffi.toml"] {
            let path = dep.join(extra);
            if path.is_file() {
                files.push(path);
            }
        }
        // The protobuf sources its build script compiles: the core's
        // `build.rs` runs `tonic_build::compile_protos("proto/shadowmesh.proto")`,
        // so those files are build inputs like any other. (`src/shadowmesh.udl`,
        // which the same build script reads, is already under `src/`.)
        collect(&dep.join("proto"), &mut files);
    }
    files
}

/// Every path dependency this crate declares, read out of its own manifest.
///
/// A path dependency is compiled into the artefact, so its sources determine
/// the binary exactly as much as this crate's own do. They are read from the
/// manifest rather than hard-coded, so a new path dependency cannot be added
/// without being covered.
///
/// A path that does not name a dependency is left out, and the coverage test
/// in `src/attribution.rs` is what catches a dependency that was left out by
/// mistake — it names each one the desktop client links.
fn path_dependencies() -> Vec<PathBuf> {
    let Ok(manifest) = fs::read_to_string("Cargo.toml") else {
        return Vec::new();
    };
    let mut deps = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `path = "…"` — the manifest's way of naming a path dependency.
        let Some((_, after)) = line.split_once("path") else {
            continue;
        };
        let Some(after) = after.trim_start().strip_prefix('=') else {
            continue;
        };
        let Some(after) = after.trim().strip_prefix('"') else {
            continue;
        };
        let Some(end) = after.find('"') else {
            continue;
        };
        let dep = PathBuf::from(&after[..end]);
        // ⚠️ **A path dependency is a DIRECTORY with a manifest in it.** The
        // manifest's `path` key means two different things: in
        // `[dependencies]` it names a path dependency, and in a `[[bin]]`
        // section it names the binary's own source file
        // (`path = "src/main.rs"`). Only the first is a dependency, and the
        // second is already covered by this crate's own `src/` — so the
        // manifest-in-the-directory is what tells them apart.
        if dep.join("Cargo.toml").is_file() {
            deps.push(dep);
        }
    }
    deps
}

/// Collects every file under `dir` (recursively).
fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// FNV-1a, 64-bit.
///
/// Chosen because it is four lines, has no dependency, and is specified
/// exactly — the digest has to be reproducible by the check that reads it,
/// on any toolchain, forever.
fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}
