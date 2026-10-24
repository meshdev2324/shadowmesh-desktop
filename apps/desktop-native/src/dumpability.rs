//! C-2 — the desktop client does not dump.
//!
//! `apps/desktop-native` links the daemon crate and resolves the **same** IPC
//! credential through the same owner (`client.rs:278`, encoded into the frame
//! at `client.rs:291-294`). L10's `dumpability-ruling.md` §3.2: **same
//! posture, same reason** — and §7 **C-2**, owner **L7**, **BLOCKING**.
//!
//! ## The mechanism, and the one fact that decides it
//!
//! The ruling's load-bearing fact (§2.2): on a systemd host the kernel's
//! `core_pattern` is a **pipe**, and a piped handler receives the image
//! **regardless of `RLIMIT_CORE`** — `core(5)` ignores the limit when the
//! pattern is a pipe, which is every systemd host. So the protection is the
//! **attribute**: `prctl(PR_SET_DUMPABLE, 0)`, which strips the process's
//! read/ptrace eligibility and stops the piped dump. The rlimit is set **in
//! addition** — the belt, not the brace; a build that sets only the rlimit is
//! **M-2** by construction.
//!
//! ## Scope — the binary owns the posture, and only there
//!
//! - **In the binary's `main()`**, as its **first** statement, so nothing can
//!   place credential material in a still-dumpable memory image (M-3's
//!   desktop shape; the ordering gate below reads this file and holds it).
//! - **Not at library load, and not in the shipped `.so`** (§3.5): the
//!   `.so` serves the mobile clients, which hold no bearer token (§6.3) and
//!   whose crashes are tombstones/crash-reports, not core dumps (§6.2).
//! - **Not in test binaries** — §3.4: they hold only a fake credential, and
//!   a test that cannot be debugged is a test nobody debugs. This module
//!   never applies its posture to a test process; the gates below measure
//!   the posture in children they control.
//! - **Windows**: a documented no-op — Windows does not write ELF-style
//!   core files; its crash artefacts (WER minidumps) are not `/proc`-gated
//!   and their suppression is a different mechanism out of this ruling's
//!   scope. The cfg arm exists so the tree compiles there **without
//!   pretending coverage**: on Windows, nothing in this module is
//!   protection, and nothing here claims it.
//! - **macOS**: `prctl` does not exist there. `RLIMIT_CORE` **is** honored
//!   by macOS' core-dump path (no piped `core_pattern`), so the rlimit is
//!   real coverage there; the attribute half stays Linux-only and says so.
//!
//! The gates below follow the house convention: each is **able to fail**,
//! and the cross-process one is built alongside its negative control — a
//! gate that has only ever been green is decorative.

/// The whole posture. Idempotent, portable, and honest: it does exactly what
/// its cfg arms say and nothing else.
pub fn apply() {
    // The attribute is the load-bearing half (Linux only; `prctl` is a Linux
    // syscall).
    #[cfg(target_os = "linux")]
    set_not_dumpable();
    // The belt: honored on non-piped hosts (macOS) and correct-but-insufficient
    // on piped ones — where it is NOT the protection (M-2) and must never be
    // described as one.
    #[cfg(unix)]
    set_core_rlimit_zero();
}

/// THE ATTRIBUTE — C-2's act.
///
/// Panics if the kernel refuses: failing to set the posture here means
/// running a credential-holding process with its core image settable — the
/// one outcome this module exists to prevent. Dying loudly at startup is the
/// safe answer, not dying quietly-(and dumpably) later.
#[cfg(target_os = "linux")]
fn set_not_dumpable() {
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
        panic!(
            "prctl(PR_SET_DUMPABLE, 0) failed (rc={rc}) — this client resolves the \
             daemon's IPC credential (client.rs:278), and L10's C-2 forbids running it \
             with a settable core dump. Refusing to continue."
        );
    }
}

/// RLIMIT_CORE = {0, 0}, the belt (§2.2 / M-2: never the sole protection).
#[cfg(unix)]
fn set_core_rlimit_zero() {
    let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // Best-effort by design: the rlimit is NOT the protection, so a failure
    // here must not block the attribute — but it must not hide either:
    // the startup line is the one an operator reads.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc != 0 {
        eprintln!(
            "dumpability: setrlimit(RLIMIT_CORE, 0) failed (rc={rc}) — this is the \
             belt, not the brace (L10's dumpability ruling §2.2); the attribute is \
             what stops a piped core."
        );
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::apply;
    use std::io::BufRead;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    /// The desktop's `main.rs`, as it is written — the source gate must read
    /// the source, not a summary of it.
    const MAIN_RS: &str = include_str!("main.rs");

    /// Strips `//` comments so a gate never fires on its own prose.
    fn strip_comments(src: &str) -> String {
        src.lines()
            .map(|line| line.split("//").next().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    // ------------------------------------------------------------------
    // The child-subject mechanism.
    //
    // R-8's measurement is a *same-uid peer* black-box read of the subject's
    // `/proc/<pid>/{status,environ}` — and self-introspection is ALWAYS
    // allowed (`__ptrace_may_access` early-returns for `same_thread_group`),
    // so an in-process arm cannot prove the posture: reading one's OWN
    // `/proc/self/environ` succeeds even at `PR_SET_DUMPABLE = 0`. The
    // subject is therefore this binary itself, re-executed in a controlled
    // child role (the house pattern the F97 gate established): no shipped
    // code carries a hidden mode, and no shipped binary needs a display to
    // be measured.
    // ------------------------------------------------------------------

    /// Child role: sets the posture, then parks. THE SUBJECT.
    const ROLE_SUBJECT: &str = "SHADOWMESH_DESKTOP_DUMPABLE_CHILD";
    /// Child role: parks *without* the posture. THE NEGATIVE CONTROL — the
    /// proof the detector is not blind.
    const ROLE_CONTROL: &str = "SHADOWMESH_DESKTOP_DUMPABLE_CONTROL_CHILD";

    /// The parked child's lifetime. The parent finishes the measurement in
    /// milliseconds and kills the child right after, but the window must be
    /// generous enough that a slow peer-step cannot outlive it.
    const CHILD_PARK: Duration = Duration::from_secs(10);

    /// Runs a controlled child role in-place: spawns `this test binary`
    /// again, in the requested role, waits for its READY line, and hands the
    /// live `Child` back. The READY line is the only synchronization the
    /// measurement has: a `/proc` read scored against a child that had not
    /// yet applied its posture would be a false green.
    ///
    /// The child runs this same test binary under its **libtest harness**
    /// (that is what a cargo-built test binary *is*; nextest merely drives it
    /// differently), so the invocation uses libtest's own CLI: filters are
    /// **positional substrings** — this test tree has no `--exact` flag —
    /// and `--nocapture` is what lets the role's println reach the pipe.
    /// The banner lines arrive first, so the handshake scans for the READY
    /// line under an explicit deadline: a child that fails to announce is
    /// killed and reported, never waited on forever.
    fn spawn_role(role: &'static str) -> Child {
        let mut child = Command::new(std::env::current_exe().expect("this executable"))
            .arg("--nocapture")
            .arg("--test-threads")
            .arg("1")
            .arg("the_desktop_client_posture_blocks_a_same_uid_peer")
            .env(role, "1")
            .stdout(Stdio::piped())
            .spawn()
            .expect("a controlled child must spawn");
        let stdout = child.stdout.take().expect("the child's stdout is piped");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        // EOF: the child is gone and never announced.
                        let _ = tx.send(None);
                        return;
                    }
                    Ok(_) => {
                        if line.trim() == "READY" {
                            let _ = tx.send(Some(()));
                            return;
                        }
                    }
                    Err(_) => {
                        let _ = tx.send(None);
                        return;
                    }
                }
            }
        });
        let announced = rx.recv_timeout(Duration::from_secs(30)).unwrap_or(None);
        if announced.is_none() {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "the controlled child (role {role}) failed its READY handshake — \
                 it never announced, so any measurement against it would score a \
                 child whose posture state is unknown"
            );
        }
        child
    }

    fn kill(child: Child) {
        let mut child = child;
        let pid = child.id();
        // SIGKILL: the child is a helper, and the parent is not measuring
        // its death — only un-parking it.
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
        let _ = child.wait();
    }

    /// A same-uid peer's read of the subject's CREDENTIAL surfaces,
    /// returned as the kernel answered each.
    ///
    /// ⚠️ **Why `environ`, and not `status`.** The posture (dumpable=0)
    /// flips the whole `/proc/<pid>/` tree to root-*ownership*; what becomes
    /// unreadable to a same-uid, non-capability peer is what the file's own
    /// MODE then refuses. `status` carries no secrets and ships mode `0444`
    /// — world-readable on purpose — so it stays readable even when
    /// root-owned (observed directly on this host's kernel). The
    /// credential-bearing surfaces — `environ` (mode `0400` here), `mem`,
    /// `maps`, `auxv` — are the ones the flip protects. The discriminator
    /// for "the posture stands between the peer and the subject" is
    /// therefore an environ/maps read, never a status read: a gate keyed on
    /// `status` would have red-proven green and green-proven green —
    /// indistinguishable.
    fn peer_read_environ(pid: u32) -> std::io::Result<String> {
        std::fs::read_to_string(format!("/proc/{pid}/environ"))
    }

    fn peer_read_maps(pid: u32) -> std::io::Result<String> {
        std::fs::read_to_string(format!("/proc/{pid}/maps"))
    }

    fn assert_not_running_as_root() {
        let uid = unsafe { libc::getuid() };
        let euid = unsafe { libc::geteuid() };
        assert_ne!(
            uid, 0,
            "the gate is running as root — root bypasses the /proc ownership \
             check and the measurement is vacuous (R-2's root clause)"
        );
        assert_ne!(
            euid, 0,
            "the gate is running setuid-root — the measurement is vacuous for \
             the same reason"
        );
    }

    /// 🔴 **R-8 — the posture measurement, same shape as R-2, both ways.**
    ///
    ///   * THE CONTROL — a child that did NOT set the posture: the peer
    ///     **must** read its `/proc/<pid>/environ` **and** `/maps`. If it
    ///     cannot, the detector is blind — any refusal below would mean
    ///     nothing — and this half failing fails the gate.
    ///   * THE SUBJECT — a child that DID set the posture (`apply()`, the
    ///     exact function `main()` runs): the peer **must** be refused on
    ///     both surfaces, and the kernel's refusal name must be `EACCES`.
    ///
    /// The surfaces are the credential-bearing ones (see
    /// [`peer_read_environ`]'s note): `status` is world-readable on modern
    /// kernels even when the posture took — scoring its refusal would make
    /// this gate red on a CORRECT posture.
    ///
    /// Both children must still be alive at the moment of the read: a
    /// `NotFound` is a DEAD subject, not a protected one, and it is red for
    /// a different reason.
    #[test]
    fn the_desktop_client_posture_blocks_a_same_uid_peer() {
        // The child role, dispatched in-place: a re-executed test binary that
        // sets the posture and parks (THE SUBJECT), or parks without (THE
        // CONTROL). Edition-2024 let-chains: the role must be set (non-empty)
        // for the arm to fire.
        if let Ok(role) = std::env::var(ROLE_CONTROL)
            && !role.is_empty()
        {
            // ⚠️ The harness (even --nocapture) leaves `test <name> ... `
            // open on our stdout; terminate that line BEFORE announcing,
            // or READY arrives as a tail of the status line and the
            // parent's line-scanner never sees a bare one.
            println!("\nREADY");
            std::thread::sleep(CHILD_PARK);
            return;
        }
        if let Ok(role) = std::env::var(ROLE_SUBJECT)
            && !role.is_empty()
        {
            // The posture the shipped main() runs, in the child. The
            // newline first (same reason as the control arm): end the
            // harness's open status line before announcing.
            apply();
            println!("\nREADY");
            std::thread::sleep(CHILD_PARK);
            return;
        }

        assert_not_running_as_root();

        // THE CONTROL — the detector's unblinding: the peer CAN read an
        // unprotected child's credential surfaces.
        let control = spawn_role(ROLE_CONTROL);
        let pid = control.id();
        for (name, read) in [("environ", peer_read_environ(pid)), ("maps", peer_read_maps(pid))] {
            assert!(
                read.is_ok(),
                "the negative control failed: the peer could not read a dumpable \
                 child's /proc/{pid}/{name} ({:?}) — the detector is blind, and \
                 this gate cannot distinguish a suppressed dump from an invisible \
                 one (R-2's control arm)",
                read.err()
            );
        }

        // THE SUBJECT — the posture stands between the peer and the subject:
        // the same peer, the same two reads, now refused — the kernel's own
        // name for it (EACCES), on every surface.
        let subject = spawn_role(ROLE_SUBJECT);
        let pid = subject.id();
        for (name, read) in [("environ", peer_read_environ(pid)), ("maps", peer_read_maps(pid))] {
            match read {
                Err(e) => {
                    assert!(
                        matches!(e.kind(), std::io::ErrorKind::PermissionDenied),
                        "the subject's /proc/{pid}/{name} was refused, but not with \
                         EACCES ({e:?}) — the gate refuses to score an error it \
                         cannot name"
                    );
                }
                Ok(_) => {
                    panic!(
                        "the peer READ the non-dumpable child's /proc/{pid}/{name} — \
                         the posture did not stand between the peer and the subject \
                         (C-2's exact defect, observed)"
                    );
                }
            }
        }

        // Both helpers were ALIVE through the measurement. Un-park them now:
        // a subject that had died early would have failed the arms above
        // with NotFound-style errors — never a green.
        kill(subject);
        kill(control);
    }

    /// The in-process half: the POSTURE IS REAL KERNEL STATE.
    ///
    /// The peer measurement above proves what a non-dumpable process looks
    /// like FROM OUTSIDE. This gate proves that THIS binary's `apply()` —
    /// the function `main()` runs — actually produces that object: the
    /// attribute bit, the rlimit, and the kernel's own view of the limit.
    ///
    /// ⚠️ **Runs through nextest** (one process per test): the "before"
    /// control assumes a fresh process; under plain `cargo test` the two
    /// behavioural gates share one, and run concurrently.
    #[test]
    fn the_posture_is_real_kernel_state() {
        assert_not_running_as_root();

        // BEFORE — the control: a fresh process is dumpable, and its core
        // rlimit is unset. If a host starts non-dumpable, this gate fails:
        // a before-arm that cannot be distinguished from an after-arm
        // proves nothing.
        let before = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(
            before, 1,
            "a fresh process must start dumpable (PR_GET_DUMPABLE=1); the \
             'before' arm of this gate is not measurable on this host"
        );

        // AFTER — the attribute and the rlimit, both read back.
        apply();
        let after = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(
            after, 0,
            "apply() must leave PR_GET_DUMPABLE == 0 — the attribute is the \
             load-bearing half (§2.2), and its absence is M-2's precise defect"
        );
        let mut rl = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rl) };
        assert_eq!(rc, 0, "getrlimit(RLIMIT_CORE) must succeed");
        assert_eq!(
            (rl.rlim_cur, rl.rlim_max),
            (0, 0),
            "apply() must leave RLIMIT_CORE at {{0, 0}} — the belt (M-2 names a \
             build that sets the belt without the brace)"
        );

        // The kernel's own view of the rlimit, cross-checked through
        // /proc/self/limits — the source an operator reads:
        // "Max core file size   0  0  bytes".
        let limits = std::fs::read_to_string("/proc/self/limits")
            .expect("/proc/self/limits must be readable for self");
        let row = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .expect("/proc/self/limits must carry the 'Max core file size' row");
        let tokens: Vec<&str> = row.split_whitespace().collect();
        assert_eq!(tokens.last().copied(), Some("bytes"));
        assert_eq!(
            &tokens[tokens.len() - 3..tokens.len() - 1],
            ["0", "0"],
            "the kernel's own view of RLIMIT_CORE is not {{0, 0}} after apply(): \
             `{row}`"
        );
    }

    /// 🔴 **M-3's desktop shape — the posture precedes the credential.**
    ///
    /// "The credential must never be resident in a dumpable process" (M-3,
    /// desktop variant; R-5's caretaker on the daemon). This is a **source
    /// gate**: it reads `main.rs` as written and asserts that
    /// `dumpability::apply()` is declared, is CALLED, and is called BEFORE
    /// the first `DaemonClient::connect()` — the credential's first
    /// residence on the desktop path.
    #[test]
    fn the_client_sets_its_posture_before_the_credential_is_resident() {
        let code = strip_comments(MAIN_RS);

        assert!(
            code.contains("pub mod dumpability;"),
            "main.rs must declare the posture module — a posture that is not \
             wired is a posture that does not exist (C-2 covers the module, \
             not the file that forgot to call it)"
        );
        assert!(
            code.contains("dumpability::apply()"),
            "main.rs must CALL dumpability::apply() — a module declared but \
             never called ships a credential-holding process with a settable \
             core (L10's M-2 must-not-build list)"
        );

        let posture = code.find("dumpability::apply()").expect("asserted above");
        let first_credential = code
            .split_once("DaemonClient::connect()")
            .map(|(head, _)| head.len())
            .expect("main.rs must reach the daemon, via DaemonClient::connect()");

        assert!(
            posture < first_credential,
            "the posture call and the first credential-resolving call are \
             reversed: the credential would become resident while the process \
             is still dumpable (M-3 — the desktop order matters, and this \
             gate is why)"
        );
    }
}
