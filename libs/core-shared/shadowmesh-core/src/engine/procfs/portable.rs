//! Portable `/proc` process attribution — the fallback and the reference.
//!
//! This is the implementation that shipped before io_uring was introduced,
//! moved here unchanged in behaviour. It is what runs:
//!
//!   * on every non-Linux target (macOS has no io_uring and no equivalent),
//!   * on Linux when the io_uring worker cannot be created (a seccomp profile
//!     that blocks `io_uring_setup`, a kernel without it, RLIMIT_NPROC),
//!   * in the unit tests, as the oracle the io_uring backend is checked against.
//!
//! Because it is the oracle, the parsing lives in [`parse_inode_table`] and is
//! shared verbatim with the io_uring backend: there is exactly one parser, so
//! "the uring path found something different" can only mean different *bytes*,
//! never different *rules*.

use super::ProcessInfo;
use std::fs;

/// Locate the process that owns `local_port`, using plain `std::fs` syscalls.
pub(crate) fn find_process_info(local_port: u16) -> Option<ProcessInfo> {
    let inode = find_inode(local_port)?;
    find_pid_by_inode(inode)
}

/// Map a local TCP/UDP port to the socket inode the kernel recorded for it.
///
/// `/proc/net/tcp` is checked before `/proc/net/tcp6`, and the first row whose
/// local port matches wins — a port can appear in both tables (a v4-mapped v6
/// socket shows up in both) and the original implementation always preferred
/// the IPv4 row, so this ordering is behaviour, not an accident.
pub(crate) fn find_inode(target_port: u16) -> Option<u64> {
    for path in PROC_NET_TABLES {
        if let Ok(content) = fs::read_to_string(path) {
            if let Some(inode) = parse_inode_table(&content, target_port) {
                return Some(inode);
            }
        }
    }
    None
}

/// The two tables the kernel exposes for listening/connected sockets.
pub(crate) const PROC_NET_TABLES: [&str; 2] = ["/proc/net/tcp", "/proc/net/tcp6"];

/// Extract the socket inode for `target_port` from a `/proc/net/tcp{,6}` table.
///
/// Field layout is the kernel's:
///
/// ```text
///   sl  local_address rem_address   st tx_queue rx_queue tr tm->when
///   retrnsmt   uid   timeout inode
/// 0:01: 2A0A0A0A:1F90 ...                                  12345
/// ```
///
/// so the local port is field 1 after the colon and the inode is field 9.
///
/// This walks the whitespace-separated fields with an iterator instead of
/// materialising a `Vec<&str>` per line. With a few hundred sockets per host
/// that allocation happened once per row, on a path that runs for every inbound
/// packet; `tests::parser_agrees_with_allocating_reference` pins the iterator
/// version against the allocating original on generated tables so the rewrite
/// cannot drift.
pub(crate) fn parse_inode_table(table: &str, target_port: u16) -> Option<u64> {
    let mut fields = table.lines();
    // Row 0 is the header: `sl local_address rem_address st ...`.
    fields.next()?;

    for line in fields {
        let mut row = line.split_whitespace();

        // Rows shorter than 10 fields are incomplete and are skipped, exactly
        // as the allocating version skipped `parts.len() < 10`.
        let Some(local_addr) = row.nth(1) else { continue };
        let Some(inode) = row.nth(7) else { continue };

        // A local address without a colon, or with a non-hex port, is not a
        // match -- and, as in the original, it does not stop the scan.
        let Some(port_hex) = local_addr.split(':').nth(1) else { continue };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else { continue };

        if port == target_port {
            // A matching row whose inode will not parse is a hard stop: the
            // original returned `None` here rather than continuing.
            return inode.parse().ok();
        }
    }
    None
}

/// Walk `/proc/[pid]/fd` looking for the socket that owns `target_inode`.
///
/// Every pid directory and every file descriptor beneath it is read, and each
/// descriptor is `readlink`ed and compared against `socket:[inode]`. This is
/// the dominant cost of the whole lookup by a wide margin — see the module
/// docs in `uring.rs` for why io_uring cannot take it over.
pub(crate) fn find_pid_by_inode(target_inode: u64) -> Option<ProcessInfo> {
    let target_link = format!("socket:[{}]", target_inode);

    // Iterate over /proc/[pid]/fd
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let pid_str = match path.file_name().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => continue,
            };

            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let fd_path = path.join("fd");
            if let Ok(fds) = fs::read_dir(fd_path) {
                for fd in fds.flatten() {
                    if let Ok(link) = fs::read_link(fd.path()) {
                        if link.to_string_lossy() == target_link {
                            return read_process_name(&path, pid);
                        }
                    }
                }
            }
        }
    }
    None
}

/// `comm` holds the executable name with a trailing newline.
///
/// A read failure yields the literal `"unknown"` — including the trailing
/// `.trim()`, which on the error path is a no-op, so the field is exactly
/// `unknown` and not `unknown\n`. Both the fallback string and the trim are
/// part of the metadata the routing rules match on, so they are preserved.
pub(crate) fn read_process_name(proc_dir: &std::path::Path, pid: u32) -> Option<ProcessInfo> {
    let name = fs::read_to_string(proc_dir.join("comm"))
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();
    Some(ProcessInfo { pid, name })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
 0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n\
 1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 54321 1 0000000000000000 100 0 0 10 0\n\
 2: 0100007F:1F91 0200007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0\n\
 3: 0200007F:C001 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n";

    /// The pre-rewrite implementation, kept verbatim. Every behavioural
    /// question about the iterator rewrite is settled by this test.
    fn parse_inode_table_allocating(table: &str, target_port: u16) -> Option<u64> {
        for line in table.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }
            let local_addr = parts[1];
            if let Some(port_hex) = local_addr.split(':').nth(1) {
                if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                    if port == target_port {
                        return parts[9].parse().ok();
                    }
                }
            }
        }
        None
    }

    #[test]
    fn header_row_is_never_matched() {
        // The header contains no colon, so both versions must fall through it
        // rather than treating `local_address` as a port.
        assert_eq!(parse_inode_table(TABLE, 0), None);
        assert_eq!(parse_inode_table_allocating(TABLE, 0), None);
    }

    #[test]
    fn matches_every_row_by_port() {
        // 0x1F90 is 8080, 0x0277 is 631, 0xC001 is 49153.
        for (port, inode) in [(0x1F90u16, 12345u64), (0x0277, 54321), (0xC001, 4242)] {
            assert_eq!(parse_inode_table(TABLE, port), Some(inode), "port {port:#x}");
            assert_eq!(parse_inode_table_allocating(TABLE, port), Some(inode));
        }
        // No row listens on 443.
        assert_eq!(parse_inode_table(TABLE, 443), None);
        assert_eq!(parse_inode_table_allocating(TABLE, 443), None);
    }

    #[test]
    fn first_matching_row_wins() {
        // Same port in two rows: both versions must return the first inode.
        let dup =
            format!("{TABLE} 4: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 77777 1 0 100 0 0 10 0\n");
        assert_eq!(parse_inode_table(&dup, 0x1F90), Some(12345));
        assert_eq!(parse_inode_table_allocating(&dup, 0x1F90), Some(12345));
    }

    #[test]
    fn short_and_malformed_rows_are_skipped() {
        // A truncated row must not stop the scan, and must not abort it either:
        // the allocating version used `continue`, so rows after it still count.
        let truncated = format!(
            "{TABLE}4: 0100007F:BEEF 00000000:0000\n\
             5: 0100007F:DEAD 00000000:0000 0A 0 0 0 0 0 31337 1 0 100 0 0 10 0\n"
        );
        assert_eq!(parse_inode_table(&truncated, 0xDEAD), Some(31337));
        assert_eq!(parse_inode_table_allocating(&truncated, 0xDEAD), Some(31337));
    }

    #[test]
    fn non_numeric_inode_is_not_a_match() {
        let bad =
            format!("{TABLE}6: 0100007F:FEED 00000000:0000 0A 0 0 0 0 0 nope 1 0 100 0 0 10 0\n");
        assert_eq!(parse_inode_table(&bad, 0xFEED), None);
        assert_eq!(parse_inode_table_allocating(&bad, 0xFEED), None);
    }

    /// Exhaustive agreement check over generated tables.
    ///
    /// The iterator rewrite trades a per-row `Vec<&str>` for a walk over
    /// `split_whitespace`. That is only safe if the two agree on *every* input
    /// shape the kernel can emit, including rows with too few fields, rows with
    /// a non-numeric port, rows with a non-numeric inode, and empty tables.
    /// Deterministic pseudo-random generation keeps this a unit test rather
    /// than a property-test dependency, and sweeps 20k tables x 3 ports.
    #[test]
    fn parser_agrees_with_allocating_reference() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..20_000 {
            let rows = (next() % 6) as usize;
            let mut table = String::from(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n",
            );
            for _ in 0..rows {
                let addr = match next() % 5 {
                    0 => format!("0100007F:{:04X}", next() % 0x1_0000),
                    1 => format!("00000000:{:04X}", next() % 0x1_0000),
                    2 => "0100007F:ZZZZ".to_string(),
                    3 => format!("0100007F:{:04X}", next() % 0x1_0000),
                    _ => format!("malformed{}-{}", next() % 100, next() % 100),
                };
                let inode = match next() % 6 {
                    0 => format!("{}", next() % 100_000),
                    1 => "not-a-number".to_string(),
                    2 => format!("{}", next() % 100_000),
                    _ => format!("{}", next() % 100_000),
                };
                // Vary the field count so some rows land below the 10-field
                // floor and get skipped by both implementations.
                let n_fields = 1 + (next() % 14) as usize;
                let mut row: Vec<String> = Vec::with_capacity(n_fields);
                row.push("0:".to_string());
                row.push(addr.clone());
                for _ in 2..n_fields {
                    row.push("0".to_string());
                }
                // The inode only exists if the row is long enough to have one.
                if n_fields > 9 {
                    row[9] = inode.clone();
                }
                table.push_str(&row.join(" "));
                table.push('\n');
            }

            for port in [0u16, 0x1F90, 0xBEEF, u16::MAX] {
                assert_eq!(
                    parse_inode_table(&table, port),
                    parse_inode_table_allocating(&table, port),
                    "disagreement on port {port:#x} in:\n{table}"
                );
            }
        }
    }

    #[test]
    fn empty_table_has_no_match() {
        assert_eq!(parse_inode_table("", 80), None);
        assert_eq!(parse_inode_table_allocating("", 80), None);
        assert_eq!(parse_inode_table("header only\n", 80), None);
    }

    /// The local port is hex, and only the local port.
    ///
    /// The kernel prints the local address as `<32-bit hex address>:<16-bit hex
    /// port>`, so the port field is `001A` for 26 and `1F90` for 8080. Reading
    /// it as decimal would attribute a socket to whichever process happens to
    /// own the port whose *digits* match -- a wrong process, on a lookup whose
    /// answer drives routing and shaping.
    #[test]
    fn local_port_is_parsed_as_hex_not_decimal() {
        // 0x1A = 26 decimal, which is also 10 in hex and 26 in decimal: the one
        // row shape that separates the two readings.
        let hex_only =
            format!("{TABLE} 9: 0100007F:001A 00000000:0000 0A 0 0 0 0 0 55555 1 0 100 0 0 10 0\n");

        assert_eq!(parse_inode_table(&hex_only, 26), Some(55555), "hex reading");
        assert_eq!(parse_inode_table(&hex_only, 10), None, "decimal reading must not match");
        assert_eq!(parse_inode_table_allocating(&hex_only, 26), Some(55555));
        assert_eq!(parse_inode_table_allocating(&hex_only, 10), None);

        // 0x1F90 = 8080 decimal, 1_080 in decimal digits: the TABLE row that
        // already existed, checked against the decimal misreading.
        assert_eq!(parse_inode_table(TABLE, 8080), Some(12345));
        assert_eq!(parse_inode_table(TABLE, 1080), None);
    }

    /// The address half is ignored entirely.
    ///
    /// Only the port after the colon is consulted, so `::ffff:127.0.0.1`-style
    /// v4-mapped rows and any address the kernel may print resolve by port
    /// alone. Both backends share this parser, so this is a property of the
    /// lookup as a whole rather than of either backend.
    #[test]
    fn address_half_does_not_affect_the_match() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n\
                     0: 00000000:0277 00000000:0000 0A 0 0 0 0 0 111 1 0 100 0 0 10 0\n\
                     1: FFFFFFFF:0277 00000000:0000 0A 0 0 0 0 0 222 1 0 100 0 0 10 0\n";
        // First matching row wins regardless of the address it carries.
        assert_eq!(parse_inode_table(table, 0x0277), Some(111));
    }

    /// Socket state is not filtered.
    ///
    /// `st` is field 3 and neither backend reads it: a row in `01` (ESTABLISHED),
    /// `06` (TIME_WAIT) or `0A` (LISTEN) is matched the same way, and the first
    /// row wins whatever its state. That is deliberate and it fails *closed* --
    /// a TIME_WAIT row carries inode 0, which no `/proc/[pid]/fd` links to, so
    /// the lookup answers "no attribution" rather than "the wrong process".
    ///
    /// Pinned because a future "optimisation" that filtered on `st` would change
    /// which row wins, and that is a change of security behaviour, not of speed.
    #[test]
    fn socket_state_is_not_filtered_by_the_shared_parser() {
        let mut table = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n",
        );
        for (i, state) in ["01", "06", "0A", "08"].iter().enumerate() {
            table.push_str(&format!(
                "{i:>2}: 0100007F:BEEF 00000000:0000 {state} 0 0 0 0 0 {} 1 0 100 0 0 10 0\n",
                900 + i
            ));
        }

        // 0xBEEF = 48879. Every state is a candidate; the first row wins.
        assert_eq!(parse_inode_table(&table, 0xBEEF), Some(900));
        assert_eq!(parse_inode_table_allocating(&table, 0xBEEF), Some(900));

        // And a TIME_WAIT-only table still hands back its inode -- the fd walk
        // is what turns inode 0 into `None`, not the parser.
        let time_wait = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n\
                         0: 0100007F:C001 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0     0 1 0000000000000000 100 0 0 10 0\n";
        assert_eq!(parse_inode_table(time_wait, 0xC001), Some(0));
        assert_eq!(parse_inode_table_allocating(time_wait, 0xC001), Some(0));
    }
}
