use serde::Serialize;
use std::fs;

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

pub struct ProcessSearcher;

impl ProcessSearcher {
    pub fn find_process_info(local_port: u16) -> Option<ProcessInfo> {
        let inode = Self::find_inode(local_port)?;
        Self::find_pid_by_inode(inode)
    }

    fn find_inode(target_port: u16) -> Option<u64> {
        // Parse /proc/net/tcp and /proc/net/tcp6
        for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 10 {
                        continue;
                    }

                    // local_address is 2nd column: IP:PORT in hex
                    let local_addr = parts[1];
                    if let Some(port_hex) = local_addr.split(':').nth(1) {
                        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                            if port == target_port {
                                return parts[9].parse().ok();
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn find_pid_by_inode(target_inode: u64) -> Option<ProcessInfo> {
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
                                let name = fs::read_to_string(path.join("comm"))
                                    .unwrap_or_else(|_| "unknown".to_string())
                                    .trim()
                                    .to_string();
                                return Some(ProcessInfo { pid, name });
                            }
                        }
                    }
                }
            }
        }
        None
    }
}
