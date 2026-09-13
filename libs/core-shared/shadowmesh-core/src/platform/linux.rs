use anyhow::{anyhow, Result};
use libc::{splice, SPLICE_F_MOVE, SPLICE_F_NONBLOCK};
use std::fs;
use std::io;
use std::os::unix::io::RawFd;
use std::process::Command;
use tracing::info;

/// Attempt zero-copy data transfer between two FDs using splice(2).
/// Includes mandatory fallback logic per DEBUGGABILITY.md §2.
pub fn splice_forward(src: RawFd, dst: RawFd, len: usize) -> Result<usize> {
    let n = unsafe {
        splice(
            src,
            std::ptr::null_mut(),
            dst,
            std::ptr::null_mut(),
            len,
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK,
        )
    };

    if n < 0 {
        let err = io::Error::last_os_error();
        // Fallback on ENOSYS (not implemented) or EINVAL (pipe requirement)
        if err.kind() == io::ErrorKind::InvalidInput || err.raw_os_error() == Some(libc::ENOSYS) {
            return Err(anyhow!("Splice not supported, falling back to standard I/O: {}", err));
        }
        return Err(anyhow!("Splice failed: {}", err));
    }

    Ok(n as usize)
}

/// Enable TCP_FASTOPEN (TFO) on the given socket FD.
pub fn enable_tfo(fd: RawFd) -> Result<()> {
    let qlen: libc::c_int = 5;
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &qlen as *const _ as *const libc::c_void,
            std::mem::size_of_val(&qlen) as libc::socklen_t,
        )
    };

    if res < 0 {
        return Err(anyhow!("Failed to enable TCP_FASTOPEN: {}", io::Error::last_os_error()));
    }

    Ok(())
}

/// Linux-specific platform orchestration (TUN/Routing).
pub struct LinuxPlatform;

impl LinuxPlatform {
    /// Sets up routing for a TUN interface.
    pub fn setup_tun(name: &str, _address: &str, _netmask: &str) -> Result<()> {
        info!("Setting up routing for TUN interface {}", name);

        // 1. Set interface up
        Self::run_command("ip", &["link", "set", name, "up"])?;

        // 2. Example: Route FakeIP range through TUN
        // v6.9.2: Hardcoded for now, should be configurable
        Self::run_command("ip", &["route", "add", "198.18.0.0/16", "dev", name])?;

        Ok(())
    }

    /// Tears down routing for a TUN interface.
    pub fn teardown_tun(name: &str) -> Result<()> {
        info!("Tearing down routing for TUN interface {}", name);
        let _ = Self::run_command("ip", &["route", "del", "198.18.0.0/16", "dev", name]);
        let _ = Self::run_command("ip", &["link", "set", name, "down"]);
        Ok(())
    }

    /// Hijacks system DNS to point to a local resolver.
    pub fn hijack_dns(dns_server: &str) -> Result<()> {
        info!("Hijacking DNS to {}", dns_server);
        // Backup /etc/resolv.conf
        if fs::metadata("/etc/resolv.conf.bak").is_err() {
            fs::copy("/etc/resolv.conf", "/etc/resolv.conf.bak")?;
        }

        let content = format!("nameserver {}\n", dns_server);
        fs::write("/etc/resolv.conf", content)?;
        Ok(())
    }

    /// Restores system DNS from backup.
    pub fn restore_dns() -> Result<()> {
        info!("Restoring DNS");
        if fs::metadata("/etc/resolv.conf.bak").is_ok() {
            let _ = fs::copy("/etc/resolv.conf.bak", "/etc/resolv.conf");
        }
        Ok(())
    }

    fn run_command(cmd: &str, args: &[&str]) -> Result<()> {
        let status = Command::new(cmd).args(args).status()?;

        if status.success() {
            Ok(())
        } else {
            Err(anyhow!("Command {} {:?} failed with exit code {:?}", cmd, args, status.code()))
        }
    }
}
