use crate::orchestration::SystemCommandRunner;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait DnsManager: Send + Sync {
    /// Configures the system DNS for the specified interface.
    async fn set_dns(&self, interface: &str, dns_servers: Vec<String>) -> anyhow::Result<()>;

    /// Resets the system DNS for the specified interface to its default state (usually DHCP).
    async fn reset_dns(&self, interface: &str) -> anyhow::Result<()>;
}

pub struct LinuxDnsManager {
    runner: Arc<dyn SystemCommandRunner>,
}

#[cfg(target_os = "linux")]
#[zbus::proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1"
)]
trait SystemdResolved {
    fn set_link_dns(&self, ifindex: i32, addresses: Vec<(i32, Vec<u8>)>) -> zbus::Result<()>;
    fn set_link_domains(&self, ifindex: i32, domains: Vec<(String, bool)>) -> zbus::Result<()>;
    fn revert_link(&self, ifindex: i32) -> zbus::Result<()>;
}

#[async_trait]
impl DnsManager for LinuxDnsManager {
    async fn set_dns(&self, interface: &str, dns_servers: Vec<String>) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::net::IpAddr;
            use std::str::FromStr;

            let ifindex =
                unsafe { libc::if_nametoindex(std::ffi::CString::new(interface)?.as_ptr()) };
            if ifindex == 0 {
                return Err(anyhow::anyhow!("Interface {} not found", interface));
            }

            let connection = zbus::Connection::system().await?;
            let proxy = SystemdResolvedProxy::new(&connection).await?;

            let mut addresses = Vec::new();
            for dns in dns_servers.iter() {
                if let Ok(ip) = IpAddr::from_str(dns) {
                    match ip {
                        IpAddr::V4(v4) => addresses.push((libc::AF_INET, v4.octets().to_vec())),
                        IpAddr::V6(v6) => addresses.push((libc::AF_INET6, v6.octets().to_vec())),
                    }
                }
            }

            // Set DNS servers via native DBus call (Microsecond latency)
            proxy.set_link_dns(ifindex as i32, addresses).await?;
            // Force all queries through this link for ShadowMesh
            proxy.set_link_domains(ifindex as i32, vec![(".".to_string(), true)]).await?;

            // HARDENING: Add firewall rules to block DNS bypass
            // Block all outbound DNS (port 53) NOT going through shadowmesh-wg0
            self.runner
                .run_command(
                    "iptables",
                    &[
                        "-A", "OUTPUT", "-p", "udp", "--dport", "53", "!", "-o", interface, "-j",
                        "REJECT",
                    ],
                )
                .await?;
            self.runner
                .run_command(
                    "iptables",
                    &[
                        "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "!", "-o", interface, "-j",
                        "REJECT",
                    ],
                )
                .await?;

            // IPv6 Leak Protection: Reject all IPv6 DNS queries to prevent leaks via dual-stack
            self.runner
                .run_command(
                    "ip6tables",
                    &["-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REJECT"],
                )
                .await?;
            self.runner
                .run_command(
                    "ip6tables",
                    &["-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REJECT"],
                )
                .await?;

            return Ok(());
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = interface;
            let _ = dns_servers;
            Ok(())
        }
    }

    async fn reset_dns(&self, interface: &str) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let ifindex =
                unsafe { libc::if_nametoindex(std::ffi::CString::new(interface)?.as_ptr()) };
            if ifindex != 0 {
                let connection = zbus::Connection::system().await?;
                let proxy = SystemdResolvedProxy::new(&connection).await?;
                proxy.revert_link(ifindex as i32).await?;
            }

            // Remove hardening rules
            let _ = self
                .runner
                .run_command(
                    "iptables",
                    &[
                        "-D", "OUTPUT", "-p", "udp", "--dport", "53", "!", "-o", interface, "-j",
                        "REJECT",
                    ],
                )
                .await;
            let _ = self
                .runner
                .run_command(
                    "iptables",
                    &[
                        "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "!", "-o", interface, "-j",
                        "REJECT",
                    ],
                )
                .await;
            let _ = self
                .runner
                .run_command(
                    "ip6tables",
                    &["-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REJECT"],
                )
                .await;
            let _ = self
                .runner
                .run_command(
                    "ip6tables",
                    &["-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REJECT"],
                )
                .await;

            return Ok(());
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = interface;
            Ok(())
        }
    }
}

pub struct WindowsDnsManager {
    runner: Arc<dyn SystemCommandRunner>,
}

#[async_trait]
impl DnsManager for WindowsDnsManager {
    async fn set_dns(&self, interface: &str, dns_servers: Vec<String>) -> anyhow::Result<()> {
        if dns_servers.is_empty() {
            return self.reset_dns(interface).await;
        }

        // Set the primary DNS
        self.runner
            .run_command(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "dnsserver",
                    interface,
                    "static",
                    &dns_servers[0],
                    "primary",
                ],
            )
            .await?;

        // Add additional DNS servers
        for (i, dns) in dns_servers.iter().enumerate().skip(1) {
            let index = (i + 1).to_string();
            self.runner
                .run_command(
                    "netsh",
                    &[
                        "interface",
                        "ipv4",
                        "add",
                        "dnsserver",
                        interface,
                        dns,
                        &format!("index={}", index),
                    ],
                )
                .await?;
        }
        Ok(())
    }

    async fn reset_dns(&self, interface: &str) -> anyhow::Result<()> {
        self.runner
            .run_command(
                "netsh",
                &["interface", "ipv4", "set", "dnsserver", interface, "source=dhcp"],
            )
            .await?;
        Ok(())
    }
}

pub struct MacDnsManager {
    runner: Arc<dyn SystemCommandRunner>,
}

#[async_trait]
impl DnsManager for MacDnsManager {
    async fn set_dns(&self, interface: &str, dns_servers: Vec<String>) -> anyhow::Result<()> {
        let dns_list = dns_servers.join(" ");
        self.runner.run_command("networksetup", &["-setdnsservers", interface, &dns_list]).await?;
        Ok(())
    }

    async fn reset_dns(&self, interface: &str) -> anyhow::Result<()> {
        self.runner.run_command("networksetup", &["-setdnsservers", interface, "Empty"]).await?;
        Ok(())
    }
}

/// Factory function to create the appropriate DnsManager for the current platform.
pub fn create_dns_manager(runner: Arc<dyn SystemCommandRunner>) -> Arc<dyn DnsManager> {
    #[cfg(target_os = "linux")]
    return Arc::new(LinuxDnsManager { runner });
    #[cfg(target_os = "windows")]
    return Arc::new(WindowsDnsManager { runner });
    #[cfg(target_os = "macos")]
    return Arc::new(MacDnsManager { runner });
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    panic!("Unsupported platform for DnsManager");
}
