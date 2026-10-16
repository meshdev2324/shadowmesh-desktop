/// Network detection and analysis components.
pub mod detector;
/// Resilient node discovery engine.
pub mod discovery;
/// Data leak prevention and firewall rules.
pub mod leak_guard;
/// Bandwidth throttling for Quantum Tunneling.
pub mod throttler;

#[cfg(test)]
mod throttler_test;

use crate::ShadowMeshError;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;

/// Creates a UDP socket tuned for high-performance VPN tunneling.
/// Sets SO_RCVBUF and SO_SNDBUF to 2MB to handle high-bandwidth bursts.
pub fn create_tuned_udp_socket(addr: SocketAddr) -> Result<std::net::UdpSocket, ShadowMeshError> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| ShadowMeshError::SocketTuningFailed)?;

    // Optimization: Aggressive buffer sizes for 1Gbps+ throughput
    let buf_size = 2 * 1024 * 1024; // 2MB
    let _ = socket.set_recv_buffer_size(buf_size);
    let _ = socket.set_send_buffer_size(buf_size);

    // Optimization: Enable PMTU discovery if possible
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let val: libc::c_int = 2; // IP_PMTUDISC_DO
                                  // SAFETY: Calling setsockopt with valid file descriptor and integer pointer.
                                  // IP_PMTUDISC_DO is a standard Linux socket option.
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    socket.bind(&addr.into()).map_err(|_| ShadowMeshError::SocketTuningFailed)?;

    Ok(socket.into())
}
