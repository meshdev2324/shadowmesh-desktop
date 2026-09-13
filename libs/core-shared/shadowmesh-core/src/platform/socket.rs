use anyhow::Result;
use socket2::{Socket, TcpKeepalive};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

/// Apply high-performance socket tuning per keneral & debug .md.
pub fn tune_tcp_socket(socket: &Socket) -> Result<()> {
    // Enable TCP_NODELAY by default to eliminate Nagle's delay
    socket.set_nodelay(true)?;

    // Configure keepalive for long-lived proxy streams
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10))
        .with_retries(3);
    socket.set_tcp_keepalive(&keepalive)?;

    // Enable SO_REUSEPORT for multi-core scalability
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;

    Ok(())
}

/// Helper to tune a standard library TcpStream.
pub fn tune_std_tcp_stream(stream: &TcpStream) -> Result<()> {
    use std::os::unix::io::FromRawFd;
    let socket = unsafe { Socket::from_raw_fd(stream.as_raw_fd()) };
    let res = tune_tcp_socket(&socket);
    // Don't drop the socket as it would close the FD
    std::mem::forget(socket);
    res
}
