use parking_lot::Mutex;
use shadowmesh_core::engine::context::ConnectionContext;
use shadowmesh_core::engine::metadata::{ConnectionMetadata, Endpoint};
use shadowmesh_core::transport::outbound::vmess::VlessOutbound;
use shadowmesh_core::transport::traits::OutboundDialer;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

#[tokio::test]
async fn test_vless_handshake_success() {
    let _ = tracing_subscriber::fmt::try_init();
    let uuid = Uuid::new_v4();
    let uuid_str = uuid.to_string();

    // 1. Start Mock VLESS Server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        let _ = n; // handshake length asserted via field checks below

        // Validate VLESS Handshake
        // [Version 1b][UUID 16b][Addons Len 1b][Addons][Command 1b][Port 2b][AddrType 1b]
        assert_eq!(buf[0], 0x00); // Version
        assert_eq!(&buf[1..17], uuid.as_bytes()); // UUID
        assert_eq!(buf[17], 0x00); // Addons Len (0 in this test)
        assert_eq!(buf[18], 0x01); // Command: Connect

        // Port should be 443 (0x01BB) at index 19, 20
        let port = u16::from_be_bytes([buf[19], buf[20]]);
        assert_eq!(port, 443);

        assert_eq!(buf[21], 0x03); // Addr Type: Domain

        // Send VLESS Success Response [Version, Addons Len]
        socket.write_all(&[0x00, 0x00]).await.unwrap();

        // Echo test
        let mut data = [0u8; 4];
        socket.read_exact(&mut data).await.unwrap();
        socket.write_all(&data).await.unwrap();
    });

    // 2. Start VLESS Client
    let outbound = VlessOutbound::new(
        "test".into(),
        "127.0.0.1".into(),
        server_addr.port(),
        &uuid_str,
        "".into(),
        None,
    )
    .unwrap();

    let metadata = ConnectionMetadata::new(Endpoint::new_domain("google.com".into(), 443));
    let context = Arc::new(Mutex::new(ConnectionContext::new(metadata)));

    let mut stream = outbound.dial_stream(context).await.unwrap();

    // 3. Roundtrip verification
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ping");

    server_handle.await.unwrap();
}
