use shadowmesh_core::engine::actor::EngineHandle;
use shadowmesh_core::transport::inbound::vmess::VlessInbound;
use shadowmesh_core::transport::traits::InboundListener;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

#[tokio::test]
async fn test_active_probing_resistance_fallback() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Start Decoy Server
    let decoy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = decoy_listener.accept().await {
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            if n > 0 {
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello Decoy!")
                    .await
                    .unwrap();
            }
        }
    });

    // 2. Start VLESS Inbound
    let (event_tx, _event_rx) = async_channel::unbounded();
    let engine = EngineHandle::new(event_tx);
    let uuid = Uuid::new_v4();

    // Get a free port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    drop(listener); // Release port for VLESS

    let vless_inbound = Arc::new(
        VlessInbound::new(
            "vless-in".into(),
            listen_addr.to_string(),
            &uuid.to_string(),
            engine,
            None,
            Some(decoy_addr.to_string()),
        )
        .unwrap(),
    );

    let vless_task = vless_inbound.clone();
    tokio::spawn(async move {
        vless_task.listen().await.unwrap();
    });

    // Give it a moment to bind
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // 3. Unauthorized Probe (Simulate random HTTP request)
    let mut probe_stream = TcpStream::connect(listen_addr).await.unwrap();
    probe_stream.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await.unwrap();

    let mut response = [0u8; 1024];
    let n = probe_stream.read(&mut response).await.unwrap();
    let resp_str = String::from_utf8_lossy(&response[..n]);

    // Should return decoy response, not an error or closed connection
    assert!(resp_str.contains("Hello Decoy!"));
    assert!(resp_str.contains("200 OK"));
}
