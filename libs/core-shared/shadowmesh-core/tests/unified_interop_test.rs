use shadowmesh_core::engine::actor::EngineHandle;
use shadowmesh_core::engine::events::EngineEvent;
use shadowmesh_core::transport::inbound::vmess::VlessInbound;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

#[tokio::test]
async fn test_vless_unified_interop() {
    let _ = tracing_subscriber::fmt::try_init();
    let uuid = Uuid::new_v4();
    let uuid_str = uuid.to_string();

    // 1. Setup Mock Echo Server (The ultimate destination)
    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        socket.write_all(&buf[..n]).await.unwrap();
    });

    // 2. Setup VLESS Inbound (Server Side)
    let (in_event_tx, in_event_rx) = async_channel::unbounded();
    let in_engine = EngineHandle::new(in_event_tx);

    // The inbound should forward to the echo server
    tokio::spawn(async move {
        while let Ok(event) = in_event_rx.recv().await {
            if let EngineEvent::NewStream { mut stream, .. } = event {
                let mut target = TcpStream::connect(echo_addr).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
            }
        }
    });

    let _vless_in = VlessInbound::new(
        "server-in".into(),
        "127.0.0.1:0".into(),
        &uuid_str,
        in_engine,
        None,
        None,
    )
    .unwrap();

    // We need to know the port. Let's bind manually.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    drop(listener); // Close to let VlessInbound bind

    // Re-create with known port
    let _vless_in = VlessInbound::new(
        "server-in".into(),
        server_addr.to_string(),
        &uuid_str,
        EngineHandle::new(async_channel::unbounded().0),
        None,
        None,
    )
    .unwrap();

    // Wait, let's use the real VlessInbound::listen logic but we need the port.
    // I'll update VlessInbound to use a port from config if 0 is passed.
}
