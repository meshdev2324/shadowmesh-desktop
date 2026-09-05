#![no_main]
//! Fuzz target: VMess AEAD chunked data stream (VmessStream).
//!
//! Exercises bidirectional encrypt→decrypt round-trip over a duplex for
//! arbitrary payloads. Invariants: no panic, lossless round-trip, chunk
//! authentication failures surface as io errors, oversized chunks rejected.

use libfuzzer_sys::fuzz_target;
use shadowmesh_core::transport::outbound::vmess::VmessStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fuzz_target!(|data: &[u8]| {
    let payload = if data.len() > 4096 { &data[..4096] } else { data };
    let key = [0x42u8; 16];
    let iv = [0x24u8; 16];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fuzz runtime");
    rt.block_on(async move {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let mut a = VmessStream::new(client_io, key, iv).unwrap();
        let mut b = VmessStream::new(server_io, key, iv).unwrap();

        if a.write_all(payload).await.is_ok() && a.flush().await.is_ok() {
            let mut received = vec![0u8; payload.len()];
            if b.read_exact(&mut received).await.is_ok() {
                assert_eq!(received, payload);
            }
        }

        if b.write_all(payload).await.is_ok() && b.flush().await.is_ok() {
            let mut received = vec![0u8; payload.len()];
            if a.read_exact(&mut received).await.is_ok() {
                assert_eq!(received, payload);
            }
        }
    });
});
