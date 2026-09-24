use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use hmac::Hmac;
use md5::{Digest, Md5};
use parking_lot::Mutex;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use shadowmesh_core::engine::context::ConnectionContext;
use shadowmesh_core::engine::metadata::{ConnectionMetadata, Endpoint};
use shadowmesh_core::transport::outbound::vmess::VmessOutbound;
use shadowmesh_core::transport::traits::OutboundDialer;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

#[tokio::test]
async fn test_vmess_handshake_and_aead_data_success() {
    let _ = tracing_subscriber::fmt::try_init();
    let uuid = Uuid::new_v4();
    let uuid_str = uuid.to_string();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        let mut auth_id_buf = [0u8; 16];
        socket.read_exact(&mut auth_id_buf).await.unwrap();

        let now = chrono::Utc::now().timestamp();
        let mut found_valid_ts = false;
        let mut target_ts = 0;
        use hmac::Mac;
        for ts in now - 1..=now + 1 {
            let mut hmac: Hmac<Md5> = KeyInit::new_from_slice(uuid.as_bytes()).unwrap();
            hmac.update(&ts.to_be_bytes());
            let expected_auth_id = hmac.finalize().into_bytes();
            if auth_id_buf == expected_auth_id.as_slice() {
                found_valid_ts = true;
                target_ts = ts;
                break;
            }
        }
        assert!(found_valid_ts, "Valid AuthID not found");

        let mut key_md5 = Md5::new();
        key_md5.update(uuid.as_bytes());
        key_md5.update(b"c4861939-ed4a-43f6-932c-354924a4f89d");
        let key_bytes: [u8; 16] = key_md5.finalize().into();

        let mut iv_md5 = Md5::new();
        let ts_bytes = (target_ts as u64).wrapping_mul(4).to_be_bytes();
        for _ in 0..4 {
            iv_md5.update(ts_bytes);
        }
        let iv_bytes: [u8; 16] = iv_md5.finalize().into();

        let cipher = Aes128::new(&key_bytes.into());
        let mut feedback = iv_bytes;

        // Decrypt header for IPv4 (45 bytes + 4 bytes checksum = 49 bytes)
        let mut header = Vec::new();
        for _ in 0..49 {
            let b = socket.read_u8().await.unwrap();
            let mut block = feedback;
            cipher.encrypt_block((&mut block).into());
            let decrypted = b ^ block[0];
            header.push(decrypted);
            feedback.rotate_left(1);
            feedback[15] = b;
        }

        assert_eq!(header[0], 0x01);
        let request_key_bytes: [u8; 16] = header[17..33].try_into().unwrap();
        let unbound_key = UnboundKey::new(&AES_128_GCM, &request_key_bytes).unwrap();
        let aead = LessSafeKey::new(unbound_key);

        // Read AEAD Chunked Data
        let mut len_chunk = [0u8; 18];
        socket.read_exact(&mut len_chunk).await.unwrap();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&0u64.to_be_bytes()); // Seq 0

        let decrypted_len = aead
            .open_in_place(
                Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap(),
                Aad::empty(),
                &mut len_chunk,
            )
            .unwrap();
        let payload_len = u16::from_be_bytes(decrypted_len[..2].try_into().unwrap()) as usize;

        let mut payload_chunk = vec![0u8; payload_len + 16];
        socket.read_exact(&mut payload_chunk).await.unwrap();
        let decrypted_payload = aead
            .open_in_place(
                Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap(),
                Aad::empty(),
                &mut payload_chunk,
            )
            .unwrap();

        assert_eq!(decrypted_payload, b"ping");

        // Echo using AEAD (Seq 0 as well for simplicity in mock)
        let mut resp_len = (4u16).to_be_bytes().to_vec();
        let tag = aead
            .seal_in_place_separate_tag(
                Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap(),
                Aad::empty(),
                &mut resp_len,
            )
            .unwrap();
        socket.write_all(&resp_len).await.unwrap();
        socket.write_all(tag.as_ref()).await.unwrap();

        let mut resp_payload = b"ping".to_vec();
        let tag = aead
            .seal_in_place_separate_tag(
                Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap(),
                Aad::empty(),
                &mut resp_payload,
            )
            .unwrap();
        socket.write_all(&resp_payload).await.unwrap();
        socket.write_all(tag.as_ref()).await.unwrap();
    });

    let outbound = VmessOutbound::new(
        "test".into(),
        "127.0.0.1".into(),
        server_addr.port(),
        &uuid_str,
        "aes-128-gcm".into(),
    )
    .unwrap();

    let metadata = ConnectionMetadata::new(Endpoint::new_ip("1.2.3.4".parse().unwrap(), 443));
    let context = Arc::new(Mutex::new(ConnectionContext::new(metadata)));

    let mut stream = outbound.dial_stream(context).await.unwrap();

    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();

    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ping");

    server_handle.await.unwrap();
}
