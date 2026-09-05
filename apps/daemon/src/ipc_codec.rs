use crate::types::IpcError;
use bytes::{Buf, BufMut, BytesMut};

/// High-performance IPC codec for length-prefixed (u32BE) messaging.
pub struct IpcCodec;

impl IpcCodec {
    /// Maximum payload size (64KB) to prevent OOM attacks.
    pub const MAX_PAYLOAD_SIZE: usize = 65536;
    /// Header size (4 bytes for u32 length).
    pub const HEADER_SIZE: usize = 4;

    /// Encodes a payload into a length-prefixed frame.
    pub fn encode(payload: &[u8], dst: &mut BytesMut) -> Result<(), IpcError> {
        if payload.len() > Self::MAX_PAYLOAD_SIZE {
            return Err(IpcError::PayloadTooLarge(payload.len()));
        }

        dst.reserve(Self::HEADER_SIZE + payload.len());
        dst.put_u32(payload.len() as u32);
        dst.put_slice(payload);
        Ok(())
    }

    /// Decodes a frame from the buffer. Returns None if more data is needed.
    pub fn decode(src: &mut BytesMut) -> Result<Option<BytesMut>, IpcError> {
        if src.len() < Self::HEADER_SIZE {
            return Ok(None);
        }

        // Peek at the length without consuming (Big Endian)
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&src[..4]);
        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > Self::MAX_PAYLOAD_SIZE {
            return Err(IpcError::PayloadTooLarge(len));
        }

        if src.len() < Self::HEADER_SIZE + len {
            // Wait for more data. Ensure we have enough capacity for the full frame.
            src.reserve(Self::HEADER_SIZE + len - src.len());
            return Ok(None);
        }

        // Consume the header and the payload
        src.advance(Self::HEADER_SIZE);
        let payload = src.split_to(len);
        Ok(Some(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_codec_roundtrip() {
        let mut buf = BytesMut::new();
        let payload = b"{\"action\": \"ping\", \"token\": \"test\"}";
        IpcCodec::encode(payload, &mut buf).unwrap();

        let decoded = IpcCodec::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.as_ref(), payload);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_codec_partial_read() {
        let mut buf = BytesMut::new();
        let payload = b"hello world";
        IpcCodec::encode(payload, &mut buf).unwrap();

        let mut partial = buf.split_to(6); // Only header + 2 bytes
        assert!(IpcCodec::decode(&mut partial).unwrap().is_none());

        partial.put_slice(&buf); // Add the rest
        let decoded = IpcCodec::decode(&mut partial).unwrap().unwrap();
        assert_eq!(decoded.as_ref(), payload);
    }

    proptest! {
        #[test]
        fn prop_codec_roundtrip(ref p in "\\PC*") {
            let mut buf = BytesMut::new();
            let payload = p.as_bytes();
            if payload.len() <= IpcCodec::MAX_PAYLOAD_SIZE {
                IpcCodec::encode(payload, &mut buf).unwrap();
                let decoded = IpcCodec::decode(&mut buf).unwrap().unwrap();
                prop_assert_eq!(decoded.as_ref(), payload);
                prop_assert!(buf.is_empty());
            }
        }

        #[test]
        fn prop_codec_partial_recovery(ref p in "\\PC*", split_at in 0..100usize) {
            let mut buf = BytesMut::new();
            let payload = p.as_bytes();
            if !payload.is_empty() && payload.len() <= 1024 {
                IpcCodec::encode(payload, &mut buf).unwrap();
                let total_len = buf.len();
                let split = split_at % total_len;

                let mut first_half = buf.split_to(split);
                prop_assert!(IpcCodec::decode(&mut first_half).unwrap().is_none());

                first_half.put_slice(&buf);
                let decoded = IpcCodec::decode(&mut first_half).unwrap().unwrap();
                prop_assert_eq!(decoded.as_ref(), payload);
            }
        }
    }
}
