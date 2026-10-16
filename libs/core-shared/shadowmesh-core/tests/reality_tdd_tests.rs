use bytes::{BufMut, BytesMut};
use std::io::{Cursor, Read};

// Simulate the logic we want in reality.rs
fn parse_next_packet(stream: &mut Cursor<Vec<u8>>) -> Option<Vec<u8>> {
    let mut cmd_buf = [0u8; 1];
    if stream.read_exact(&mut cmd_buf).is_err() {
        return None;
    }
    let cmd = cmd_buf[0];

    if cmd == 0x01 {
        // Data Frame (Vision)
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).is_err() {
            return None;
        }
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut payload = vec![0u8; len];
        if stream.read_exact(&mut payload).is_err() {
            return None;
        }

        // Inner Layer XUDP
        let data_len = u16::from_be_bytes([payload[7], payload[8]]) as usize;
        return Some(payload[9..9 + data_len].to_vec());
    } else if cmd == 0x02 {
        // Padding Frame (Vision)
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).is_err() {
            return None;
        }
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut dummy = vec![0u8; len];
        let _ = stream.read_exact(&mut dummy);

        // Recurse to find the next actual data frame
        return parse_next_packet(stream);
    }
    None
}

#[test]
fn test_vision_data_frame() {
    let mut xudp = BytesMut::new();
    xudp.put_u8(0x01); // IPv4
    xudp.put(&[127, 0, 0, 1][..]);
    xudp.put_u16(51820);
    xudp.put_u16(5); // Len
    xudp.put(&[0, 1, 2, 3, 4][..]);

    let mut data = BytesMut::new();
    data.put_u8(0x01); // Cmd: Data
    data.put_u16(xudp.len() as u16); // Vision Len
    data.put(xudp);

    let mut cursor = Cursor::new(data.to_vec());
    let result = parse_next_packet(&mut cursor).unwrap();
    assert_eq!(result, vec![0, 1, 2, 3, 4]);
}

#[test]
fn test_vision_with_padding() {
    let mut data = BytesMut::new();
    data.put_u8(0x02); // Cmd: Padding
    data.put_u16(10); // Len
    data.put(&[0u8; 10][..]); // Padding garbage

    let mut xudp = BytesMut::new();
    xudp.put_u8(0x01); // IPv4
    xudp.put(&[127, 0, 0, 1][..]);
    xudp.put_u16(51820);
    xudp.put_u16(3); // Len
    xudp.put(&[9, 8, 7][..]);

    data.put_u8(0x01); // Cmd: Data
    data.put_u16(xudp.len() as u16);
    data.put(xudp);

    let mut cursor = Cursor::new(data.to_vec());
    let result = parse_next_packet(&mut cursor).unwrap();
    assert_eq!(result, vec![9, 8, 7]);
}

#[test]
fn test_diagnosis_of_4612_error() {
    let mut data = BytesMut::new();
    data.put_u8(0x02); // Command Padding
    data.put_u16(4612); // LARGE PADDING (0x1204)
    data.put(vec![0u8; 4612].as_slice());

    let mut xudp = BytesMut::new();
    xudp.put_u8(0x01); // IPv4
    xudp.put(&[127, 0, 0, 1][..]);
    xudp.put_u16(51820);
    xudp.put_u16(4);
    xudp.put(&[1, 2, 3, 4][..]);

    data.put_u8(0x01); // Real Data
    data.put_u16(xudp.len() as u16);
    data.put(xudp);

    let mut cursor = Cursor::new(data.to_vec());
    let result = parse_next_packet(&mut cursor).unwrap();
    assert_eq!(result, vec![1, 2, 3, 4]);
}
