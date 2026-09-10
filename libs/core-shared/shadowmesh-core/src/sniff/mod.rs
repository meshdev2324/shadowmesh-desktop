use crate::engine::metadata::SniffedData;
use async_trait::async_trait;

#[async_trait]
pub trait Sniffer: Send + Sync {
    fn name(&self) -> &str;
    async fn sniff(&self, data: &[u8]) -> Option<SniffedData>;
}

pub struct TlsSniffer;

#[async_trait]
impl Sniffer for TlsSniffer {
    fn name(&self) -> &str {
        "tls"
    }

    async fn sniff(&self, data: &[u8]) -> Option<SniffedData> {
        if data.len() < 5 {
            return None;
        }

        // TLS ContentType (1 byte) + Version (2 bytes) + Length (2 bytes)
        if data[0] != 0x16 { // Handshake
            return None;
        }

        // We only care about ClientHello
        if data.len() < 43 || data[5] != 0x01 {
            return None;
        }

        let mut pos = 43; // Skip Header(5) + HandshakeHeader(4) + Version(2) + Random(32)

        // Session ID
        if pos >= data.len() { return None; }
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher Suites
        if pos + 1 >= data.len() { return None; }
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
        pos += 2 + cipher_suites_len;

        // Compression Methods
        if pos >= data.len() { return None; }
        let compression_methods_len = data[pos] as usize;
        pos += 1 + compression_methods_len;

        // Extensions
        if pos + 1 >= data.len() { return None; }
        let extensions_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
        pos += 2;
        let extensions_end = pos + extensions_len;

        while pos + 3 < data.len() && pos + 3 < extensions_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos+1]]);
            let ext_len = u16::from_be_bytes([data[pos+2], data[pos+3]]) as usize;
            pos += 4;

            if ext_type == 0x00 { // server_name
                if pos + 2 >= data.len() { return None; }
                let sn_list_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
                pos += 2;

                let mut sn_pos = pos;
                let sn_end = pos + sn_list_len;
                while sn_pos + 2 < data.len() && sn_pos + 2 < sn_end {
                    let name_type = data[sn_pos];
                    let name_len = u16::from_be_bytes([data[sn_pos+1], data[sn_pos+2]]) as usize;
                    sn_pos += 3;
                    if name_type == 0x00 { // host_name
                        if sn_pos + name_len <= data.len() {
                            let domain = String::from_utf8_lossy(&data[sn_pos..sn_pos+name_len]).to_string();
                            return Some(SniffedData {
                                protocol: Some("tls".to_string()),
                                domain: Some(domain),
                            });
                        }
                    }
                    sn_pos += name_len;
                }
            }
            pos += ext_len;
        }

        Some(SniffedData {
            protocol: Some("tls".to_string()),
            domain: None,
        })
    }
}

pub struct HttpSniffer;

#[async_trait]
impl Sniffer for HttpSniffer {
    fn name(&self) -> &str {
        "http"
    }

    async fn sniff(&self, data: &[u8]) -> Option<SniffedData> {
        let text = String::from_utf8_lossy(data);
        let lines: Vec<&str> = text.lines().collect();
        if lines.is_empty() {
            return None;
        }

        let first_line = lines[0];
        let methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH", "TRACE"];
        if !methods.iter().any(|m| first_line.starts_with(m)) {
            return None;
        }

        let mut domain = None;
        for line in lines.iter().skip(1) {
            if line.to_lowercase().starts_with("host:") {
                domain = Some(line[5..].trim().to_string());
                break;
            }
        }

        Some(SniffedData {
            protocol: Some("http".to_string()),
            domain,
        })
    }
}

pub struct UdpSniffer;

#[async_trait]
impl Sniffer for UdpSniffer {
    fn name(&self) -> &str {
        "udp"
    }

    async fn sniff(&self, data: &[u8]) -> Option<SniffedData> {
        if data.len() >= 12 {
            let flags = u16::from_be_bytes([data[2], data[3]]);
            let qr = (flags >> 15) & 0x01;
            let opcode = (flags >> 11) & 0x0F;
            let qcount = u16::from_be_bytes([data[4], data[5]]);

            if qr == 0 && opcode == 0 && qcount > 0 {
                return Some(SniffedData {
                    protocol: Some("dns".to_string()),
                    domain: None,
                });
            }
        }

        if !data.is_empty() && (data[0] & 0x80 != 0 || data[0] & 0x40 != 0) {
            return Some(SniffedData {
                protocol: Some("quic".to_string()),
                domain: None,
            });
        }

        None
    }
}
