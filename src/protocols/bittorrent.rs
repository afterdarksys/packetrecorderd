use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitTorrentInfo {
    pub info_hash: Option<String>,
    pub peer_id: Option<String>,
    pub message_type: String, // "Handshake", "DHT", "uTP", "Unknown"
}

pub struct BitTorrentParser;

impl BitTorrentParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, data: &[u8]) -> Option<BitTorrentInfo> {
        if data.len() < 20 {
            return None;
        }

        // Check for BitTorrent Protocol Handshake
        // \x13BitTorrent protocol
        if data.len() >= 68 && data[0] == 0x13 && &data[1..20] == b"BitTorrent protocol" {
            // Bytes 28-48: Info Hash
            let info_hash = hex::encode(&data[28..48]);
            // Bytes 48-68: Peer ID
            let peer_id = String::from_utf8_lossy(&data[48..68]).to_string();

            return Some(BitTorrentInfo {
                info_hash: Some(info_hash),
                peer_id: Some(peer_id),
                message_type: "Handshake".to_string(),
            });
        }

        // Check for uTP (Micro Transport Protocol)
        // uTP packets usually start with 0x41 (DATA) or 0x01 (ST_DATA) etc over UDP
        // But detecting generic UDP based uTP is harder without flow context.
        // We will look for simple signatures if possible. 
        // A common uTP header is relatively generic, skipping for now to avoid false positives 
        // unless we have stricter constraints.
        
        // Check for DHT (Distributed Hash Table) messages
        // Bencoded dictionaries: d1:ad2:id20:...
        if data.starts_with(b"d1:ad2:id20:") || data.starts_with(b"d1:rd2:id20:") {
             return Some(BitTorrentInfo {
                info_hash: None,
                peer_id: None,
                message_type: "DHT".to_string(),
            });
        }
        
        // Check for common 'krpc' DHT queries
        // d1:q...
        if data.starts_with(b"d1:q") && data.windows(2).any(|w| w == b"id") {
             return Some(BitTorrentInfo {
                info_hash: None,
                peer_id: None,
                message_type: "DHT Query".to_string(),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bittorrent_handshake() {
        let mut data = Vec::new();
        data.push(0x13);
        data.extend_from_slice(b"BitTorrent protocol");
        data.extend_from_slice(&[0u8; 8]); // Extensions
        data.extend_from_slice(&[0xAA; 20]); // Info Hash
        data.extend_from_slice(b"-TR2940-123456789012"); // Peer ID
        
        let parser = BitTorrentParser::new();
        let info = parser.parse(&data).unwrap();
        assert_eq!(info.message_type, "Handshake");
        assert_eq!(info.info_hash, Some(hex::encode(&[0xAA; 20])));
        assert_eq!(info.peer_id, Some("-TR2940-123456789012".to_string()));
    }

    #[test]
    fn test_dht_message() {
        let data = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
        let parser = BitTorrentParser::new();
        let info = parser.parse(data).unwrap();
        assert_eq!(info.message_type, "DHT");
    }
}
