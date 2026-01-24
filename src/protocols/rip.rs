use anyhow::Result;

use super::{ProtocolInfo, ProtocolParser};

#[derive(Debug, Clone)]
pub struct RipInfo {
    pub version: u8,
    pub command: String,
    pub route_count: usize,
}

pub struct RipParser;

impl RipParser {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolParser for RipParser {
    fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        if data.len() < 4 {
            return Ok(ProtocolInfo::Unknown);
        }

        let command = data[0];
        let version = data[1];

        // RIPv2 is version 2. RIPv1 is version 1.
        if version != 2 {
            return Ok(ProtocolInfo::Unknown);
        }

        let command_str = match command {
            1 => "Request",
            2 => "Response",
            _ => "Unknown",
        }
        .to_string();

        // RIP entries are 20 bytes each after the 4-byte header.
        let route_count = (data.len().saturating_sub(4)) / 20;

        Ok(ProtocolInfo::Rip(RipInfo {
            version,
            command: command_str,
            route_count,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ripv2_header_and_counts_routes() {
        // RIP response v2 with 1 route entry (dummy bytes)
        let mut pkt = vec![0u8; 4 + 20];
        pkt[0] = 2; // Response
        pkt[1] = 2; // v2
        pkt[2] = 0;
        pkt[3] = 0;

        let parser = RipParser::new();
        let info = parser.parse(&pkt).unwrap();
        match info {
            ProtocolInfo::Rip(r) => {
                assert_eq!(r.version, 2);
                assert_eq!(r.command, "Response");
                assert_eq!(r.route_count, 1);
            }
            _ => panic!("expected rip"),
        }
    }
}
