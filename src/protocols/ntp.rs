use anyhow::Result;

use super::{ProtocolInfo, ProtocolParser};

#[derive(Debug, Clone)]
pub struct NtpInfo {
    pub version: u8,
    pub mode: String,
    pub stratum: u8,
}

pub struct NtpParser;

impl NtpParser {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolParser for NtpParser {
    fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        if data.len() < 48 {
            return Ok(ProtocolInfo::Unknown);
        }

        let b0 = data[0];
        let version = (b0 >> 3) & 0x07;
        let mode = b0 & 0x07;
        let stratum = data[1];

        if version == 0 {
            return Ok(ProtocolInfo::Unknown);
        }

        let mode_str = match mode {
            0 => "Reserved",
            1 => "Symmetric Active",
            2 => "Symmetric Passive",
            3 => "Client",
            4 => "Server",
            5 => "Broadcast",
            6 => "NTP Control",
            7 => "Private",
            _ => "Unknown",
        }
        .to_string();

        Ok(ProtocolInfo::Ntp(NtpInfo {
            version,
            mode: mode_str,
            stratum,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_ntp_header() {
        // Minimal NTP packet (48 bytes). LI=0, VN=4, Mode=3 (client)
        let mut pkt = vec![0u8; 48];
        pkt[0] = (0 << 6) | (4 << 3) | 3;
        pkt[1] = 0; // stratum for client request often 0

        let parser = NtpParser::new();
        let info = parser.parse(&pkt).unwrap();
        match info {
            ProtocolInfo::Ntp(n) => {
                assert_eq!(n.version, 4);
                assert_eq!(n.mode, "Client");
                assert_eq!(n.stratum, 0);
            }
            _ => panic!("expected ntp"),
        }
    }
}
