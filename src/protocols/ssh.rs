use anyhow::Result;
use super::{ProtocolInfo, ProtocolParser};

#[derive(Debug, Clone)]
pub struct SshInfo {
    pub version: String,
    pub software: String,
    pub raw: String,
}

pub struct SshParser;

impl SshParser {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolParser for SshParser {
    fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        // SSH identification string: SSH-protoversion-softwareversion comments CR LF
        // e.g. SSH-2.0-OpenSSH_8.2p1
        
        if data.len() < 4 || &data[0..4] != b"SSH-" {
            return Ok(ProtocolInfo::Unknown);
        }

        // Find end of line
        let end = data.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(data.len());
        let ident_str = String::from_utf8_lossy(&data[0..end]).to_string();
        
        // Parse components
        let parts: Vec<&str> = ident_str.split('-').collect();
        let version = if parts.len() > 1 { parts[1].to_string() } else { "Unknown".to_string() };
        let software = if parts.len() > 2 { parts[2..].join("-") } else { "Unknown".to_string() };

        Ok(ProtocolInfo::Ssh(SshInfo {
            version,
            software,
            raw: ident_str,
        }))
    }
}
