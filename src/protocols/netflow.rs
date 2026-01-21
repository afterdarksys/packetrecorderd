use anyhow::Result;
use netflow_parser::NetflowParser as NfParser;
use super::{ProtocolInfo, ProtocolParser};

pub struct NetflowParser;

impl NetflowParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        // Netflow is typically UDP payload.
        // The netflow_parser crate handles V5, V9, IPFIX.
        
        match NfParser::parse_packet(data) {
            Ok(packet) => {
                // For now, we just identify it as Netflow.
                // In a real implementation, we would extract flow records.
                Ok(ProtocolInfo::Netflow(format!("{:?}", packet)))
            },
            Err(_) => Ok(ProtocolInfo::Unknown),
        }
    }
}
