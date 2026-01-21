use anyhow::Result;
use netflow_parser::NetflowParser as NfParser;
use super::ProtocolInfo;

pub struct NetflowParser;

impl NetflowParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        // Netflow is typically UDP payload.
        // The netflow_parser crate handles V5, V9, IPFIX.
        
        let mut parser = NfParser::default();
        match parser.parse_bytes(data).first() {
            Some(packet) => {
                // For now, we just identify it as Netflow.
                // In a real implementation, we would extract flow records.
                Ok(ProtocolInfo::Netflow(format!("{:?}", packet)))
            },
            None => Ok(ProtocolInfo::Unknown),
        }
    }
}
