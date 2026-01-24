use anyhow::Result;
use super::{ProtocolInfo, DnsInfo};
use dns_parser::Packet;

pub struct DnsParser;

impl DnsParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        match Packet::parse(data) {
            Ok(packet) => {
                // We'll take the first question as the main info
                if let Some(question) = packet.questions.first() {
                    return Ok(ProtocolInfo::Dns(DnsInfo {
                        query: question.qname.to_string(),
                        qtype: format!("{:?}", question.qtype),
                    }));
                }
                Ok(ProtocolInfo::Unknown)
            },
            Err(_) => Ok(ProtocolInfo::Unknown),
        }
    }
}
