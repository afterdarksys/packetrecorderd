use anyhow::Result;
use nom::{
    number::complete::{be_u32},
    IResult,
};
use super::ProtocolInfo;

// Basic sFlow v5 parser implementation since a stable crate is not always available.
// sFlow structure:
// Header: Version (u32), IP Version (u32), IP Address (u32/u128), Sub Agent ID (u32), Sequence Number (u32), Uptime (u32), Number of Samples (u32)
// Samples...

#[derive(Debug)]
pub struct SflowHeader {
    pub version: u32,
    pub ip_version: u32,
    pub sub_agent_id: u32,
    pub sequence_number: u32,
    pub uptime: u32,
    pub num_samples: u32,
}

fn parse_sflow_header(input: &[u8]) -> IResult<&[u8], SflowHeader> {
    let (input, version) = be_u32(input)?;
    let (input, ip_version) = be_u32(input)?;
    
    // Skip IP address based on version (4 bytes for v4, 16 for v6)
    let (input, _) = if ip_version == 1 {
        nom::bytes::complete::take(4usize)(input)?
    } else {
        nom::bytes::complete::take(16usize)(input)?
    };

    let (input, sub_agent_id) = be_u32(input)?;
    let (input, sequence_number) = be_u32(input)?;
    let (input, uptime) = be_u32(input)?;
    let (input, num_samples) = be_u32(input)?;

    Ok((input, SflowHeader {
        version,
        ip_version,
        sub_agent_id,
        sequence_number,
        uptime,
        num_samples,
    }))
}

pub struct SflowParser;

impl SflowParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        // sFlow is typically UDP 6343
        match parse_sflow_header(data) {
            Ok((_, header)) => {
                if header.version == 5 {
                    Ok(ProtocolInfo::Sflow(format!("v5, seq: {}, samples: {}", header.sequence_number, header.num_samples)))
                } else {
                    Ok(ProtocolInfo::Unknown)
                }
            },
            Err(_) => Ok(ProtocolInfo::Unknown),
        }
    }
}
