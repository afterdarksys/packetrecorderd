use anyhow::Result;
use nom::{
    number::complete::{be_u16, be_u8},
    IResult,
};
use super::{ProtocolInfo, ProtocolParser};

#[derive(Debug)]
pub enum NetbiosType {
    NameService,
    SessionService,
    DatagramService,
}

#[derive(Debug)]
pub struct NetbiosInfo {
    pub service_type: NetbiosType,
    pub info: String,
}

pub struct NetbiosParser;

impl NetbiosParser {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolParser for NetbiosParser {
    fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        // Heuristic detection
        // NBSS (TCP 139) typically starts with 0x00, 0x81, 0x82, 0x83, 0x85
        // NBNS (UDP 137) typically starts with Transaction ID (any 2 bytes) then Flags.
        // Flags high bit is R/R (Response/Request). Opcode is bits 11-14.
        
        // Try NBSS first (simple header)
        if let Ok((_, info)) = parse_nbss(data) {
            return Ok(ProtocolInfo::Netbios(info));
        }

        // Try NBNS (similar to DNS)
        if let Ok((_, info)) = parse_nbns(data) {
            return Ok(ProtocolInfo::Netbios(info));
        }

        Ok(ProtocolInfo::Unknown)
    }
}

fn parse_nbss(input: &[u8]) -> IResult<&[u8], NetbiosInfo> {
    let (input, msg_type) = be_u8(input)?;
    let (input, _flags) = be_u8(input)?;
    let (input, length) = be_u16(input)?;

    // NBSS types
    // 0x00: Session Message
    // 0x81: Session Request
    // 0x82: Positive Session Response
    // 0x83: Negative Session Response
    // 0x85: Keep Alive
    
    let type_str = match msg_type {
        0x00 => "Session Message",
        0x81 => "Session Request",
        0x82 => "Positive Session Response",
        0x83 => "Negative Session Response",
        0x85 => "Keep Alive",
        _ => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag))),
    };

    Ok((input, NetbiosInfo {
        service_type: NetbiosType::SessionService,
        info: format!("{}: Len={}", type_str, length),
    }))
}

fn parse_nbns(input: &[u8]) -> IResult<&[u8], NetbiosInfo> {
    // NBNS Header is 12 bytes
    if input.len() < 12 {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Eof)));
    }
    
    let (input, trans_id) = be_u16(input)?;
    let (input, flags) = be_u16(input)?;
    let (input, q_count) = be_u16(input)?;
    let (input, a_count) = be_u16(input)?;
    
    // Basic validation of flags to ensure it looks like NBNS/WINS
    // Opcode is bits 11-14 (0x7800 mask)
    // 0 = Query, 5 = Registration, 6 = Release, 7 = WACK, 8 = Refresh
    let opcode = (flags & 0x7800) >> 11;
    let is_response = (flags & 0x8000) != 0;
    
    let op_str = match opcode {
        0 => "Query",
        5 => "Registration",
        6 => "Release",
        7 => "WACK",
        8 => "Refresh",
        _ => "Unknown", // Might not be NBNS if opcode is weird, but we accept it for now
    };

    Ok((input, NetbiosInfo {
        service_type: NetbiosType::NameService, // Covers WINS
        info: format!("TransID={:04x}, Op={}, Resp={}, Q={}, A={}", trans_id, op_str, is_response, q_count, a_count),
    }))
}
