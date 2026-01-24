use anyhow::Result;
use nom::{
    number::complete::{be_u16, be_u8},
    IResult,
};
use super::{ProtocolInfo, ProtocolParser};

#[derive(Debug, Clone)]
pub enum NetbiosType {
    NameService,
    SessionService,
    DatagramService,
}

fn parse_nbdgm(input: &[u8]) -> IResult<&[u8], NetbiosInfo> {
    if input.len() < 10 {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Eof)));
    }

    let (input, msg_type) = be_u8(input)?;
    let (input, _flags) = be_u8(input)?;
    let (input, dgm_id) = be_u16(input)?;

    let (input, src_ip_b0) = be_u8(input)?;
    let (input, src_ip_b1) = be_u8(input)?;
    let (input, src_ip_b2) = be_u8(input)?;
    let (input, src_ip_b3) = be_u8(input)?;

    let (input, src_port) = be_u16(input)?;

    let src_ip = std::net::Ipv4Addr::new(src_ip_b0, src_ip_b1, src_ip_b2, src_ip_b3).to_string();

    let type_str = match msg_type {
        0x10 => "Direct Unique Datagram",
        0x11 => "Direct Group Datagram",
        0x12 => "Broadcast Datagram",
        0x13 => "Datagram Error",
        0x14 => "Datagram Query Request",
        0x15 => "Datagram Positive Query Response",
        0x16 => "Datagram Negative Query Response",
        _ => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag))),
    };

    Ok((input, NetbiosInfo {
        service_type: NetbiosType::DatagramService,
        info: format!("{}: ID={:04x}, Src={}:{}", type_str, dgm_id, src_ip, src_port),
    }))
}

#[derive(Debug, Clone)]
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

        if let Ok((_, info)) = parse_nbdgm(data) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nbdgm_header() {
        // NBDGM minimal header (11 bytes). Message type 0x12 (Broadcast Datagram).
        // msg_type, flags, dgm_id, src_ip(4), src_port
        let data = [
            0x12, 0x00, 0x12, 0x34, 10, 0, 0, 5, 0x00, 0x8a,
        ];

        let parser = NetbiosParser::new();
        let info = parser.parse(&data).unwrap();
        match info {
            ProtocolInfo::Netbios(n) => match n.service_type {
                NetbiosType::DatagramService => {}
                _ => panic!("expected datagram service"),
            },
            _ => panic!("expected netbios"),
        }
    }
}
