use anyhow::Result;
use nom::{
    bytes::complete::take,
    number::complete::be_u8,
    IResult,
};
use super::{ProtocolInfo, ProtocolParser};

#[derive(Debug, Clone)]
pub struct LdapInfo {
    pub message_id: u32,
    pub operation: String,
}

pub struct LdapParser;

impl LdapParser {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolParser for LdapParser {
    fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        match parse_ldap_packet(data) {
            Ok((_, info)) => Ok(ProtocolInfo::Ldap(info)),
            Err(_) => Ok(ProtocolInfo::Unknown),
        }
    }
}

// Basic BER parsing for LDAP
fn parse_ldap_packet(input: &[u8]) -> IResult<&[u8], LdapInfo> {
    // LDAP Message is a BER Sequence (0x30)
    let (input, tag) = be_u8(input)?;
    if tag != 0x30 {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)));
    }

    // Length (simplified for short form)
    let (input, len_byte) = be_u8(input)?;
    let (input, _len) = if len_byte & 0x80 != 0 {
        let len_bytes = (len_byte & 0x7f) as usize;
        let (i, _l) = take(len_bytes)(input)?;
        (i, 0) // Ignoring length for this quick check
    } else {
        (input, len_byte as usize)
    };

    // Message ID (Integer 0x02)
    let (input, msg_id_tag) = be_u8(input)?;
    if msg_id_tag != 0x02 {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)));
    }
    let (input, msg_id_len) = be_u8(input)?;
    let (input, msg_id_bytes) = take(msg_id_len)(input)?;
    
    // Parse message ID (simplification, assuming <= 4 bytes)
    let mut msg_id = 0u32;
    for &b in msg_id_bytes {
        msg_id = (msg_id << 8) | b as u32;
    }

    // Protocol Op
    let (input, op_tag) = be_u8(input)?;
    
    // Application tags for LDAP operations (RFC 4511)
    let operation = match op_tag {
        0x60 => "BindRequest",
        0x61 => "BindResponse",
        0x42 => "UnbindRequest",
        0x63 => "SearchRequest",
        0x64 => "SearchResultEntry",
        0x65 => "SearchResultDone",
        0x66 => "ModifyRequest",
        0x67 => "ModifyResponse",
        0x68 => "AddRequest",
        0x69 => "AddResponse",
        0x4A => "DelRequest",
        0x6B => "DelResponse",
        0x6C => "ModDNRequest",
        0x6D => "ModDNResponse",
        0x6E => "CompareRequest",
        0x6F => "CompareResponse",
        0x50 => "AbandonRequest",
        0x73 => "ExtendedRequest",
        0x74 => "ExtendedResponse",
        _ => "Unknown",
    }.to_string();

    Ok((input, LdapInfo {
        message_id: msg_id,
        operation,
    }))
}
