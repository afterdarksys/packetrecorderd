use anyhow::Result;
use nom::{
    bytes::complete::take,
    number::complete::be_u8,
    IResult,
};

use super::{ProtocolInfo, ProtocolParser};

#[derive(Debug, Clone)]
pub struct SnmpInfo {
    pub version: String,
    pub community: Option<String>,
    pub pdu_type: String,
}

pub struct SnmpParser;

impl SnmpParser {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolParser for SnmpParser {
    fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        if let Ok((_, info)) = parse_snmp_message(data) {
            return Ok(ProtocolInfo::Snmp(info));
        }
        Ok(ProtocolInfo::Unknown)
    }
}

fn parse_snmp_message(input: &[u8]) -> IResult<&[u8], SnmpInfo> {
    let (input, tag) = be_u8(input)?;
    if tag != 0x30 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    let (input, _len) = parse_ber_len(input)?;

    let (input, _int_tag) = be_u8(input)?;
    if _int_tag != 0x02 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    let (input, int_len) = parse_ber_len(input)?;
    let (input, version_bytes) = take(int_len)(input)?;
    let version_num = decode_i64(version_bytes).unwrap_or(-1);

    let version = match version_num {
        0 => "v1",
        1 => "v2c",
        3 => "v3",
        _ => "unknown",
    }
    .to_string();

    let (input, octet_tag) = be_u8(input)?;
    if octet_tag != 0x04 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    let (input, comm_len) = parse_ber_len(input)?;
    let (input, community_bytes) = take(comm_len)(input)?;
    let community = std::str::from_utf8(community_bytes)
        .ok()
        .map(|s| s.to_string());

    let (input, pdu_tag) = be_u8(input)?;
    let pdu_type = match pdu_tag {
        0xA0 => "GetRequest",
        0xA1 => "GetNextRequest",
        0xA2 => "GetResponse",
        0xA3 => "SetRequest",
        0xA4 => "Trap",
        0xA5 => "GetBulkRequest",
        0xA6 => "InformRequest",
        0xA7 => "SNMPv2Trap",
        _ => "UnknownPdu",
    }
    .to_string();

    Ok((
        input,
        SnmpInfo {
            version,
            community,
            pdu_type,
        },
    ))
}

fn parse_ber_len(input: &[u8]) -> IResult<&[u8], usize> {
    let (input, b) = be_u8(input)?;
    if (b & 0x80) == 0 {
        return Ok((input, b as usize));
    }

    let n = (b & 0x7F) as usize;
    if n == 0 || n > 4 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::LengthValue,
        )));
    }

    let (input, bytes) = take(n)(input)?;
    let mut len: usize = 0;
    for &x in bytes {
        len = (len << 8) | (x as usize);
    }

    Ok((input, len))
}

fn decode_i64(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() {
        return None;
    }

    let mut v: i64 = 0;
    for &b in bytes {
        v = (v << 8) | (b as i64);
    }

    if (bytes[0] & 0x80) != 0 {
        let bit_len = (bytes.len() * 8) as u32;
        v -= 1i64 << bit_len;
    }

    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_snmp_v2c_get_request() {
        // SNMPv2c GetRequest with community "public".
        // 30 1a 02 01 01 04 06 70 75 62 6c 69 63 a0 0d 02 01 01 02 01 00 02 01 00 30 00
        let pkt = hex::decode("301a02010104067075626c6963a00d0201010201000201003000").unwrap();

        let parser = SnmpParser::new();
        let info = parser.parse(&pkt).unwrap();

        match info {
            ProtocolInfo::Snmp(s) => {
                assert_eq!(s.version, "v2c");
                assert_eq!(s.community.as_deref(), Some("public"));
                assert_eq!(s.pdu_type, "GetRequest");
            }
            _ => panic!("expected snmp"),
        }
    }
}
