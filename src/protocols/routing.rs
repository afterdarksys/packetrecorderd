#![allow(dead_code)]
use anyhow::Result;
use super::ProtocolInfo;

#[derive(Debug, Clone)]
pub struct BgpInfo {
    pub type_: String,
    pub length: u16,
    pub as_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OspfInfo {
    pub version: u8,
    pub type_: String,
    pub router_id: String,
    pub area_id: String,
}

#[derive(Debug, Clone)]
pub struct EigrpInfo {
    pub version: u8,
    pub opcode: String,
    pub autonomous_system: u32,
}

pub struct RoutingParser;

impl RoutingParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_bgp(&self, data: &[u8]) -> Result<ProtocolInfo> {
        // Marker (16 bytes) + Length (2 bytes) + Type (1 byte)
        if data.len() < 19 {
            return Ok(ProtocolInfo::Unknown);
        }
        
        // Basic check for BGP marker (all 1s)
        let is_marker_valid = data[0..16].iter().all(|&b| b == 0xFF);
        if !is_marker_valid {
            return Ok(ProtocolInfo::Unknown);
        }

        let length = u16::from_be_bytes([data[16], data[17]]);
        let type_code = data[18];
        
        let type_str = match type_code {
            1 => "OPEN",
            2 => "UPDATE",
            3 => "NOTIFICATION",
            4 => "KEEPALIVE",
            _ => "UNKNOWN",
        };

        Ok(ProtocolInfo::Bgp(BgpInfo {
            type_: type_str.to_string(),
            length,
            as_path: None, // Parsing AS path from UPDATE is complex, leaving for now
        }))
    }

    pub fn parse_ospf(&self, data: &[u8]) -> Result<ProtocolInfo> {
        // OSPF Header: Version (1), Type (1), Packet Length (2), Router ID (4), Area ID (4), Checksum (2), AuType (2), Authentication (8)
        if data.len() < 24 {
            return Ok(ProtocolInfo::Unknown);
        }

        let version = data[0];
        if version != 2 && version != 3 {
             return Ok(ProtocolInfo::Unknown);
        }

        let type_code = data[1];
        let type_str = match type_code {
            1 => "Hello",
            2 => "Database Description",
            3 => "Link State Request",
            4 => "Link State Update",
            5 => "Link State Acknowledgment",
            _ => "Unknown",
        };

        let router_id = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]).to_string();
        let area_id = std::net::Ipv4Addr::new(data[8], data[9], data[10], data[11]).to_string();

        Ok(ProtocolInfo::Ospf(OspfInfo {
            version,
            type_: type_str.to_string(),
            router_id,
            area_id,
        }))
    }

    pub fn parse_eigrp(&self, data: &[u8]) -> Result<ProtocolInfo> {
        // EIGRP Header: Version (1), Opcode (1), Checksum (2), Flags (4), Sequence (4), Ack (4), AS (4)
        if data.len() < 20 {
            return Ok(ProtocolInfo::Unknown);
        }

        let version = data[0];
        if version != 2 {
            // EIGRP v2 is standard
            // return Ok(ProtocolInfo::Unknown); 
            // Actually check opcode ranges
        }

        let opcode = data[1];
        let opcode_str = match opcode {
            1 => "Update",
            3 => "Query",
            4 => "Reply",
            5 => "Hello",
            6 => "IPX SAP",
            10 => "SIA Query",
            11 => "SIA Reply",
            _ => "Unknown",
        };

        let autonomous_system = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

        Ok(ProtocolInfo::Eigrp(EigrpInfo {
            version,
            opcode: opcode_str.to_string(),
            autonomous_system,
        }))
    }
}
