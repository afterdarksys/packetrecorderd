#![allow(dead_code)]
pub mod tls;
pub mod http;
pub mod dns;
pub mod netflow;
pub mod sflow;
pub mod ldap;
pub mod netbios;
pub mod snmp;
pub mod ntp;
pub mod rip;
pub mod routing;
pub mod smtp;
pub mod ssh;

#[allow(dead_code)]
use anyhow::Result;
pub trait ProtocolParser {
    fn parse(&self, data: &[u8]) -> Result<ProtocolInfo>;
}

#[derive(Debug, Clone)]
pub enum ProtocolInfo {
    Tls(TlsInfo),
    Http(HttpInfo),
    Dns(DnsInfo),
    Ldap(ldap::LdapInfo),
    Netbios(netbios::NetbiosInfo),
    Snmp(snmp::SnmpInfo),
    Ntp(ntp::NtpInfo),
    Rip(rip::RipInfo),
    Icmp(IcmpInfo),
    Bgp(routing::BgpInfo),
    Ospf(routing::OspfInfo),
    Eigrp(routing::EigrpInfo),
    Smtp(smtp::SmtpInfo),
    Ssh(ssh::SshInfo),
    Netflow(String),
    Sflow(String),
    Unknown,
}

#[derive(Debug, Clone)]
pub struct IcmpInfo {
    pub type_: u8,
    pub code: u8,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub version: String,
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub ja3_string: Option<String>,
    pub server_certificates: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct HttpInfo {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub query: String,
    pub qtype: String,
}
