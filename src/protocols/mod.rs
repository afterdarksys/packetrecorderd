#![allow(dead_code)]
pub mod tls;
pub mod http;
pub mod dns;
pub mod netflow;
pub mod sflow;
pub mod ldap;
pub mod netbios;

#[allow(dead_code)]
use anyhow::Result;
pub trait ProtocolParser {
    fn parse(&self, data: &[u8]) -> Result<ProtocolInfo>;
}

#[derive(Debug)]
pub enum ProtocolInfo {
    Tls(TlsInfo),
    Http(HttpInfo),
    Dns(DnsInfo),
    Ldap(ldap::LdapInfo),
    Netbios(netbios::NetbiosInfo),
    Netflow(String),
    Sflow(String),
    Unknown,
}

#[derive(Debug)]
pub struct TlsInfo {
    pub version: String,
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub ja3_string: Option<String>,
}

#[derive(Debug)]
pub struct HttpInfo {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug)]
pub struct DnsInfo {
    pub query: String,
    pub qtype: String,
}
