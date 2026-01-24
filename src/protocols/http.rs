use anyhow::Result;
use super::{ProtocolInfo, HttpInfo};

pub struct HttpParser;

impl HttpParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);

        if let Ok(httparse::Status::Complete(_)) = req.parse(data) {
             let mut host = None;
             let mut user_agent = None;

             for header in req.headers {
                 if header.name.eq_ignore_ascii_case("Host") {
                     host = Some(String::from_utf8_lossy(header.value).to_string());
                 } else if header.name.eq_ignore_ascii_case("User-Agent") {
                     user_agent = Some(String::from_utf8_lossy(header.value).to_string());
                 }
             }

             return Ok(ProtocolInfo::Http(HttpInfo {
                 method: req.method.unwrap_or("UNKNOWN").to_string(),
                 path: req.path.unwrap_or("/").to_string(),
                 host,
                 user_agent,
             }));
        }

        Ok(ProtocolInfo::Unknown)
    }
}
