use anyhow::Result;
use super::ProtocolInfo;
use std::str;

#[derive(Debug, Clone)]
pub struct SmtpInfo {
    pub command: Option<String>,
    pub response_code: Option<u16>,
    pub payload: String,
    pub is_starttls: bool,
}

pub struct SmtpParser;

impl SmtpParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, data: &[u8]) -> Result<ProtocolInfo> {
        // Basic heuristic: SMTP is line-based, ASCII.
        // Check if data looks like SMTP.
        
        if data.is_empty() {
            return Ok(ProtocolInfo::Unknown);
        }

        // Try to interpret as ASCII string
        let s = match str::from_utf8(data) {
            Ok(v) => v,
            Err(_) => return Ok(ProtocolInfo::Unknown),
        };

        let s_upper = s.to_uppercase();
        let trimmed = s.trim();

        // Server Response: 3 digits followed by space or -
        if trimmed.len() >= 3 && trimmed.chars().next().map_or(false, |c| c.is_digit(10)) {
             if let Some(code_str) = trimmed.get(0..3) {
             if let Ok(code) = code_str.parse::<u16>() {
                 // Common SMTP codes: 220 (Service ready), 250 (OK), 354 (Start mail input)
                 if matches!(code, 220 | 221 | 250 | 354 | 421 | 450 | 451 | 452 | 500 | 501 | 502 | 503 | 504 | 550 | 551 | 552 | 553 | 554) {
                     return Ok(ProtocolInfo::Smtp(SmtpInfo {
                         command: None,
                         response_code: Some(code),
                         payload: trimmed.to_string(),
                         is_starttls: false,
                     }));
                 }
             }
             }
        }

        // Client Commands
        let mut command = None;
        let mut is_starttls = false;

        if s_upper.starts_with("EHLO") {
            command = Some("EHLO".to_string());
        } else if s_upper.starts_with("HELO") {
            command = Some("HELO".to_string());
        } else if s_upper.starts_with("MAIL FROM:") {
            command = Some("MAIL FROM".to_string());
        } else if s_upper.starts_with("RCPT TO:") {
            command = Some("RCPT TO".to_string());
        } else if s_upper.starts_with("DATA") {
            command = Some("DATA".to_string());
        } else if s_upper.starts_with("STARTTLS") {
            command = Some("STARTTLS".to_string());
            is_starttls = true;
        } else if s_upper.starts_with("QUIT") {
            command = Some("QUIT".to_string());
        } else if s_upper.starts_with("RSET") {
            command = Some("RSET".to_string());
        } else if s_upper.starts_with("AUTH") {
            command = Some("AUTH".to_string());
        }

        if let Some(cmd) = command {
            return Ok(ProtocolInfo::Smtp(SmtpInfo {
                command: Some(cmd),
                response_code: None,
                payload: trimmed.to_string(),
                is_starttls,
            }));
        }

        Ok(ProtocolInfo::Unknown)
    }
}
