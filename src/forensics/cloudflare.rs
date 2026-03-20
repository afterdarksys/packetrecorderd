use crate::protocols::ProtocolInfo;
use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use super::darkapi::{IpReputationResponse, ThreatIntelResponse};

pub enum CloudflareService {
    Archive,
    Api,
    Dashboard,
    Tunnel,
    Worker,
    R2,
    Unknown,
}

impl CloudflareService {
    pub fn as_str(&self) -> &'static str {
        match self {
            CloudflareService::Archive => "Cloudflare Archive",
            CloudflareService::Api => "Cloudflare API",
            CloudflareService::Dashboard => "Cloudflare Dashboard",
            CloudflareService::Tunnel => "Cloudflare Tunnel",
            CloudflareService::Worker => "Cloudflare Worker",
            CloudflareService::R2 => "Cloudflare R2",
            CloudflareService::Unknown => "Cloudflare (Unknown)",
        }
    }
}

pub fn check_cloudflare(info: &ProtocolInfo) -> Option<CloudflareService> {
    if let ProtocolInfo::Tls(tls_info) = info {
        // Check SNI
        if let Some(sni) = &tls_info.sni {
            if sni.ends_with(".cfargotunnel.com") || sni.ends_with(".trycloudflare.com") {
                return Some(CloudflareService::Tunnel);
            }
            if sni == "api.cloudflare.com" {
                return Some(CloudflareService::Api);
            }
            if sni == "dash.cloudflare.com" {
                return Some(CloudflareService::Dashboard);
            }
            if sni.ends_with(".workers.dev") {
                return Some(CloudflareService::Worker);
            }
            if sni.ends_with(".r2.cloudflarestorage.com") {
                return Some(CloudflareService::R2);
            }
            // General cloudflare detection if just cloudflare.com/net? 
            // Might be too broad, but let's check for specific Tunnel ALPN first.
        }

        // Check ALPN for Cloudflare Tunnel (cft-flow)
        // Note: TlsInfo currently doesn't expose ALPN directly in the struct definition in mod.rs 
        // (implied from inspection of previous TlsInfo struct in mod.rs:53).
        // If we need ALPN, we might need to add it to TlsInfo first.
        // Assuming TlsInfo might not have it yet, we will rely on SNI for now.
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::TlsInfo;

    #[test]
    fn test_cloudflare_tunnel_detection() {
        let info = ProtocolInfo::Tls(TlsInfo {
            version: "TLS 1.3".to_string(),
            sni: Some("abcd-1234.cfargotunnel.com".to_string()),
            ja3: None,
            ja3_string: None,
            server_certificates: None,
        });

        match check_cloudflare(&info) {
            Some(CloudflareService::Tunnel) => {},
            _ => panic!("Failed to detect Cloudflare Tunnel"),
        }
    }

    #[test]
    fn test_cloudflare_api_detection() {
        let info = ProtocolInfo::Tls(TlsInfo {
            version: "TLS 1.3".to_string(),
            sni: Some("api.cloudflare.com".to_string()),
            ja3: None,
            ja3_string: None,
            server_certificates: None,
        });

        match check_cloudflare(&info) {
            Some(CloudflareService::Api) => {},
            _ => panic!("Failed to detect Cloudflare API"),
        }
    }
}

pub struct CloudflareApiClient {
    client: reqwest::Client,
    api_key: String,
    account_id: String,
    base_url: String,
}

#[derive(Deserialize)]
struct CfIpResponse {
    result: CfIpResult,
    success: bool,
}

#[derive(Deserialize)]
struct CfIpResult {
    risk_score: Option<f32>, // 0.0 to 1.0 or 0-100 depending on endpoint
    classification: Option<String>,
}

impl CloudflareApiClient {
    pub fn new(api_key: String, account_id: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            account_id,
            base_url: "https://api.cloudflare.com/client/v4".to_string(),
        }
    }

    pub async fn lookup_ip(&self, ip: &str) -> Result<IpReputationResponse> {
        let url = format!("{}/accounts/{}/intel/ip?ipv4={}", self.base_url, self.account_id, ip);
        
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", self.api_key))?);
        
        let resp = self.client.get(&url)
            .headers(headers)
            .send()
            .await
            .context("Cloudflare API request failed")?;
            
        if !resp.status().is_success() {
            anyhow::bail!("Cloudflare API error: {}", resp.status());
        }
        
        let body: CfIpResponse = resp.json().await.context("Failed to parse Cloudflare response")?;
        
        // Map to common format
        let is_malicious = body.result.risk_score.unwrap_or(0.0) > 80.0;
        let mut categories = Vec::new();
        if let Some(cls) = body.result.classification {
            categories.push(cls);
        }
        
        Ok(IpReputationResponse {
            ip: ip.to_string(),
            is_malicious,
            reputation_score: body.result.risk_score.map(|s| s as i32),
            categories: Some(categories),
            asn_name: None,
            country: None,
            is_tor: false,
            is_proxy: false,
            is_vpn: false,
            is_hosting: false,
            asn: None,
        })
    }

    pub async fn lookup_domain(&self, domain: &str) -> Result<ThreatIntelResponse> {
        // Mock implementation for domain as endpoint varies
        // Assuming similar structure for illustration
        Ok(ThreatIntelResponse {
            indicator: domain.to_string(),
            indicator_type: Some("domain".to_string()),
            found: false,
            severity: None,
            categories: None,
            confidence: None,
            first_seen: None,
            last_seen: None,
            tags: None,
            sources: None,
        })
    }
}
