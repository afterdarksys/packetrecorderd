use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelResponse {
    pub found: bool,
    pub indicator: String,
    pub indicator_type: Option<String>,
    pub severity: Option<String>,
    pub categories: Option<Vec<String>>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub confidence: Option<u8>,
    pub tags: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputationResponse {
    pub ip: String,
    pub is_malicious: bool,
    pub reputation_score: Option<i32>,
    pub categories: Option<Vec<String>>,
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
    pub country: Option<String>,
    pub is_tor: bool,
    pub is_proxy: bool,
    pub is_vpn: bool,
    pub is_hosting: bool,
}

pub struct DarkApiClient {
    api_key: String,
    base_url: String,
    client: reqwest::Client,
}

impl DarkApiClient {
    pub fn new(api_key: String, base_url: String) -> Self {
        Self {
            api_key,
            base_url,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }

    /// Look up IP reputation in DarkAPI threat intelligence
    pub async fn lookup_ip(&self, ip: &str) -> Result<IpReputationResponse> {
        let url = format!("{}/v1/intel/ip/{}", self.base_url, ip);
        
        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .header("User-Agent", "packetrecorderd/0.1.0")
            .send()
            .await?;

        if response.status().is_success() {
            let data: IpReputationResponse = response.json().await?;
            Ok(data)
        } else {
            // If not found or error, return empty result
            Ok(IpReputationResponse {
                ip: ip.to_string(),
                is_malicious: false,
                reputation_score: None,
                categories: None,
                asn: None,
                asn_name: None,
                country: None,
                is_tor: false,
                is_proxy: false,
                is_vpn: false,
                is_hosting: false,
            })
        }
    }

    /// Look up domain reputation
    pub async fn lookup_domain(&self, domain: &str) -> Result<ThreatIntelResponse> {
        let url = format!("{}/v1/intel/domain/{}", self.base_url, domain);
        
        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .header("User-Agent", "packetrecorderd/0.1.0")
            .send()
            .await?;

        if response.status().is_success() {
            let data: ThreatIntelResponse = response.json().await?;
            Ok(data)
        } else {
            Ok(ThreatIntelResponse {
                found: false,
                indicator: domain.to_string(),
                indicator_type: Some("domain".to_string()),
                severity: None,
                categories: None,
                first_seen: None,
                last_seen: None,
                confidence: None,
                tags: None,
                sources: None,
            })
        }
    }

    /// Bulk IP lookup for efficiency
    pub async fn lookup_ips_bulk(&self, ips: &[String]) -> Result<HashMap<String, IpReputationResponse>> {
        let url = format!("{}/v1/intel/ip/bulk", self.base_url);
        
        let payload = serde_json::json!({
            "ips": ips
        });

        let response = self.client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .header("User-Agent", "packetrecorderd/0.1.0")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            let data: HashMap<String, IpReputationResponse> = response.json().await?;
            Ok(data)
        } else {
            Ok(HashMap::new())
        }
    }

    /// Check if domain matches known malware/phishing patterns
    pub async fn check_url(&self, url: &str) -> Result<ThreatIntelResponse> {
        let endpoint = format!("{}/v1/intel/url", self.base_url);
        
        let payload = serde_json::json!({
            "url": url
        });

        let response = self.client
            .post(&endpoint)
            .header("X-API-Key", &self.api_key)
            .header("User-Agent", "packetrecorderd/0.1.0")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            let data: ThreatIntelResponse = response.json().await?;
            Ok(data)
        } else {
            Ok(ThreatIntelResponse {
                found: false,
                indicator: url.to_string(),
                indicator_type: Some("url".to_string()),
                severity: None,
                categories: None,
                first_seen: None,
                last_seen: None,
                confidence: None,
                tags: None,
                sources: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_darkapi_client() {
        // This test requires valid API key in environment
        if let Ok(api_key) = std::env::var("DARKAPI_API_KEY") {
            let client = DarkApiClient::new(
                api_key,
                "https://api.darkapi.io".to_string()
            );

            // Test with a known safe IP (Google DNS)
            let result = client.lookup_ip("8.8.8.8").await;
            assert!(result.is_ok());
        }
    }
}
