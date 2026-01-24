use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficClassification {
    pub ip: String,
    pub classification: String,
    pub network_type: String,
    pub provider: Option<String>,
    pub country: Option<String>,
    pub is_datacenter: bool,
    pub is_residential: bool,
    pub is_mobile: bool,
    pub is_vpn: bool,
    pub is_cdn: bool,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsIntelligence {
    pub domain: String,
    pub is_suspicious: bool,
    pub dga_score: Option<f64>,
    pub entropy: Option<f64>,
    pub threat_categories: Option<Vec<String>>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

pub struct DnsScienceClient {
    api_key: String,
    base_url: String,
    client: reqwest::Client,
}

impl DnsScienceClient {
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

    /// Classify IP using DNSScience traffic intelligence
    pub async fn classify_ip(&self, ip: &str) -> Result<TrafficClassification> {
        let url = format!("{}/api/traffic-intelligence/classify", self.base_url);
        
        let payload = serde_json::json!({
            "ip": ip
        });

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("User-Agent", "packetrecorderd/0.1.0")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            let data: TrafficClassification = response.json().await?;
            Ok(data)
        } else {
            // Fallback to unknown classification
            Ok(TrafficClassification {
                ip: ip.to_string(),
                classification: "unknown".to_string(),
                network_type: "unknown".to_string(),
                provider: None,
                country: None,
                is_datacenter: false,
                is_residential: false,
                is_mobile: false,
                is_vpn: false,
                is_cdn: false,
                confidence: 0,
            })
        }
    }

    /// Get DNS intelligence for domain
    pub async fn analyze_domain(&self, domain: &str) -> Result<DnsIntelligence> {
        let url = format!("{}/api/dns-intelligence/analyze", self.base_url);
        
        let payload = serde_json::json!({
            "domain": domain
        });

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("User-Agent", "packetrecorderd/0.1.0")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            let data: DnsIntelligence = response.json().await?;
            Ok(data)
        } else {
            Ok(DnsIntelligence {
                domain: domain.to_string(),
                is_suspicious: false,
                dga_score: None,
                entropy: None,
                threat_categories: None,
                first_seen: None,
                last_seen: None,
            })
        }
    }

    /// Bulk IP classification
    pub async fn classify_ips_bulk(&self, ips: &[String]) -> Result<Vec<TrafficClassification>> {
        let url = format!("{}/api/traffic-intelligence/classify/bulk", self.base_url);
        
        let payload = serde_json::json!({
            "ips": ips
        });

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("User-Agent", "packetrecorderd/0.1.0")
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            let data: Vec<TrafficClassification> = response.json().await?;
            Ok(data)
        } else {
            Ok(Vec::new())
        }
    }

    /// Check if domain uses suspicious DNS patterns
    pub async fn check_dns_patterns(&self, domain: &str) -> Result<DnsIntelligence> {
        // This would call DNSScience's DNS pattern analysis API
        // For now, use analyze_domain as it includes pattern detection
        self.analyze_domain(domain).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dnsscience_client() {
        // This test requires valid API key in environment
        if let Ok(api_key) = std::env::var("DNSSCIENCE_API_KEY") {
            let client = DnsScienceClient::new(
                api_key,
                "https://dnsscience.io".to_string()
            );

            // Test with a known IP
            let result = client.classify_ip("8.8.8.8").await;
            assert!(result.is_ok());
        }
    }
}
