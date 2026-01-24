use crate::protocols::HttpInfo;

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkType {
    Residential,
    Datacenter,
    Hosting,
    Cdn,
    Education,
    Mobile,
    Vpn,
    Proxy,
    Tor,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct IpReputation {
    pub ip: String,
    pub network_type: NetworkType,
    pub is_bot: bool,
    pub bot_type: Option<String>,
    pub confidence: u8,
    pub details: Option<String>,
}

/// Detect bots based on User-Agent fingerprinting
pub fn detect_bot_from_user_agent(http_info: &HttpInfo) -> Option<(bool, String)> {
    if let Some(user_agent) = &http_info.user_agent {
        const BOT_SIGNATURES: &[(&str, &str)] = &[
            ("python-requests", "Python Requests Library"),
            ("curl/", "cURL Command Line Tool"),
            ("wget/", "Wget Tool"),
            ("Go-http-client", "Go HTTP Client"),
            ("Java/", "Java HTTP Client"),
            ("libwww-perl", "Perl LWP Library"),
            ("Scrapy/", "Scrapy Web Scraper"),
            ("axios/", "Axios HTTP Client"),
            ("node-fetch", "Node.js Fetch"),
            ("okhttp", "OkHttp Client"),
            ("Apache-HttpClient", "Apache HTTP Client"),
            ("HTTPie/", "HTTPie CLI"),
            ("Postman", "Postman API Client"),
            ("Insomnia", "Insomnia API Client"),
            ("k6/", "K6 Load Testing"),
            ("JMeter", "Apache JMeter"),
            ("Siege/", "Siege HTTP Benchmarking"),
            ("wrk/", "Wrk HTTP Benchmarking"),
            ("bot", "Generic Bot (in UA)"),
            ("crawler", "Generic Crawler"),
            ("spider", "Generic Spider"),
            ("slurp", "Yahoo Slurp"),
            ("bingbot", "Bing Bot"),
            ("googlebot", "Google Bot"),
            ("duckduckbot", "DuckDuckGo Bot"),
            ("baiduspider", "Baidu Spider"),
            ("yandexbot", "Yandex Bot"),
            ("facebookexternalhit", "Facebook Bot"),
            ("twitterbot", "Twitter Bot"),
            ("linkedinbot", "LinkedIn Bot"),
            ("whatsapp", "WhatsApp Link Preview"),
            ("telegrambot", "Telegram Bot"),
            ("discordbot", "Discord Bot"),
            ("slackbot", "Slack Bot"),
            ("ahrefsbot", "Ahrefs SEO Bot"),
            ("semrushbot", "SEMRush Bot"),
            ("mj12bot", "Majestic Bot"),
            ("dotbot", "DotBot"),
            ("blexbot", "BLEXBot"),
            ("petalbot", "PetalBot"),
        ];
        
        let ua_lower = user_agent.to_lowercase();
        for (signature, bot_name) in BOT_SIGNATURES {
            if ua_lower.contains(&signature.to_lowercase()) {
                return Some((true, bot_name.to_string()));
            }
        }
        
        // Check for headless browsers
        if ua_lower.contains("headless") || ua_lower.contains("puppeteer") || ua_lower.contains("phantomjs") {
            return Some((true, "Headless Browser".to_string()));
        }
    }
    
    None
}

/// Detect datacenter/hosting IPs based on ASN patterns (basic heuristics)
pub fn classify_ip_type(ip: &str) -> NetworkType {
    // This is a simplified version. In production, you would:
    // 1. Use MaxMind GeoIP database
    // 2. Query DarkAPI/DNSScience for classification
    // 3. Maintain ASN-to-type mappings
    
    // Common datacenter IP ranges (very basic heuristics)
    if is_common_hosting_range(ip) {
        return NetworkType::Hosting;
    }
    
    if is_common_cdn_range(ip) {
        return NetworkType::Cdn;
    }
    
    // Default to unknown - API lookup required for accurate classification
    NetworkType::Unknown
}

/// Check if IP is in common hosting provider ranges
fn is_common_hosting_range(ip: &str) -> bool {
    // AWS
    if ip.starts_with("3.") || ip.starts_with("13.") || ip.starts_with("15.") ||
       ip.starts_with("18.") || ip.starts_with("52.") || ip.starts_with("54.") {
        return true;
    }
    
    // Google Cloud
    if ip.starts_with("34.") || ip.starts_with("35.") {
        return true;
    }
    
    // Azure
    if ip.starts_with("13.") || ip.starts_with("20.") || ip.starts_with("40.") ||
       ip.starts_with("51.") || ip.starts_with("52.") || ip.starts_with("104.") {
        return true;
    }
    
    // DigitalOcean
    if ip.starts_with("104.131.") || ip.starts_with("138.68.") || 
       ip.starts_with("159.65.") || ip.starts_with("167.71.") ||
       ip.starts_with("167.172.") || ip.starts_with("167.99.") {
        return true;
    }
    
    // Vultr
    if ip.starts_with("45.32.") || ip.starts_with("45.76.") ||
       ip.starts_with("45.77.") || ip.starts_with("108.61.") ||
       ip.starts_with("149.28.") || ip.starts_with("207.148.") {
        return true;
    }
    
    // Linode
    if ip.starts_with("45.33.") || ip.starts_with("45.56.") ||
       ip.starts_with("45.79.") || ip.starts_with("50.116.") ||
       ip.starts_with("96.126.") || ip.starts_with("139.144.") ||
       ip.starts_with("172.104.") {
        return true;
    }
    
    false
}

/// Check if IP is in common CDN ranges
fn is_common_cdn_range(ip: &str) -> bool {
    // Cloudflare
    if ip.starts_with("104.16.") || ip.starts_with("104.17.") ||
       ip.starts_with("104.18.") || ip.starts_with("104.19.") ||
       ip.starts_with("104.20.") || ip.starts_with("104.21.") ||
       ip.starts_with("104.22.") || ip.starts_with("104.23.") ||
       ip.starts_with("104.24.") || ip.starts_with("104.25.") ||
       ip.starts_with("172.64.") || ip.starts_with("172.65.") ||
       ip.starts_with("172.66.") || ip.starts_with("172.67.") {
        return true;
    }
    
    // Fastly
    if ip.starts_with("151.101.") || ip.starts_with("146.75.") {
        return true;
    }
    
    false
}

/// Analyze HTTP traffic patterns for bot behavior
pub fn analyze_bot_behavior(requests_per_second: f64, distinct_paths: usize, total_requests: usize) -> Option<String> {
    // High request rate
    if requests_per_second > 10.0 {
        return Some(format!("High request rate: {:.1} req/s", requests_per_second));
    }
    
    // Low path diversity (bots often hit same endpoints repeatedly)
    if total_requests > 100 && distinct_paths < 5 {
        return Some(format!("Low path diversity: {} paths in {} requests", distinct_paths, total_requests));
    }
    
    // Perfect regularity (bots often have precise timing)
    // This would require more sophisticated timing analysis
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bot_detection() {
        let http_info = HttpInfo {
            method: "GET".to_string(),
            host: Some("example.com".to_string()),
            uri: Some("/".to_string()),
            user_agent: Some("python-requests/2.28.0".to_string()),
        };
        
        let result = detect_bot_from_user_agent(&http_info);
        assert!(result.is_some());
        assert!(result.unwrap().0); // is_bot = true
    }
    
    #[test]
    fn test_hosting_detection() {
        // AWS IP
        assert_eq!(classify_ip_type("3.123.45.67"), NetworkType::Hosting);
        
        // DigitalOcean IP
        assert_eq!(classify_ip_type("167.71.123.45"), NetworkType::Hosting);
        
        // Cloudflare CDN
        assert_eq!(classify_ip_type("104.16.123.45"), NetworkType::Cdn);
    }
}
