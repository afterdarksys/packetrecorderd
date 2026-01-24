use crate::protocols::DnsInfo;
use std::collections::HashMap;

/// Detect DNS tunneling based on query characteristics
pub fn detect_dns_tunneling(dns_info: &DnsInfo) -> Option<String> {
    let query = &dns_info.query;
    
    // Check query length (DNS tunneling often uses long subdomains)
    if query.len() > 60 {
        return Some(format!("Long DNS query ({}B): possible tunneling", query.len()));
    }
    
    // Check for high entropy (random-looking subdomains)
    let entropy = calculate_shannon_entropy(query);
    if entropy > 3.5 {
        return Some(format!("High entropy DNS query ({:.2}): possible tunneling or DGA", entropy));
    }
    
    // Check for excessive subdomain depth
    let subdomain_count = query.matches('.').count();
    if subdomain_count > 5 {
        return Some(format!("Excessive subdomains ({}): possible tunneling", subdomain_count));
    }
    
    // Check for TXT queries (often used for data exfiltration)
    if dns_info.qtype == "TXT" && query.len() > 40 {
        return Some("TXT query with long domain: possible data exfiltration".to_string());
    }
    
    // Check for NULL queries (unusual, potentially malicious)
    if dns_info.qtype == "NULL" {
        return Some("NULL record query: unusual DNS behavior".to_string());
    }
    
    None
}

/// Detect Domain Generation Algorithm (DGA) patterns
pub fn detect_dga(domain: &str) -> Option<String> {
    // Extract the main domain (exclude TLD)
    let parts: Vec<&str> = domain.rsplitn(2, '.').collect();
    if parts.len() < 2 {
        return None;
    }
    
    let domain_name = parts[1];
    
    // DGA domains typically have:
    // 1. High entropy (random-looking)
    // 2. Long length (often 12-20 chars)
    // 3. Low vowel ratio
    // 4. Consonant clusters
    
    let entropy = calculate_shannon_entropy(domain_name);
    let vowel_ratio = calculate_vowel_ratio(domain_name);
    let consonant_clusters = count_consonant_clusters(domain_name);
    
    // Scoring system
    let mut dga_score = 0;
    
    if entropy > 3.2 {
        dga_score += 2;
    }
    
    if domain_name.len() > 12 && domain_name.len() < 25 {
        dga_score += 1;
    }
    
    if vowel_ratio < 0.25 {
        dga_score += 2;
    }
    
    if consonant_clusters >= 3 {
        dga_score += 1;
    }
    
    // Check for dictionary words (DGA domains rarely contain them)
    if !contains_common_words(domain_name) {
        dga_score += 1;
    }
    
    if dga_score >= 4 {
        return Some(format!(
            "Possible DGA domain (score: {}, entropy: {:.2}, vowels: {:.2})",
            dga_score, entropy, vowel_ratio
        ));
    }
    
    None
}

/// Detect Fast Flux (requires tracking IP changes over time)
pub struct FastFluxDetector {
    domain_ips: HashMap<String, Vec<(std::time::Instant, String)>>,
}

impl FastFluxDetector {
    pub fn new() -> Self {
        Self {
            domain_ips: HashMap::new(),
        }
    }
    
    /// Record a DNS resolution
    pub fn record_resolution(&mut self, domain: &str, ip: &str) {
        let entry = self.domain_ips
            .entry(domain.to_string())
            .or_insert_with(Vec::new);
        
        entry.push((std::time::Instant::now(), ip.to_string()));
        
        // Keep only last 100 resolutions per domain
        if entry.len() > 100 {
            entry.remove(0);
        }
    }
    
    /// Check if domain exhibits fast flux behavior
    pub fn check_fast_flux(&self, domain: &str) -> Option<String> {
        if let Some(resolutions) = self.domain_ips.get(domain) {
            // Need at least 5 resolutions to detect
            if resolutions.len() < 5 {
                return None;
            }
            
            // Check for multiple unique IPs in recent time window (last 5 minutes)
            let five_min_ago = std::time::Instant::now() - std::time::Duration::from_secs(300);
            let recent: Vec<_> = resolutions.iter()
                .filter(|(time, _)| *time > five_min_ago)
                .collect();
            
            if recent.len() < 3 {
                return None;
            }
            
            // Count unique IPs
            let mut unique_ips: Vec<&String> = recent.iter().map(|(_, ip)| ip).collect();
            unique_ips.sort();
            unique_ips.dedup();
            
            // Fast flux: 3+ different IPs in 5 minutes
            if unique_ips.len() >= 3 {
                return Some(format!(
                    "Fast flux detected: {} unique IPs in 5 min", 
                    unique_ips.len()
                ));
            }
        }
        
        None
    }
    
    /// Clean up old entries (call periodically)
    pub fn cleanup_old_entries(&mut self) {
        let one_hour_ago = std::time::Instant::now() - std::time::Duration::from_secs(3600);
        
        for (_, resolutions) in self.domain_ips.iter_mut() {
            resolutions.retain(|(time, _)| *time > one_hour_ago);
        }
        
        // Remove domains with no recent resolutions
        self.domain_ips.retain(|_, resolutions| !resolutions.is_empty());
    }
}

/// Detect suspicious TLDs commonly used in malware/phishing
pub fn check_suspicious_tld(domain: &str) -> Option<String> {
    const SUSPICIOUS_TLDS: &[&str] = &[
        ".tk", ".ml", ".ga", ".cf", ".gq",  // Free TLDs heavily abused
        ".top", ".xyz", ".club", ".work", ".date",
        ".stream", ".download", ".racing", ".win", ".bid",
        ".loan", ".trade", ".science", ".party", ".review",
        ".cricket", ".link", ".click", ".accountant"
    ];
    
    for tld in SUSPICIOUS_TLDS {
        if domain.ends_with(tld) {
            return Some(format!("Suspicious TLD: {}", tld));
        }
    }
    
    None
}

// Helper functions

fn calculate_shannon_entropy(s: &str) -> f64 {
    let mut char_counts: HashMap<char, usize> = HashMap::new();
    let len = s.len() as f64;
    
    for c in s.chars() {
        *char_counts.entry(c.to_ascii_lowercase()).or_insert(0) += 1;
    }
    
    let mut entropy = 0.0;
    for count in char_counts.values() {
        let probability = *count as f64 / len;
        entropy -= probability * probability.log2();
    }
    
    entropy
}

fn calculate_vowel_ratio(s: &str) -> f64 {
    let vowels = s.chars().filter(|c| "aeiou".contains(c.to_ascii_lowercase())).count();
    let total = s.len();
    
    if total == 0 {
        return 0.0;
    }
    
    vowels as f64 / total as f64
}

fn count_consonant_clusters(s: &str) -> usize {
    let vowels = "aeiou";
    let mut clusters = 0;
    let mut in_cluster = false;
    
    for c in s.chars() {
        if !vowels.contains(c.to_ascii_lowercase()) && c.is_alphabetic() {
            if !in_cluster {
                clusters += 1;
                in_cluster = true;
            }
        } else {
            in_cluster = false;
        }
    }
    
    clusters
}

fn contains_common_words(s: &str) -> bool {
    const COMMON_WORDS: &[&str] = &[
        "the", "and", "com", "net", "org", "web", "mail", "info", "app",
        "shop", "store", "news", "blog", "site", "home", "page", "tech",
        "data", "cloud", "api", "admin", "user", "login", "secure", "server"
    ];
    
    let lower = s.to_lowercase();
    for word in COMMON_WORDS {
        if lower.contains(word) {
            return true;
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dga_detection() {
        // Known DGA-like domain
        let dga_domain = "xbhklmwqrtz.com";
        assert!(detect_dga(dga_domain).is_some());
        
        // Normal domain
        let normal_domain = "google.com";
        assert!(detect_dga(normal_domain).is_none());
    }
    
    #[test]
    fn test_entropy_calculation() {
        // High entropy (random)
        let random = "xqzvkpwm";
        assert!(calculate_shannon_entropy(random) > 2.5);
        
        // Low entropy (repeated chars)
        let repeated = "aaaabbbb";
        assert!(calculate_shannon_entropy(repeated) < 2.0);
    }
    
    #[test]
    fn test_suspicious_tld() {
        assert!(check_suspicious_tld("malware.tk").is_some());
        assert!(check_suspicious_tld("phishing.ml").is_some());
        assert!(check_suspicious_tld("google.com").is_none());
    }
}
