use std::sync::{Arc, RwLock}; // Use std RwLock for sync access
use tokio::sync::mpsc;
// use tokio::sync::Mutex as TokioMutex; // Removed
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use tracing::{debug, warn};

use super::darkapi::{DarkApiClient, IpReputationResponse, ThreatIntelResponse};
use super::dnsscience::{DnsScienceClient, DnsIntelligence, TrafficClassification};
use super::cloudflare::CloudflareApiClient;

/// Request types for async API lookups
#[derive(Debug, Clone)]
pub enum ApiLookupRequest {
    IpReputation { ip: String },
    DomainReputation { domain: String },
    UrlCheck { url: String },
}

/// Response from API lookups
#[derive(Debug, Clone)]
pub enum ApiLookupResponse {
    IpReputation(IpReputationResponse),
    DomainReputation(ThreatIntelResponse),
    UrlCheck(ThreatIntelResponse),
    DnsIntelligence(DnsIntelligence), // Added
    TrafficClassification(TrafficClassification), // Added
    Error(String),
}

/// Cached API response with timestamp
#[derive(Debug, Clone)]
struct CachedResponse {
    response: ApiLookupResponse,
    timestamp: DateTime<Utc>,
}

/// Async API lookup handler with caching
pub struct ApiLookupHandler {
    darkapi_client: Option<Arc<DarkApiClient>>,
    dnsscience_client: Option<Arc<DnsScienceClient>>,
    cloudflare_client: Option<Arc<CloudflareApiClient>>,
    request_tx: mpsc::UnboundedSender<(ApiLookupRequest, tokio::sync::oneshot::Sender<ApiLookupResponse>)>,
    cache: Arc<RwLock<HashMap<String, CachedResponse>>>,
}

impl ApiLookupHandler {
    /// Create new handler and spawn background worker
    pub fn new(
        darkapi_client: Option<Arc<DarkApiClient>>,
        dnsscience_client: Option<Arc<DnsScienceClient>>,
        cloudflare_client: Option<Arc<CloudflareApiClient>>,
    ) -> Self {
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let cache = Arc::new(RwLock::new(HashMap::new()));
        
        // Spawn background worker
        if darkapi_client.is_some() || dnsscience_client.is_some() || cloudflare_client.is_some() {
            let cache_clone = cache.clone();
            let darkapi = darkapi_client.clone();
            let dnsscience = dnsscience_client.clone();
            let cloudflare = cloudflare_client.clone();
            tokio::spawn(async move {
                Self::worker(darkapi, dnsscience, cloudflare, request_rx, cache_clone).await;
            });
        }
        
        Self {
            darkapi_client,
            dnsscience_client,
            cloudflare_client,
            request_tx,
            cache,
        }
    }
    
    /// Background worker that processes API requests
    async fn worker(
        darkapi: Option<Arc<DarkApiClient>>,
        dnsscience: Option<Arc<DnsScienceClient>>,
        cloudflare: Option<Arc<CloudflareApiClient>>,
        mut request_rx: mpsc::UnboundedReceiver<(ApiLookupRequest, tokio::sync::oneshot::Sender<ApiLookupResponse>)>,
        cache: Arc<RwLock<HashMap<String, CachedResponse>>>,
    ) {
        while let Some((request, response_tx)) = request_rx.recv().await {
            let cache_key = Self::cache_key(&request);
            
            // Check cache first
            {
                if let Ok(cache_guard) = cache.read() {
                    if let Some(cached) = cache_guard.get(&cache_key) {
                        // Cache valid for 5 minutes
                        if Utc::now().signed_duration_since(cached.timestamp) < Duration::minutes(5) {
                            debug!("Cache hit for {}", cache_key);
                            let _ = response_tx.send(cached.response.clone());
                            continue;
                        }
                    }
                }
            }
            
            // Make API call
            let response = match request {
                ApiLookupRequest::IpReputation { ref ip } => {
                     // Try Cloudflare first
                     if let Some(client) = &cloudflare {
                         match client.lookup_ip(ip).await {
                             Ok(data) => ApiLookupResponse::IpReputation(data),
                             Err(e) => {
                                 warn!("Cloudflare IP lookup failed: {}", e);
                                 // Fallback to DNSScience
                                 Self::lookup_ip_fallback(ip, &dnsscience, &darkapi).await
                             }
                         }
                     } else {
                         Self::lookup_ip_fallback(ip, &dnsscience, &darkapi).await
                     }
                },
                ApiLookupRequest::DomainReputation { ref domain } => {
                    // Try DNSScience first, then DarkAPI
                    if let Some(client) = &dnsscience {
                         match client.analyze_domain(domain).await {
                            Ok(data) => ApiLookupResponse::DnsIntelligence(data),
                            Err(e) => {
                                warn!("DNSScience lookup failed: {}", e);
                                // Fallback to DarkAPI
                                if let Some(dark) = &darkapi {
                                    match dark.lookup_domain(domain).await {
                                        Ok(data) => ApiLookupResponse::DomainReputation(data),
                                        Err(e2) => ApiLookupResponse::Error(format!("Both APIs failed: {}; {}", e, e2))
                                    }
                                } else {
                                     ApiLookupResponse::Error(e.to_string())
                                }
                            }
                        }
                    } else if let Some(client) = &darkapi {
                         match client.lookup_domain(domain).await {
                            Ok(data) => ApiLookupResponse::DomainReputation(data),
                            Err(e) => {
                                warn!("DarkAPI domain lookup failed: {}", e);
                                ApiLookupResponse::Error(e.to_string())
                            }
                        }
                    } else {
                        ApiLookupResponse::Error("No Intelligence API configured".to_string())
                    }
                },
                ApiLookupRequest::UrlCheck { ref url } => {
                    if let Some(client) = &darkapi {
                        match client.check_url(url).await {
                            Ok(data) => ApiLookupResponse::UrlCheck(data),
                            Err(e) => {
                                warn!("DarkAPI URL check failed: {}", e);
                                ApiLookupResponse::Error(e.to_string())
                            }
                        }
                    } else {
                         ApiLookupResponse::Error("DarkAPI not configured".to_string())
                    }
                },
            };
            
            // Cache the response
            {
                if let Ok(mut cache_guard) = cache.write() {
                    cache_guard.insert(cache_key.clone(), CachedResponse {
                        response: response.clone(),
                        timestamp: Utc::now(),
                    });
                    
                    // Limit cache size to 1000 entries
                    if cache_guard.len() > 1000 {
                        // Remove oldest entries - simple strategy: remove random/arbitrary to avoid sorting overhead frequently
                        // Or just clear 10%
                        // valid drainage
                        let keys_to_remove: Vec<String> = cache_guard.keys().take(100).cloned().collect();
                        for k in keys_to_remove {
                            cache_guard.remove(&k);
                        }
                    }
                }
            }
            
            // Send response
            let _ = response_tx.send(response);
        }
    }
    
    /// Generate cache key for request
    fn cache_key(request: &ApiLookupRequest) -> String {
        match request {
            ApiLookupRequest::IpReputation { ip } => format!("ip:{}", ip),
            ApiLookupRequest::DomainReputation { domain } => format!("domain:{}", domain),
            ApiLookupRequest::UrlCheck { url } => format!("url:{}", url),
        }
    }

    /// Submit lookup request without waiting (fire-and-forget)
    /// This allows synchronous code to trigger lookups that populate the cache later
    pub fn queue_lookup(&self, request: ApiLookupRequest) {
        if self.darkapi_client.is_none() && self.dnsscience_client.is_none() {
            return;
        }
        
        // Create a dummy channel as we don't care about immediate response here
        // The worker populates the cache which is what we care about
        let (response_tx, _) = tokio::sync::oneshot::channel();
        
        if let Err(e) = self.request_tx.send((request, response_tx)) {
            warn!("Failed to queue API lookup request: {}", e);
        }
    }
    
    /// Submit async lookup request (non-blocking)
    pub async fn lookup(&self, request: ApiLookupRequest) -> Option<ApiLookupResponse> {
        if self.darkapi_client.is_none() && self.dnsscience_client.is_none() {
            return None;
        }
        
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        
        if self.request_tx.send((request, response_tx)).is_err() {
            warn!("Failed to send API lookup request");
            return None;
        }
        
        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(10), response_rx).await {
            Ok(Ok(response)) => Some(response),
            Ok(Err(_)) => {
                warn!("API lookup channel closed");
                None
            },
            Err(_) => {
                warn!("API lookup timeout");
                None
            }
        }
    }
    
    /// Try to get cached response immediately (synchronous, non-blocking check)
    pub fn get_cached(&self, request: &ApiLookupRequest) -> Option<ApiLookupResponse> {
        let cache_key = Self::cache_key(request);
        
        if let Ok(cache_guard) = self.cache.read() {
            if let Some(cached) = cache_guard.get(&cache_key) {
                // Cache valid for 5 minutes
                if Utc::now().signed_duration_since(cached.timestamp) < Duration::minutes(5) {
                    return Some(cached.response.clone());
                }
            }
        }
        
        None
    }
    
    /// Clear cache
    pub fn clear_cache(&self) {
        if let Ok(mut cache_guard) = self.cache.write() {
            cache_guard.clear();
        }
    }
    
    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        if let Ok(cache_guard) = self.cache.read() {
            let total = cache_guard.len();
            let valid = cache_guard.iter()
                .filter(|(_, v)| Utc::now().signed_duration_since(v.timestamp) < Duration::minutes(5))
                .count();
            return (total, valid);
        }
        (0, 0)
    }

    async fn lookup_ip_fallback(ip: &str, dnsscience: &Option<Arc<DnsScienceClient>>, darkapi: &Option<Arc<DarkApiClient>>) -> ApiLookupResponse {
        if let Some(client) = dnsscience {
            match client.classify_ip(ip).await {
                    Ok(data) => ApiLookupResponse::TrafficClassification(data),
                    Err(e) => {
                        warn!("DNSScience IP classification failed: {}", e);
                        // Fallback to DarkAPI
                        if let Some(dark) = darkapi {
                            match dark.lookup_ip(ip).await {
                                Ok(data) => ApiLookupResponse::IpReputation(data),
                                Err(e2) => ApiLookupResponse::Error(format!("APIs failed: {}; {}", e, e2))
                            }
                        } else {
                                ApiLookupResponse::Error(e.to_string())
                        }
                    }
            }
        } else if let Some(client) = darkapi {
            match client.lookup_ip(ip).await {
                Ok(data) => ApiLookupResponse::IpReputation(data),
                Err(e) => {
                    warn!("DarkAPI IP lookup failed: {}", e);
                    ApiLookupResponse::Error(e.to_string())
                }
            }
        } else {
            ApiLookupResponse::Error("No Intelligence API configured".to_string())
        }
    }
}
