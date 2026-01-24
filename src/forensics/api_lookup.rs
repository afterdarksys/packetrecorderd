use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex as TokioMutex;
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use tracing::{debug, warn};

use super::darkapi::{DarkApiClient, IpReputationResponse, ThreatIntelResponse};

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
    request_tx: mpsc::UnboundedSender<(ApiLookupRequest, tokio::sync::oneshot::Sender<ApiLookupResponse>)>,
    cache: Arc<TokioMutex<HashMap<String, CachedResponse>>>,
}

impl ApiLookupHandler {
    /// Create new handler and spawn background worker
    pub fn new(darkapi_client: Option<Arc<DarkApiClient>>) -> Self {
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let cache = Arc::new(TokioMutex::new(HashMap::new()));
        
        // Spawn background worker
        if let Some(client) = darkapi_client.clone() {
            let cache_clone = cache.clone();
            tokio::spawn(async move {
                Self::worker(client, request_rx, cache_clone).await;
            });
        }
        
        Self {
            darkapi_client,
            request_tx,
            cache,
        }
    }
    
    /// Background worker that processes API requests
    async fn worker(
        client: Arc<DarkApiClient>,
        mut request_rx: mpsc::UnboundedReceiver<(ApiLookupRequest, tokio::sync::oneshot::Sender<ApiLookupResponse>)>,
        cache: Arc<TokioMutex<HashMap<String, CachedResponse>>>,
    ) {
        while let Some((request, response_tx)) = request_rx.recv().await {
            let cache_key = Self::cache_key(&request);
            
            // Check cache first
            {
                let cache_guard = cache.lock().await;
                if let Some(cached) = cache_guard.get(&cache_key) {
                    // Cache valid for 5 minutes
                    if Utc::now().signed_duration_since(cached.timestamp) < Duration::minutes(5) {
                        debug!("Cache hit for {}", cache_key);
                        let _ = response_tx.send(cached.response.clone());
                        continue;
                    }
                }
            }
            
            // Make API call
            let response = match request {
                ApiLookupRequest::IpReputation { ref ip } => {
                    match client.lookup_ip(ip).await {
                        Ok(data) => ApiLookupResponse::IpReputation(data),
                        Err(e) => {
                            warn!("DarkAPI IP lookup failed: {}", e);
                            ApiLookupResponse::Error(e.to_string())
                        }
                    }
                },
                ApiLookupRequest::DomainReputation { ref domain } => {
                    match client.lookup_domain(domain).await {
                        Ok(data) => ApiLookupResponse::DomainReputation(data),
                        Err(e) => {
                            warn!("DarkAPI domain lookup failed: {}", e);
                            ApiLookupResponse::Error(e.to_string())
                        }
                    }
                },
                ApiLookupRequest::UrlCheck { ref url } => {
                    match client.check_url(url).await {
                        Ok(data) => ApiLookupResponse::UrlCheck(data),
                        Err(e) => {
                            warn!("DarkAPI URL check failed: {}", e);
                            ApiLookupResponse::Error(e.to_string())
                        }
                    }
                },
            };
            
            // Cache the response
            {
                let mut cache_guard = cache.lock().await;
                cache_guard.insert(cache_key.clone(), CachedResponse {
                    response: response.clone(),
                    timestamp: Utc::now(),
                });
                
                // Limit cache size to 1000 entries
                if cache_guard.len() > 1000 {
                    // Remove oldest entries
                    let mut entries: Vec<_> = cache_guard.iter()
                        .map(|(k, v)| (k.clone(), v.timestamp))
                        .collect();
                    entries.sort_by_key(|(_, ts)| *ts);
                    
                    // Remove oldest 100
                    for (key, _) in entries.iter().take(100) {
                        cache_guard.remove(key);
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
    
    /// Submit async lookup request (non-blocking)
    pub async fn lookup(&self, request: ApiLookupRequest) -> Option<ApiLookupResponse> {
        if self.darkapi_client.is_none() {
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
    
    /// Try to get cached response immediately (non-blocking check)
    pub async fn get_cached(&self, request: &ApiLookupRequest) -> Option<ApiLookupResponse> {
        let cache_key = Self::cache_key(request);
        let cache_guard = self.cache.lock().await;
        
        if let Some(cached) = cache_guard.get(&cache_key) {
            // Cache valid for 5 minutes
            if Utc::now().signed_duration_since(cached.timestamp) < Duration::minutes(5) {
                return Some(cached.response.clone());
            }
        }
        
        None
    }
    
    /// Clear cache
    pub async fn clear_cache(&self) {
        let mut cache_guard = self.cache.lock().await;
        cache_guard.clear();
    }
    
    /// Get cache statistics
    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache_guard = self.cache.lock().await;
        let total = cache_guard.len();
        let valid = cache_guard.iter()
            .filter(|(_, v)| Utc::now().signed_duration_since(v.timestamp) < Duration::minutes(5))
            .count();
        (total, valid)
    }
}
