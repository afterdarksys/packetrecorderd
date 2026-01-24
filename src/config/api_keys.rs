use std::env;

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub dnsscience_api_key: Option<String>,
    pub dnsscience_base_url: String,
    pub darkapi_key: Option<String>,
    pub darkapi_base_url: String,
}

impl ApiConfig {
    pub fn from_env() -> Self {
        Self {
            dnsscience_api_key: env::var("DNSSCIENCE_API_KEY").ok(),
            dnsscience_base_url: env::var("DNSSCIENCE_URL")
                .unwrap_or_else(|_| "https://dnsscience.io".to_string()),
            darkapi_key: env::var("DARKAPI_KEY").ok(),
            darkapi_base_url: env::var("DARKAPI_URL")
                .unwrap_or_else(|_| "https://console.darkapi.io".to_string()),
        }
    }

    pub fn has_dnsscience(&self) -> bool {
        self.dnsscience_api_key.is_some()
    }

    pub fn has_darkapi(&self) -> bool {
        self.darkapi_key.is_some()
    }
}
