pub mod tor;
pub mod chat;
pub mod cloud;
pub mod transfer;
pub mod darkapi;
pub mod dnsscience;
pub mod dns_threats;
pub mod ip_reputation;
pub mod api_lookup;

use crate::config::signatures::Signatures;
use crate::config::api_keys::ApiConfig;
use crate::protocols::ProtocolInfo;
use std::sync::{Arc, Mutex};
use std::sync::Arc as StdArc;

#[derive(Clone)]
pub struct ForensicsEngine {
    signatures: Arc<Signatures>,
    transfer_detector: Arc<Mutex<transfer::TransferDetector>>,
    darkapi_client: Option<StdArc<darkapi::DarkApiClient>>,
    fast_flux_detector: Arc<Mutex<dns_threats::FastFluxDetector>>,
    api_config: ApiConfig,
}

#[derive(Debug, Clone)]
pub enum ForensicsAlert {
    TorDetected {
        src_ip: String,
        dst_ip: String,
        reason: String,
    },
    ChatDetected {
        src_ip: String,
        dst_ip: String,
        protocol: String,
        app: String,
    },
    CloudStorageDetected {
        src_ip: String,
        dst_ip: String,
        service: String,
    },
    HighVolumeTransfer {
        src_ip: String,
        dst_ip: String,
        bytes: u64,
    },
    MaliciousIp {
        ip: String,
        severity: String,
        categories: Vec<String>,
        source: String,
    },
    MaliciousDomain {
        domain: String,
        severity: String,
        categories: Vec<String>,
        confidence: u8,
    },
    DnsTunneling {
        src_ip: String,
        domain: String,
        reason: String,
    },
    DgaDetected {
        src_ip: String,
        domain: String,
        score: String,
    },
    FastFlux {
        domain: String,
        details: String,
    },
    SuspiciousTld {
        src_ip: String,
        domain: String,
        tld: String,
    },
    BotDetected {
        src_ip: String,
        dst_ip: String,
        bot_type: String,
        details: Option<String>,
    },
    DatacenterIp {
        ip: String,
        network_type: String,
        provider: Option<String>,
    },
}

impl ForensicsEngine {
    pub fn new(signatures: Signatures) -> Self {
        let sigs = Arc::new(signatures);
        let api_config = ApiConfig::from_env();
        
        // Initialize DarkAPI client if credentials available
        let darkapi_client = if let (Some(api_key), base_url) = (
            api_config.darkapi_key.clone(),
            api_config.darkapi_base_url.clone()
        ) {
            Some(StdArc::new(darkapi::DarkApiClient::new(api_key, base_url)))
        } else {
            None
        };
        
        Self {
            signatures: sigs.clone(),
            transfer_detector: Arc::new(Mutex::new(transfer::TransferDetector::new(sigs))),
            darkapi_client,
            fast_flux_detector: Arc::new(Mutex::new(dns_threats::FastFluxDetector::new())),
            api_config,
        }
    }

    pub fn analyze(&self, src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16, protocol_info: &ProtocolInfo, packet_len: usize) -> Vec<ForensicsAlert> {
        let mut alerts = Vec::new();

        // Check Tor
        if let Some(reason) = tor::check_tor(&self.signatures.tor, protocol_info) {
            alerts.push(ForensicsAlert::TorDetected {
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                reason,
            });
        }

        // Check Chat
        if let Some(app) = chat::check_chat(&self.signatures.chat, protocol_info, src_port, dst_port) {
            alerts.push(ForensicsAlert::ChatDetected {
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                protocol: format!("{:?}", protocol_info),
                app,
            });
        }

        // Check Cloud Storage
        if let Some(service) = cloud::check_cloud_storage(&self.signatures.cloud_storage, protocol_info, src_port, dst_port) {
            alerts.push(ForensicsAlert::CloudStorageDetected {
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                service,
            });
        }

        // Check Transfer
        let mut transfer_detector = self.transfer_detector.lock().unwrap();
        if let Some(bytes) = transfer_detector.update(src_ip, dst_ip, packet_len) {
             alerts.push(ForensicsAlert::HighVolumeTransfer {
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                bytes,
            });
        }
        drop(transfer_detector); // Release lock

        // DNS-specific threat detection
        if let ProtocolInfo::Dns(ref dns_info) = protocol_info {
            // Check for DNS tunneling
            if let Some(reason) = dns_threats::detect_dns_tunneling(dns_info) {
                alerts.push(ForensicsAlert::DnsTunneling {
                    src_ip: src_ip.to_string(),
                    domain: dns_info.query.clone(),
                    reason,
                });
            }
            
            // Check for DGA (Domain Generation Algorithm)
            if let Some(score) = dns_threats::detect_dga(&dns_info.query) {
                alerts.push(ForensicsAlert::DgaDetected {
                    src_ip: src_ip.to_string(),
                    domain: dns_info.query.clone(),
                    score,
                });
            }
            
            // Check for suspicious TLDs
            if let Some(tld) = dns_threats::check_suspicious_tld(&dns_info.query) {
                alerts.push(ForensicsAlert::SuspiciousTld {
                    src_ip: src_ip.to_string(),
                    domain: dns_info.query.clone(),
                    tld,
                });
            }
            
            // Check for fast flux (requires tracking)
            let mut flux_detector = self.fast_flux_detector.lock().unwrap();
            flux_detector.record_resolution(&dns_info.query, dst_ip);
            if let Some(details) = flux_detector.check_fast_flux(&dns_info.query) {
                alerts.push(ForensicsAlert::FastFlux {
                    domain: dns_info.query.clone(),
                    details,
                });
            }
        }

        // HTTP-specific detections (bot detection)
        if let ProtocolInfo::Http(ref http_info) = protocol_info {
            if let Some((is_bot, bot_type)) = ip_reputation::detect_bot_from_user_agent(http_info) {
                if is_bot {
                    alerts.push(ForensicsAlert::BotDetected {
                        src_ip: src_ip.to_string(),
                        dst_ip: dst_ip.to_string(),
                        bot_type,
                        details: http_info.user_agent.clone(),
                    });
                }
            }
        }

        // IP reputation (datacenter detection)
        let network_type = ip_reputation::classify_ip_type(src_ip);
        if network_type != ip_reputation::NetworkType::Unknown {
            alerts.push(ForensicsAlert::DatacenterIp {
                ip: src_ip.to_string(),
                network_type: format!("{:?}", network_type),
                provider: None,
            });
        }

        alerts
    }
}
