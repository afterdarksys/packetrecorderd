pub mod tor;
pub mod chat;
pub mod cloud;
pub mod transfer;
pub mod darkapi;
pub mod dnsscience;
pub mod dns_threats;
pub mod ip_reputation;
pub mod api_lookup;
pub mod cloudflare;

use crate::config::signatures::Signatures;
use crate::config::api_keys::ApiConfig;
use crate::protocols::ProtocolInfo;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct ForensicsEngine {
    signatures: Arc<Signatures>,
    transfer_detector: Arc<Mutex<transfer::TransferDetector>>,
    api_lookup: Arc<api_lookup::ApiLookupHandler>,
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
    CloudflareDetected {
        src_ip: String,
        dst_ip: String,
        service: String,
        details: Option<String>,
    },
}

impl ForensicsEngine {
    pub fn new(signatures: Signatures, api_lookup: Arc<api_lookup::ApiLookupHandler>) -> Self {
        let sigs = Arc::new(signatures);
        let api_config = ApiConfig::from_env();
        
        Self {
            signatures: sigs.clone(),
            transfer_detector: Arc::new(Mutex::new(transfer::TransferDetector::new(sigs))),
            api_lookup,
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

        // Check Cloudflare
        if let Some(service) = cloudflare::check_cloudflare(protocol_info) {
            alerts.push(ForensicsAlert::CloudflareDetected {
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                service: service.as_str().to_string(),
                details: match protocol_info {
                    ProtocolInfo::Tls(info) => info.sni.clone(),
                    _ => None,
                },
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
            // Check API for Domain Reputation
            let domain_req = api_lookup::ApiLookupRequest::DomainReputation { domain: dns_info.query.clone() };
            if let Some(resp) = self.api_lookup.get_cached(&domain_req) {
                 match resp {
                     api_lookup::ApiLookupResponse::DomainReputation(intel) => {
                         if intel.found {
                             alerts.push(ForensicsAlert::MaliciousDomain {
                                 domain: dns_info.query.clone(),
                                 severity: intel.severity.unwrap_or_else(|| "Medium".to_string()),
                                 categories: intel.categories.unwrap_or_default(),
                                 confidence: intel.confidence.unwrap_or(50),
                             });
                         }
                     },
                     api_lookup::ApiLookupResponse::DnsIntelligence(intel) => {
                         if intel.is_suspicious {
                             alerts.push(ForensicsAlert::MaliciousDomain {
                                 domain: dns_info.query.clone(),
                                 severity: "High".to_string(),
                                 categories: intel.threat_categories.unwrap_or_default(),
                                 confidence: 80,
                             });
                         }
                     },
                     _ => {}
                 }
            } else {
                self.api_lookup.queue_lookup(domain_req);
            }

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

        // Check IP Reputation via API
        let ip_req = api_lookup::ApiLookupRequest::IpReputation { ip: src_ip.to_string() };
        if let Some(resp) = self.api_lookup.get_cached(&ip_req) {
            match resp {
                api_lookup::ApiLookupResponse::IpReputation(rep) => {
                    if rep.is_malicious {
                        alerts.push(ForensicsAlert::MaliciousIp {
                            ip: src_ip.to_string(),
                            severity: "High".to_string(),
                            categories: rep.categories.unwrap_or_default(),
                            source: "DarkAPI".to_string(),
                        });
                    }
                },
                api_lookup::ApiLookupResponse::TrafficClassification(cls) => {
                    if cls.is_datacenter || cls.is_vpn || cls.is_max_risk() {
                         let mut cats = Vec::new();
                         if cls.is_datacenter { cats.push("Datacenter".to_string()); }
                         if cls.is_vpn { cats.push("VPN".to_string()); }
                         
                         alerts.push(ForensicsAlert::MaliciousIp {
                            ip: src_ip.to_string(),
                            severity: if cls.confidence > 80 { "Medium".to_string() } else { "Low".to_string() },
                            categories: cats,
                            source: "DNSScience".to_string(),
                        });
                    }
                },
                _ => {}
            }
        } else {
            // Queue for future packets
            self.api_lookup.queue_lookup(ip_req);
        }

        // IP reputation (datacenter detection from local rules or API)
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

    pub fn cleanup_state(&self) {
        if let Ok(mut detector) = self.fast_flux_detector.lock() {
            detector.cleanup_old_entries();
        }
    }
}

impl ForensicsAlert {
    pub fn describe(&self) -> String {
        match self {
            ForensicsAlert::TorDetected { reason, .. } => format!("TOR: {}", reason),
            ForensicsAlert::ChatDetected { app, .. } => format!("Chat: {}", app),
            ForensicsAlert::CloudStorageDetected { service, .. } => format!("Cloud Storage: {}", service),
            ForensicsAlert::HighVolumeTransfer { bytes, .. } => format!("High Volume Transfer: {} bytes", bytes),
            ForensicsAlert::MaliciousIp { ip, severity, .. } => format!("Malicious IP: {} ({})", ip, severity),
            ForensicsAlert::MaliciousDomain { domain, severity, .. } => format!("Malicious Domain: {} ({})", domain, severity),
            ForensicsAlert::DnsTunneling { domain, reason, .. } => format!("DNS Tunneling: {} ({})", domain, reason),
            ForensicsAlert::DgaDetected { domain, score, .. } => format!("DGA: {} ({})", domain, score),
            ForensicsAlert::FastFlux { domain, .. } => format!("Fast Flux: {}", domain),
            ForensicsAlert::SuspiciousTld { domain, tld, .. } => format!("Suspicious TLD: {} ({})", domain, tld),
            ForensicsAlert::BotDetected { bot_type, .. } => format!("Bot: {}", bot_type),
            ForensicsAlert::DatacenterIp { ip, network_type, .. } => format!("Datacenter IP: {} ({})", ip, network_type),
            ForensicsAlert::CloudflareDetected { service, details, .. } => format!("Cloudflare: {} ({:?})", service, details),
        }
    }
}
