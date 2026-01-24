use std::collections::HashMap;
use anyhow::Result;
use chrono::{DateTime, Utc, Duration};
use tracing::{info, warn};
use crate::forensics::{ForensicsEngine, ForensicsAlert};
use crate::protocols::{self, ProtocolParser, ProtocolInfo};
use crate::ml::MLProcessor;
use crate::protocols::tls::TlsParser;
use crate::protocols::ldap::LdapParser;
use crate::protocols::netbios::NetbiosParser;
use crate::protocols::snmp::SnmpParser;
use crate::protocols::ntp::NtpParser;
use crate::protocols::rip::RipParser;
use crate::protocols::routing::RoutingParser;
use crate::protocols::smtp::SmtpParser;
use crate::protocols::dns::DnsParser;
use crate::protocols::http::HttpParser;
use crate::protocols::ssh::SshParser;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: u8, // 6 for TCP, 17 for UDP
}

impl FlowKey {
    fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip.clone(),
            dst_ip: self.src_ip.clone(),
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

fn extract_ip_payload_from_ethernet(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }

    let mut offset = 14usize;
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    // VLAN tags
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        if frame.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    match ethertype {
        0x0800 => {
            if frame.len() < offset + 20 {
                return None;
            }
            let ihl = (frame[offset] & 0x0f) as usize;
            let hdr_len = ihl * 4;
            if ihl < 5 {
                return None;
            }
            if frame.len() < offset + hdr_len {
                return None;
            }
            Some(&frame[offset + hdr_len..])
        }
        0x86DD => {
            if frame.len() < offset + 40 {
                return None;
            }
            Some(&frame[offset + 40..])
        }
        _ => None,
    }
}

struct FlowState {
    sni: Option<String>,
    last_seen: DateTime<Utc>,
}

pub struct PacketProcessor {
    forensics: ForensicsEngine,
    tls_parser: TlsParser,
    ldap_parser: LdapParser,
    netbios_parser: NetbiosParser,
    snmp_parser: SnmpParser,
    ntp_parser: NtpParser,
    rip_parser: RipParser,
    routing_parser: RoutingParser,
    smtp_parser: SmtpParser,
    dns_parser: DnsParser,
    http_parser: HttpParser,
    ssh_parser: SshParser,
    flow_table: HashMap<FlowKey, FlowState>,
    ml_processor: MLProcessor,
}

impl PacketProcessor {
    pub fn new(forensics: ForensicsEngine) -> Self {
        let mut ml_processor = MLProcessor::new();
        // Load models potentially in a background thread or here if fast
        if let Err(e) = ml_processor.load_models() {
            warn!("Failed to load ML models: {:?}", e);
        }

        Self {
            forensics,
            tls_parser: TlsParser::new(),
            ldap_parser: LdapParser::new(),
            netbios_parser: NetbiosParser::new(),
            snmp_parser: SnmpParser::new(),
            ntp_parser: NtpParser::new(),
            rip_parser: RipParser::new(),
            routing_parser: RoutingParser::new(),
            smtp_parser: SmtpParser::new(),
            dns_parser: DnsParser::new(),
            http_parser: HttpParser::new(),
            ssh_parser: SshParser::new(),
            flow_table: HashMap::new(),
            ml_processor,
        }
    }

    fn cleanup_stale_flows(&mut self, now: DateTime<Utc>) {
        // Remove flows older than 5 minutes
        let ttl = Duration::minutes(5);
        self.flow_table.retain(|_, state| {
            now.signed_duration_since(state.last_seen) < ttl
        });
    }

    fn describe_icmp(version: u8, type_: u8, code: u8) -> String {
        match (version, type_) {
            (4, 0) => "Echo Reply (Ping)".to_string(),
            (4, 3) => format!("Destination Unreachable (Code: {})", code),
            (4, 4) => "Source Quench".to_string(),
            (4, 5) => "Redirect".to_string(),
            (4, 8) => "Echo Request (Ping)".to_string(),
            (4, 11) => "Time Exceeded (Traceroute)".to_string(),
            (4, 12) => "Parameter Problem".to_string(),
            (4, 13) => "Timestamp".to_string(),
            (4, 14) => "Timestamp Reply".to_string(),
            (6, 1) => "Destination Unreachable".to_string(),
            (6, 2) => "Packet Too Big".to_string(),
            (6, 3) => "Time Exceeded (Traceroute)".to_string(),
            (6, 128) => "Echo Request (Ping)".to_string(),
            (6, 129) => "Echo Reply (Ping)".to_string(),
            (6, 130) => "Multicast Listener Query".to_string(),
            (6, 131) => "Multicast Listener Report".to_string(),
            (6, 132) => "Multicast Listener Done".to_string(),
            _ => format!("Type {} Code {}", type_, code),
        }
    }

    pub fn process(&mut self, timestamp: DateTime<Utc>, data: &[u8]) -> Result<()> {
        // Periodically clean up stale flows (every 1000 packets or so)
        if self.flow_table.len() % 1000 == 0 && !self.flow_table.is_empty() {
            self.cleanup_stale_flows(timestamp);
        }

        if let Ok(sliced) = etherparse::SlicedPacket::from_ethernet(data) {
            let mut src_ip = "0.0.0.0".to_string();
            let mut dst_ip = "0.0.0.0".to_string();
            let mut src_port = 0;
            let mut dst_port = 0;
            let mut payload: &[u8] = &[];
            let mut l4_protocol = "Unknown";

            if let Some(ref net) = sliced.net {
                match net {
                    etherparse::NetSlice::Ipv4(ipv4) => {
                        src_ip = std::net::Ipv4Addr::from(ipv4.header().source()).to_string();
                        dst_ip = std::net::Ipv4Addr::from(ipv4.header().destination()).to_string();
                    },
                    etherparse::NetSlice::Ipv6(ipv6) => {
                        src_ip = std::net::Ipv6Addr::from(ipv6.header().source()).to_string();
                        dst_ip = std::net::Ipv6Addr::from(ipv6.header().destination()).to_string();
                    }
                }
            }

            // Helper to get protocol number from IP header
            let mut ip_protocol = 0;
            if let Some(ref net) = sliced.net {
                match net {
                    etherparse::NetSlice::Ipv4(ipv4) => {
                        ip_protocol = ipv4.header().protocol().into();
                    },
                    etherparse::NetSlice::Ipv6(ipv6) => {
                        ip_protocol = ipv6.header().next_header().into();
                    }
                }
            }

            let mut protocol_info = protocols::ProtocolInfo::Unknown;

            if let Some(transport) = sliced.transport {
                match transport {
                    etherparse::TransportSlice::Tcp(tcp) => {
                        src_port = tcp.source_port();
                        dst_port = tcp.destination_port();
                        payload = tcp.payload();
                        l4_protocol = "TCP";

                        // Check for BGP (Port 179)
                        if src_port == 179 || dst_port == 179 {
                            if let Ok(info) = self.routing_parser.parse_bgp(payload) {
                                protocol_info = info;
                            }
                        }

                        // Check for SMTP (Ports 25, 465, 587)
                        if src_port == 25 || dst_port == 25 || src_port == 465 || dst_port == 465 || src_port == 587 || dst_port == 587 {
                             if let Ok(info) = self.smtp_parser.parse(payload) {
                                 if !matches!(info, ProtocolInfo::Unknown) {
                                     protocol_info = info;
                                 }
                             }
                        }

                        // Check for SSH (Port 22)
                        if src_port == 22 || dst_port == 22 {
                            if let Ok(info) = self.ssh_parser.parse(payload) {
                                if !matches!(info, ProtocolInfo::Unknown) {
                                    protocol_info = info;
                                }
                            }
                        }

                        // Check for DOT (Port 853) - It is TLS, but we can tag it if we want specific handling
                        // The TLS parser will handle the handshake.
                        if src_port == 853 || dst_port == 853 {
                            // DOT is just TLS over a specific port.
                            // We rely on the general TLS parser below, but we could set a hint or
                            // wrap the result to indicate DOT.
                            l4_protocol = "DOT (TCP)";
                        }
                    },
                    etherparse::TransportSlice::Udp(udp) => {
                        src_port = udp.source_port();
                        dst_port = udp.destination_port();
                        payload = udp.payload();
                        l4_protocol = "UDP";

                        // Check for DNS (Port 53)
                        if src_port == 53 || dst_port == 53 {
                             if let Ok(info) = self.dns_parser.parse(payload) {
                                 protocol_info = info;
                             }
                        }

                        // Check for SNMP (Ports 161, 162)
                        if matches!(protocol_info, protocols::ProtocolInfo::Unknown)
                            && (src_port == 161 || dst_port == 161 || src_port == 162 || dst_port == 162)
                        {
                            if let Ok(info) = self.snmp_parser.parse(payload) {
                                if !matches!(info, protocols::ProtocolInfo::Unknown) {
                                    protocol_info = info;
                                }
                            }
                        }

                        // Check for NTP (Port 123)
                        if matches!(protocol_info, protocols::ProtocolInfo::Unknown)
                            && (src_port == 123 || dst_port == 123)
                        {
                            if let Ok(info) = self.ntp_parser.parse(payload) {
                                if !matches!(info, protocols::ProtocolInfo::Unknown) {
                                    protocol_info = info;
                                }
                            }
                        }

                        // Check for RIPv2 (Port 520)
                        if matches!(protocol_info, protocols::ProtocolInfo::Unknown)
                            && (src_port == 520 || dst_port == 520)
                        {
                            if let Ok(info) = self.rip_parser.parse(payload) {
                                if !matches!(info, protocols::ProtocolInfo::Unknown) {
                                    protocol_info = info;
                                }
                            }
                        }

                        // Check for QUIC/DOH (Port 443 UDP) - This is distinct from TCP DOH
                        // if src_port == 443 || dst_port == 443 {
                        //     l4_protocol = "QUIC";
                        // }
                    },
                    etherparse::TransportSlice::Icmpv4(icmp) => {
                        l4_protocol = "ICMPv4";
                        let type_ = icmp.type_u8();
                        let code = icmp.code_u8();
                        protocol_info = ProtocolInfo::Icmp(protocols::IcmpInfo {
                            type_,
                            code,
                            description: Self::describe_icmp(4, type_, code),
                        });
                    },
                    etherparse::TransportSlice::Icmpv6(icmp) => {
                        l4_protocol = "ICMPv6";
                        let type_ = icmp.type_u8();
                        let code = icmp.code_u8();
                        protocol_info = ProtocolInfo::Icmp(protocols::IcmpInfo {
                            type_,
                            code,
                            description: Self::describe_icmp(6, type_, code),
                        });
                    },
                    _ => {}
                }
            } else {
                // No transport slice (or unparsed). Check IP protocol for OSPF/EIGRP.
                if let Some(ip_payload) = extract_ip_payload_from_ethernet(data) {
                    if ip_protocol == 89 {
                        l4_protocol = "OSPF";
                        if let Ok(info) = self.routing_parser.parse_ospf(ip_payload) {
                            if !matches!(info, protocols::ProtocolInfo::Unknown) {
                                protocol_info = info;
                            }
                        }
                    }

                    if ip_protocol == 88 {
                        l4_protocol = "EIGRP";
                        if let Ok(info) = self.routing_parser.parse_eigrp(ip_payload) {
                            if !matches!(info, protocols::ProtocolInfo::Unknown) {
                                protocol_info = info;
                            }
                        }
                    }
                }
            }
            
            if !payload.is_empty() {
                // Protocol detection chain (if not already found)
                if matches!(protocol_info, protocols::ProtocolInfo::Unknown) {
                
                // Try TLS
                if let Ok(info) = self.tls_parser.parse(payload) {
                    if !matches!(info, protocols::ProtocolInfo::Unknown) {
                        protocol_info = info;

                        // Check for ALPN suggesting DOH
                        if let ProtocolInfo::Tls(ref mut tls_info) = protocol_info {
                             // If we detected ALPN "h2" on port 443, it MIGHT be DOH, but it's also just HTTP/2.
                             // DOH often uses "h2" (HTTP/2) or "http/1.1".
                             // There isn't a specific ALPN for DOH usually (it's just HTTP).
                             // However, DOT (853) might have "dot" ALPN (RFC 7858).
                             
                             if src_port == 853 || dst_port == 853 {
                                 // Enhance info to say it is DOT
                                 tls_info.version = format!("DOT ({})", tls_info.version);
                             }
                        }

                        // Flow Tracking Logic for TLS
                        if let ProtocolInfo::Tls(ref tls_info) = protocol_info {
                            let key = FlowKey {
                                src_ip: src_ip.clone(),
                                dst_ip: dst_ip.clone(),
                                src_port,
                                dst_port,
                                protocol: 6, // TCP
                            };

                            // If Client Hello with SNI, store it
                            if let Some(sni) = &tls_info.sni {
                                self.flow_table.insert(key.clone(), FlowState {
                                    sni: Some(sni.clone()),
                                    last_seen: timestamp,
                                });
                                info!("TLS Handshake detected. SNI: {} (Flow: {:?})", sni, key);
                            }

                            // If Server Certificate, check for matching SNI
                            if tls_info.server_certificates.is_some() {
                                let reverse_key = key.reverse();
                                if let Some(state) = self.flow_table.get(&reverse_key) {
                                    if let Some(sni) = &state.sni {
                                         info!("TLS Certificate seen for existing flow. Original SNI: {}", sni);
                                         // Here we could verify if cert matches SNI
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Try HTTP if unknown
                if matches!(protocol_info, protocols::ProtocolInfo::Unknown) {
                    if let Ok(info) = self.http_parser.parse(payload) {
                         if !matches!(info, protocols::ProtocolInfo::Unknown) {
                             protocol_info = info;
                         }
                    }
                }

                // Try LDAP if unknown
                if matches!(protocol_info, protocols::ProtocolInfo::Unknown) {
                    if let Ok(info) = self.ldap_parser.parse(payload) {
                        if !matches!(info, protocols::ProtocolInfo::Unknown) {
                            protocol_info = info;
                        }
                    }
                }

                // Try NetBIOS if unknown
                if matches!(protocol_info, protocols::ProtocolInfo::Unknown) {
                    if let Ok(info) = self.netbios_parser.parse(payload) {
                        if !matches!(info, protocols::ProtocolInfo::Unknown) {
                            protocol_info = info;
                        }
                    }
                }

                // ML Inference for Protocol Detection
                // Only run if we haven't identified it deterministically, or to verify
                if matches!(protocol_info, protocols::ProtocolInfo::Unknown) {
                    // Extract simple features: [src_port, dst_port, payload_len, ...]
                    // In a real implementation we would need normalized features matching the training data
                    let features = vec![
                        src_port as f32, 
                        dst_port as f32, 
                        data.len() as f32,
                        // Filler for remaining 7 dimensions
                        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
                    ];
                    
                    if let Some(predicted) = self.ml_processor.predict_protocol(&features) {
                        info!("ML PREDICTION: {} -> {} : Probable Protocol: {}", src_ip, dst_ip, predicted);
                    }
                }

                let alerts = self.forensics.analyze(&src_ip, &dst_ip, src_port, dst_port, &protocol_info, data.len());
                for alert in alerts {
                    match alert {
                        ForensicsAlert::TorDetected { src_ip, dst_ip, reason } => {
                            warn!("TOR DETECTED: {} -> {}: {}", src_ip, dst_ip, reason);
                        },
                        ForensicsAlert::ChatDetected { src_ip, dst_ip, app, protocol } => {
                            info!("CHAT DETECTED: {} -> {}: App={}, Proto={}", src_ip, dst_ip, app, protocol);
                        },
                        ForensicsAlert::CloudStorageDetected { src_ip, dst_ip, service } => {
                            warn!("CLOUD STORAGE DETECTED: {} -> {}: Service={}", src_ip, dst_ip, service);
                        },
                        ForensicsAlert::HighVolumeTransfer { src_ip, dst_ip, bytes } => {
                            info!("TRANSFER DETECTED: {} -> {}: {} bytes", src_ip, dst_ip, bytes);
                        },
                        ForensicsAlert::MaliciousIp { ip, severity, categories, source } => {
                            warn!("MALICIOUS IP: {} - Severity: {} - Categories: {:?} - Source: {}", ip, severity, categories, source);
                        },
                        ForensicsAlert::MaliciousDomain { domain, severity, categories, confidence } => {
                            warn!("MALICIOUS DOMAIN: {} - Severity: {} - Categories: {:?} - Confidence: {}%", domain, severity, categories, confidence);
                        },
                        ForensicsAlert::DnsTunneling { src_ip, domain, reason } => {
                            warn!("DNS TUNNELING: {} -> {} - Reason: {}", src_ip, domain, reason);
                        },
                        ForensicsAlert::DgaDetected { src_ip, domain, score } => {
                            warn!("DGA DETECTED: {} -> {} - {}", src_ip, domain, score);
                        },
                        ForensicsAlert::FastFlux { domain, details } => {
                            warn!("FAST FLUX: {} - {}", domain, details);
                        },
                        ForensicsAlert::SuspiciousTld { src_ip, domain, tld } => {
                            info!("SUSPICIOUS TLD: {} -> {} - {}", src_ip, domain, tld);
                        },
                        ForensicsAlert::BotDetected { src_ip, dst_ip, bot_type, details } => {
                            info!("BOT DETECTED: {} -> {} - Type: {} - UA: {:?}", src_ip, dst_ip, bot_type, details);
                        },
                        ForensicsAlert::DatacenterIp { ip, network_type, provider } => {
                            info!("DATACENTER IP: {} - Type: {} - Provider: {:?}", ip, network_type, provider);
                        },
                    }
                }
                }
            }
        }
        Ok(())
    }
}
