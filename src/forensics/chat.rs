use crate::config::signatures::ChatProtocol;
use crate::protocols::ProtocolInfo;
use std::collections::HashMap;

pub fn check_chat(signatures: &HashMap<String, ChatProtocol>, info: &ProtocolInfo, src_port: u16, dst_port: u16) -> Option<String> {
    for (app_name, protocol) in signatures {
        // Check Ports
        if protocol.ports.contains(&src_port) || protocol.ports.contains(&dst_port) {
            // If port matches, we check other indicators if available, or just flag if high confidence?
            // For now, let's look for strong indicators like SNI if TLS.
            if let ProtocolInfo::Tls(tls_info) = info {
                 if let Some(sni) = &tls_info.sni {
                     for suffix in &protocol.sni_suffixes {
                         if sni.ends_with(suffix) {
                             return Some(app_name.clone());
                         }
                     }
                 }
            } else if !protocol.sni_suffixes.is_empty() {
                 // If we have SNI suffixes but it's not TLS, we might miss it unless we parse HTTP Host headers etc.
                 // But if ports match, it's a "Maybe".
                 // For now, let's require SNI match for TLS traffic or just port match if it's specific enough?
                 // Let's stick to SNI match for high confidence for now.
            }
        }
        
        // Also check SNI even if port doesn't match standard ports (non-standard port usage)
        if let ProtocolInfo::Tls(tls_info) = info {
             if let Some(sni) = &tls_info.sni {
                 for suffix in &protocol.sni_suffixes {
                     if sni.ends_with(suffix) {
                         return Some(app_name.clone());
                     }
                 }
             }
        }
    }
    None
}
