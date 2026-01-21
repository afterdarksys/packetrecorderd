use crate::config::signatures::CloudStorageProtocol;
use crate::protocols::ProtocolInfo;
use std::collections::HashMap;

pub fn check_cloud_storage(signatures: &HashMap<String, CloudStorageProtocol>, info: &ProtocolInfo, src_port: u16, dst_port: u16) -> Option<String> {
    for (service_name, protocol) in signatures {
        // Check Ports
        if protocol.ports.contains(&src_port) || protocol.ports.contains(&dst_port) {
            // Strong indicator check (SNI)
            if let ProtocolInfo::Tls(tls_info) = info {
                 if let Some(sni) = &tls_info.sni {
                     for suffix in &protocol.sni_suffixes {
                         if sni.ends_with(suffix) {
                             return Some(service_name.clone());
                         }
                     }
                 }
            }
        }
        
        // Also check SNI even if port doesn't match standard ports
        if let ProtocolInfo::Tls(tls_info) = info {
             if let Some(sni) = &tls_info.sni {
                 for suffix in &protocol.sni_suffixes {
                     if sni.ends_with(suffix) {
                         return Some(service_name.clone());
                     }
                 }
             }
        }
    }
    None
}
