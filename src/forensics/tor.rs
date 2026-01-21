use crate::config::signatures::TorSignatures;
use crate::protocols::ProtocolInfo;

pub fn check_tor(signatures: &TorSignatures, info: &ProtocolInfo) -> Option<String> {
    if let ProtocolInfo::Tls(tls_info) = info {
        // Check JA3
        if let Some(ja3) = &tls_info.ja3 {
            if signatures.ja3_hashes.contains(ja3) {
                return Some(format!("Matched JA3: {}", ja3));
            }
        }

        // Check SNI
        if let Some(sni) = &tls_info.sni {
            for suffix in &signatures.sni_suffixes {
                if sni.ends_with(suffix) {
                    return Some(format!("Matched SNI suffix: {}", suffix));
                }
            }
        }
    }
    None
}
