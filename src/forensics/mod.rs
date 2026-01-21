pub mod tor;
pub mod chat;
pub mod cloud;
pub mod transfer;

use crate::config::signatures::Signatures;
use crate::protocols::ProtocolInfo;
use std::sync::{Arc, Mutex};

pub struct ForensicsEngine {
    signatures: Arc<Signatures>,
    transfer_detector: Arc<Mutex<transfer::TransferDetector>>,
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
}

impl ForensicsEngine {
    pub fn new(signatures: Signatures) -> Self {
        let sigs = Arc::new(signatures);
        Self {
            signatures: sigs.clone(),
            transfer_detector: Arc::new(Mutex::new(transfer::TransferDetector::new(sigs))),
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

        alerts
    }
}
