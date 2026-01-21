use crate::config::signatures::Signatures;
use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use std::sync::Arc;

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
}

struct FlowStats {
    bytes: u64,
    packet_count: u64,
    large_packet_count: u64, // > 1000 bytes e.g.
    last_seen: SystemTime,
}

pub struct TransferDetector {
    signatures: Arc<Signatures>,
    flows: HashMap<FlowKey, FlowStats>,
}

impl TransferDetector {
    pub fn new(signatures: Arc<Signatures>) -> Self {
        Self {
            signatures,
            flows: HashMap::new(),
        }
    }

    pub fn update(&mut self, src_ip: &str, dst_ip: &str, packet_len: usize) -> Option<u64> {
        let key = FlowKey {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
        };

        // Clean up old flows occasionally (dumb implementation for now: check on every 1000th packet or just check this flow)
        // Real implementation should have a separate cleanup task.
        
        let stats = self.flows.entry(key.clone()).or_insert(FlowStats {
            bytes: 0,
            packet_count: 0,
            large_packet_count: 0,
            last_seen: SystemTime::now(),
        });

        stats.bytes += packet_len as u64;
        stats.packet_count += 1;
        stats.last_seen = SystemTime::now();

        if packet_len > 1000 {
            stats.large_packet_count += 1;
        }

        // Check thresholds
        if stats.bytes > self.signatures.transfer.high_volume_threshold_bytes {
            let ratio = stats.large_packet_count as f64 / stats.packet_count as f64;
            if ratio > self.signatures.transfer.large_packet_ratio_threshold {
                return Some(stats.bytes);
            }
        }

        None
    }
}
