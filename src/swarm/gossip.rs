use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: String, // "ip", "domain", "hash"
    pub value: String,
    pub confidence: f32,
    pub source_node: String,
}

#[derive(Clone)]
pub struct GossipService {
    peers: Arc<Mutex<HashSet<String>>>, // List of peer addresses
    threats: broadcast::Sender<ThreatIndicator>,
}

impl GossipService {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            peers: Arc::new(Mutex::new(HashSet::new())),
            threats: tx,
        }
    }

    pub fn add_peer(&self, peer_addr: String) {
        let mut peers = self.peers.lock().unwrap();
        peers.insert(peer_addr);
    }

    pub fn broadcast_threat(&self, threat: ThreatIndicator) {
        // In a real implementation, this would send gRPC/HTTP requests to peers
        // For now, we simulate the broadcast
        let peers = self.peers.lock().unwrap();
        info!("Broadcasting threat {:?} to {} peers", threat, peers.len());
        
        // This internal broadcast is for local subscribers (e.g. API, logger)
        let _ = self.threats.send(threat);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ThreatIndicator> {
        self.threats.subscribe()
    }
}
