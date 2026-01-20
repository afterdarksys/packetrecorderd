use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration as TokioDuration};
use tracing::{debug, info, warn};

use crate::storage::{PacketStore, StoredPacket};

/// Statistics for a replay session
#[derive(Debug, Clone, Default)]
pub struct ReplayStats {
    pub packets_replayed: u64,
    pub bytes_replayed: u64,
    pub packets_skipped: u64,
    pub elapsed_time: Duration,
}

/// Configuration for packet replay
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Speed multiplier (1.0 = real-time, 2.0 = 2x speed, 0.0 = as fast as possible)
    pub speed: f64,
    
    /// Maximum number of packets to replay (0 = all)
    pub max_packets: u64,
    
    /// Whether to display packets instead of sending them
    pub display_only: bool,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            speed: 1.0,
            max_packets: 0,
            display_only: true,
        }
    }
}

/// Session for replaying packets
pub struct ReplaySession {
    store: Arc<Mutex<PacketStore>>,
    session_id: String,
    config: ReplayConfig,
    stats: ReplayStats,
}

impl ReplaySession {
    /// Create a new replay session
    pub fn new(store: Arc<Mutex<PacketStore>>, session_id: String, config: ReplayConfig) -> Result<Self> {
        // Verify session exists
        store
            .lock().unwrap()
            .get_session(&session_id)
            .context("Failed to get session")?
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;
        
        info!("Created replay session for {}", session_id);
        
        Ok(Self {
            store,
            session_id,
            config,
            stats: ReplayStats::default(),
        })
    }
    
    /// Replay packets with timing control
    pub async fn replay(&mut self) -> Result<ReplayStats> {
        let start_time = Utc::now();
        
        // Get all packets for the session
        let packets = self.store.lock().unwrap().get_packets(&self.session_id, None)
            .context("Failed to get packets")?;
        
        if packets.is_empty() {
            warn!("No packets to replay in session {}", self.session_id);
            return Ok(self.stats.clone());
        }
        
        info!("Replaying {} packets from session {}", packets.len(), self.session_id);
        
        let mut prev_timestamp: Option<DateTime<Utc>> = None;
        
        for (idx, packet) in packets.iter().enumerate() {
            // Check if we've hit the max packet limit
            if self.config.max_packets > 0 && idx >= self.config.max_packets as usize {
                info!("Reached max packet limit: {}", self.config.max_packets);
                break;
            }
            
            // Calculate delay if not first packet and not running at max speed
            if let Some(prev_ts) = prev_timestamp {
                if self.config.speed > 0.0 {
                    let time_diff = packet.timestamp.signed_duration_since(prev_ts);
                    let duration_ms = time_diff.num_milliseconds().max(0) as u64;
                    let delay_ms = (duration_ms as f64 / self.config.speed) as u64;
                    if delay_ms > 0 {
                        sleep(TokioDuration::from_millis(delay_ms)).await;
                    }
                }
            }
            
            // Process the packet
            self.replay_packet(packet).await?;
            
            prev_timestamp = Some(packet.timestamp);
        }
        
        let end_time = Utc::now();
        self.stats.elapsed_time = end_time.signed_duration_since(start_time);
        
        info!(
            "Replay complete: {} packets, {} bytes in {} seconds",
            self.stats.packets_replayed,
            self.stats.bytes_replayed,
            self.stats.elapsed_time.num_seconds()
        );
        
        Ok(self.stats.clone())
    }
    
    /// Replay a single packet
    async fn replay_packet(&mut self, packet: &StoredPacket) -> Result<()> {
        if self.config.display_only {
            self.display_packet(packet);
        } else {
            // In a real implementation, this would send the packet to the network
            // This requires raw sockets and is platform-specific
            warn!("Network replay not implemented, displaying packet instead");
            self.display_packet(packet);
        }
        
        self.stats.packets_replayed += 1;
        self.stats.bytes_replayed += packet.data.len() as u64;
        
        if self.stats.packets_replayed % 100 == 0 {
            debug!("Replayed {} packets", self.stats.packets_replayed);
        }
        
        Ok(())
    }
    
    /// Display a packet
    fn display_packet(&self, packet: &StoredPacket) {
        println!(
            "[{}] Packet #{} - {} bytes",
            packet.timestamp.format("%H:%M:%S%.3f"),
            packet.id,
            packet.length
        );
        
        // Parse and display packet info using etherparse
        if let Ok(parsed) = self.parse_packet(&packet.data) {
            println!("  {}", parsed);
        }
    }
    
    /// Parse packet to get protocol information
    fn parse_packet(&self, data: &[u8]) -> Result<String> {
        use etherparse::PacketHeaders;
        
        match PacketHeaders::from_ethernet_slice(data) {
            Ok(headers) => {
                let mut info = String::new();
                
                if let Some(net) = headers.net {
                    match net {
                        etherparse::NetHeaders::Ipv4(ipv4, _) => {
                            info.push_str(&format!(
                                "IPv4: {}.{}.{}.{} -> {}.{}.{}.{}",
                                ipv4.source[0], ipv4.source[1], ipv4.source[2], ipv4.source[3],
                                ipv4.destination[0], ipv4.destination[1], ipv4.destination[2], ipv4.destination[3]
                            ));
                        }
                        etherparse::NetHeaders::Ipv6(ipv6, _) => {
                            info.push_str(&format!(
                                "IPv6: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x} -> {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                ipv6.source[0], ipv6.source[1], ipv6.source[2], ipv6.source[3], ipv6.source[4], ipv6.source[5], ipv6.source[6], ipv6.source[7],
                                ipv6.source[8], ipv6.source[9], ipv6.source[10], ipv6.source[11], ipv6.source[12], ipv6.source[13], ipv6.source[14], ipv6.source[15],
                                ipv6.destination[0], ipv6.destination[1], ipv6.destination[2], ipv6.destination[3], ipv6.destination[4], ipv6.destination[5], ipv6.destination[6], ipv6.destination[7],
                                ipv6.destination[8], ipv6.destination[9], ipv6.destination[10], ipv6.destination[11], ipv6.destination[12], ipv6.destination[13], ipv6.destination[14], ipv6.destination[15]
                            ));
                        }
                    }
                }
                
                if let Some(transport) = headers.transport {
                    match transport {
                        etherparse::TransportHeader::Udp(udp) => {
                            info.push_str(&format!(" | UDP: {} -> {}", udp.source_port, udp.destination_port));
                        }
                        etherparse::TransportHeader::Tcp(tcp) => {
                            info.push_str(&format!(" | TCP: {} -> {}", tcp.source_port, tcp.destination_port));
                        }
                        etherparse::TransportHeader::Icmpv4(_) => {
                            info.push_str(" | ICMPv4");
                        }
                        etherparse::TransportHeader::Icmpv6(_) => {
                            info.push_str(" | ICMPv6");
                        }
                    }
                }
                
                Ok(info)
            }
            Err(_) => Ok("Unable to parse packet".to_string()),
        }
    }
    
    /// Get current replay statistics
    pub fn stats(&self) -> &ReplayStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::PacketStore;

    #[tokio::test]
    async fn test_replay_session() {
        let store = Arc::new(Mutex::new(PacketStore::new_in_memory().unwrap()));
        let session_id = store.lock().unwrap().create_session("eth0", None).unwrap();
        
        // Add some test packets
        let packet_data = vec![0x01, 0x02, 0x03, 0x04];
        for _ in 0..5 {
            store.lock().unwrap().save_packet(&session_id, Utc::now(), &packet_data).unwrap();
        }
        
        let config = ReplayConfig {
            speed: 0.0, // Max speed for testing
            max_packets: 0,
            display_only: true,
        };
        
        let mut replay = ReplaySession::new(store, session_id, config).unwrap();
        let stats = replay.replay().await.unwrap();
        
        assert_eq!(stats.packets_replayed, 5);
        assert_eq!(stats.bytes_replayed, 20);
    }

    #[tokio::test]
    async fn test_replay_with_limit() {
        let store = Arc::new(Mutex::new(PacketStore::new_in_memory().unwrap()));
        let session_id = store.lock().unwrap().create_session("eth0", None).unwrap();
        
        let packet_data = vec![0x01, 0x02, 0x03, 0x04];
        for _ in 0..10 {
            store.lock().unwrap().save_packet(&session_id, Utc::now(), &packet_data).unwrap();
        }
        
        let config = ReplayConfig {
            speed: 0.0,
            max_packets: 3,
            display_only: true,
        };
        
        let mut replay = ReplaySession::new(store, session_id, config).unwrap();
        let stats = replay.replay().await.unwrap();
        
        assert_eq!(stats.packets_replayed, 3);
    }
}
