#![allow(dead_code)]
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

use crate::storage::PacketStore;

/// Trait for writing captured packets
pub trait PacketWriter: Send + Sync {
    /// Write a single packet
    fn write_packet(&mut self, timestamp: DateTime<Utc>, data: &[u8]) -> Result<()>;
    
    /// Flush any buffered data
    fn flush(&mut self) -> Result<()>;
    
    /// Close the writer
    fn close(&mut self) -> Result<()>;
}

/// Writer that saves packets to a database
pub struct DatabaseWriter {
    store: Arc<Mutex<PacketStore>>,
    session_id: String,
    packet_count: u64,
}

impl DatabaseWriter {
    /// Create a new database writer
    pub fn new(store: Arc<Mutex<PacketStore>>, interface: &str, filter: Option<&str>) -> Result<Self> {
        let session_id = store.lock().unwrap().create_session(interface, filter)
            .context("Failed to create database session")?;
        
        info!("Created database writer for session {}", session_id);
        
        Ok(Self {
            store,
            session_id,
            packet_count: 0,
        })
    }
    
    /// Get the session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    
    /// Get the number of packets written
    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }
}

impl PacketWriter for DatabaseWriter {
    fn write_packet(&mut self, timestamp: DateTime<Utc>, data: &[u8]) -> Result<()> {
        self.store.lock().unwrap().save_packet(&self.session_id, timestamp, data)
            .context("Failed to save packet to database")?;
        self.packet_count += 1;
        
        if self.packet_count.is_multiple_of(1000) {
            debug!("Saved {} packets to database", self.packet_count);
        }
        
        Ok(())
    }
    
    fn flush(&mut self) -> Result<()> {
        // SQLite commits are handled automatically
        Ok(())
    }
    
    fn close(&mut self) -> Result<()> {
        info!("Closing database writer, {} packets saved", self.packet_count);
        self.store.lock().unwrap().end_session(&self.session_id)
            .context("Failed to end session")
    }
}

// Note: PcapWriter removed due to pcap crate API limitations
// For pcap file output, consider using pcap-file crate instead

/// Async wrapper for packet writers
pub struct AsyncPacketWriter {
    writer: Arc<Mutex<Box<dyn PacketWriter>>>,
}

impl AsyncPacketWriter {
    /// Create a new async packet writer
    pub fn new(writer: Box<dyn PacketWriter>) -> Self {
        Self {
            writer: Arc::new(Mutex::new(writer)),
        }
    }
    
    /// Write a packet asynchronously
    pub async fn write_packet(&self, timestamp: DateTime<Utc>, data: Vec<u8>) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        writer.write_packet(timestamp, &data)
    }
    
    /// Flush the writer
    pub async fn flush(&self) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        writer.flush()
    }
    
    /// Close the writer
    pub async fn close(&self) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        writer.close()
    }
}

impl Clone for AsyncPacketWriter {
    fn clone(&self) -> Self {
        Self {
            writer: Arc::clone(&self.writer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::PacketStore;
    use std::sync::Arc;

    #[test]
    fn test_database_writer() {
        let store = Arc::new(Mutex::new(PacketStore::new_in_memory().unwrap()));
        let mut writer = DatabaseWriter::new(store.clone(), "eth0", None).unwrap();
        
        let timestamp = Utc::now();
        let data = vec![0x01, 0x02, 0x03, 0x04];
        
        writer.write_packet(timestamp, &data).unwrap();
        assert_eq!(writer.packet_count(), 1);
        
        writer.close().unwrap();
        
        let session = store.lock().unwrap().get_session(writer.session_id()).unwrap().unwrap();
        assert_eq!(session.packet_count, 1);
    }

    #[tokio::test]
    async fn test_async_writer() {
        let store = Arc::new(Mutex::new(PacketStore::new_in_memory().unwrap()));
        let writer = DatabaseWriter::new(store.clone(), "eth0", None).unwrap();
        let session_id = writer.session_id().to_string();
        
        let async_writer = AsyncPacketWriter::new(Box::new(writer));
        
        let timestamp = Utc::now();
        let data = vec![0x01, 0x02, 0x03, 0x04];
        
        async_writer.write_packet(timestamp, data).await.unwrap();
        async_writer.close().await.unwrap();
        
        let session = store.lock().unwrap().get_session(&session_id).unwrap().unwrap();
        assert_eq!(session.packet_count, 1);
    }
}
