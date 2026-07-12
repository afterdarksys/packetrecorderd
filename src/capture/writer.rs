#![allow(dead_code)]
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::io::{BufWriter, Write};
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
    pending: Vec<(DateTime<Utc>, Vec<u8>)>,
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
            pending: Vec::with_capacity(512),
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
        self.pending.push((timestamp, data.to_vec()));
        self.packet_count += 1;
        if self.pending.len() >= 512 {
            self.flush()?;
        }
        
        if self.packet_count.is_multiple_of(1000) {
            debug!("Saved {} packets to database", self.packet_count);
        }
        
        Ok(())
    }
    
    fn flush(&mut self) -> Result<()> {
        self.store.lock().map_err(|_| anyhow::anyhow!("packet store lock poisoned"))?
            .save_packets(&self.session_id, &self.pending)
            .context("Failed to save packet batch")?;
        self.pending.clear();
        Ok(())
    }
    
    fn close(&mut self) -> Result<()> {
        self.flush()?;
        info!("Closing database writer, {} packets saved", self.packet_count);
        self.store.lock().map_err(|_| anyhow::anyhow!("packet store lock poisoned"))?.end_session(&self.session_id)
            .context("Failed to end session")
    }
}

/// Writer that saves packets to a PCAP file
pub struct PcapWriter {
    writer: Option<pcap_file::pcap::PcapWriter<BufWriter<std::fs::File>>>,
    packet_count: u64,
}

impl PcapWriter {
    /// Create a new PCAP writer
    pub fn new(path: &std::path::Path) -> Result<Self> {
        let file = create_private_file(path).context("Failed to create PCAP file")?;
        
        let writer = pcap_file::pcap::PcapWriter::new(BufWriter::with_capacity(1024 * 1024, file))
            .context("Failed to create PCAP writer")?;
        
        info!("Created PCAP writer: {:?}", path);
        
        Ok(Self {
            writer: Some(writer),
            packet_count: 0,
        })
    }
    
    /// Get the number of packets written
    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }
}

impl PacketWriter for PcapWriter {
    fn write_packet(&mut self, timestamp: DateTime<Utc>, data: &[u8]) -> Result<()> {
        // Convert timestamp to Duration since UNIX epoch
        let micros = u64::try_from(timestamp.timestamp_micros())
            .context("PCAP timestamps before the Unix epoch are unsupported")?;
        let duration = std::time::Duration::from_micros(micros);
        
        let packet = pcap_file::pcap::PcapPacket::new(duration, data.len() as u32, data);
        
        self.writer.as_mut().context("PCAP writer is closed")?.write_packet(&packet)
            .context("Failed to write packet to PCAP file")?;
        
        self.packet_count += 1;
        
        if self.packet_count.is_multiple_of(1000) {
            debug!("Saved {} packets to PCAP file", self.packet_count);
        }
        
        Ok(())
    }
    
    fn flush(&mut self) -> Result<()> {
        // pcap-file does not expose its inner writer; close performs the durable flush.
        Ok(())
    }
    
    fn close(&mut self) -> Result<()> {
        info!("Closing PCAP writer, {} packets saved", self.packet_count);
        if let Some(writer) = self.writer.take() {
            writer.into_writer().flush().context("Failed to flush PCAP file")?;
        }
        Ok(())
    }
}

fn create_private_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Writer that writes to multiple destinations
pub struct MultiWriter {
    writers: Vec<Box<dyn PacketWriter>>,
}

impl MultiWriter {
    /// Create a new multi-writer
    pub fn new(writers: Vec<Box<dyn PacketWriter>>) -> Self {
        Self { writers }
    }
}

impl PacketWriter for MultiWriter {
    fn write_packet(&mut self, timestamp: DateTime<Utc>, data: &[u8]) -> Result<()> {
        for writer in &mut self.writers {
            writer.write_packet(timestamp, data)?;
        }
        Ok(())
    }
    
    fn flush(&mut self) -> Result<()> {
        for writer in &mut self.writers {
            writer.flush()?;
        }
        Ok(())
    }
    
    fn close(&mut self) -> Result<()> {
        for writer in &mut self.writers {
            writer.close()?;
        }
        Ok(())
    }
}

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
        let store = Arc::new(Mutex::new(PacketStore::new_in_memory(None).unwrap()));
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
        let store = Arc::new(Mutex::new(PacketStore::new_in_memory(None).unwrap()));
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
