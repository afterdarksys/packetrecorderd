#![allow(dead_code)]
use anyhow::{Context, Result};
use pcap::{Active, Capture, Device, Packet};
use tracing::info;

pub mod writer;

/// Represents a network interface available for capture
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
}

/// Lists all available network interfaces
pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
    let devices = Device::list().context("Failed to list network devices")?;
    
    let interfaces = devices
        .into_iter()
        .map(|device| {
            let addresses = device
                .addresses
                .iter()
                .map(|addr| addr.addr.to_string())
                .collect();
            
            NetworkInterface {
                name: device.name,
                description: device.desc,
                addresses,
            }
        })
        .collect();
    
    Ok(interfaces)
}

/// Configuration for packet capture
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub interface: String,
    pub snaplen: i32,
    pub promisc: bool,
    pub timeout: i32,
    pub buffer_size: i32,
    pub filter: Option<String>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            snaplen: 65535,  // Maximum packet size
            promisc: true,    // Promiscuous mode
            timeout: 1000,    // 1 second
            buffer_size: 10 * 1024 * 1024,  // 10MB buffer
            filter: None,
        }
    }
}

/// Packet capture session
pub struct CaptureSession {
    capture: Capture<Active>,
    config: CaptureConfig,
}

impl CaptureSession {
    /// Create a new capture session
    pub fn new(config: CaptureConfig) -> Result<Self> {
        info!("Opening capture on interface: {}", config.interface);
        
        let mut capture = Capture::from_device(config.interface.as_str())
            .context("Failed to open capture device")?
            .snaplen(config.snaplen)
            .promisc(config.promisc)
            .timeout(config.timeout)
            .buffer_size(config.buffer_size)
            .open()
            .context("Failed to activate capture")?;
        
        // Apply BPF filter if provided
        if let Some(ref filter) = config.filter {
            info!("Applying BPF filter: {}", filter);
            capture
                .filter(filter, true)
                .context("Failed to apply BPF filter")?;
        }
        
        Ok(Self { capture, config })
    }
    
    /// Get the next packet from the capture
    pub fn next_packet(&mut self) -> Result<Packet<'_>> {
        self.capture
            .next_packet()
            .context("Failed to get next packet")
    }
    
    /// Get capture statistics
    pub fn stats(&mut self) -> Result<pcap::Stat> {
        self.capture.stats().context("Failed to get capture stats")
    }
    
    /// Get the configuration used for this session
    pub fn config(&self) -> &CaptureConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_list_interfaces() {
        let interfaces = list_interfaces();
        assert!(interfaces.is_ok());
        let interfaces = interfaces.unwrap();
        assert!(!interfaces.is_empty(), "Should have at least one interface");
        
        for iface in interfaces {
            println!("Interface: {} ({:?})", iface.name, iface.description);
        }
    }
}
