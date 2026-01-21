use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use anyhow::{Context, Result};

#[derive(Debug, Deserialize, Clone)]
pub struct Signatures {
    pub tor: TorSignatures,
    pub chat: HashMap<String, ChatProtocol>,
    pub cloud_storage: HashMap<String, CloudStorageProtocol>,
    pub transfer: TransferThresholds,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TorSignatures {
    pub ja3_hashes: HashSet<String>,
    pub sni_suffixes: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChatProtocol {
    pub sni_suffixes: Vec<String>,
    pub ports: HashSet<u16>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CloudStorageProtocol {
    pub sni_suffixes: Vec<String>,
    pub ports: HashSet<u16>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TransferThresholds {
    pub high_volume_threshold_bytes: u64,
    pub large_packet_ratio_threshold: f64,
}

impl Signatures {
    pub fn load(path: &str) -> Result<Self> {
        let file = File::open(path).context("Failed to open signatures file")?;
        let reader = BufReader::new(file);
        let signatures = serde_json::from_reader(reader).context("Failed to parse signatures JSON")?;
        Ok(signatures)
    }
}
