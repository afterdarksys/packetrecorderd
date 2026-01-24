use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpProto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Flow5Tuple {
    pub proto: IpProto,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl Flow5Tuple {
    pub fn reverse(&self) -> Self {
        Self {
            proto: self.proto,
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAttribution {
    pub pid: i32,
    pub uid: Option<u32>,
    pub process: String,
    pub bundle_id: Option<String>,
    pub signing_id: Option<String>,
    pub timestamp_rfc3339: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionEvent {
    pub flow: Flow5Tuple,
    pub process: ProcessAttribution,
}

#[derive(Debug, Default)]
pub struct AttributionCache {
    inner: RwLock<HashMap<Flow5Tuple, ProcessAttribution>>,
}

impl AttributionCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&self, flow: Flow5Tuple, process: ProcessAttribution) {
        {
            let mut map = self.inner.write().unwrap();
            map.insert(flow.clone(), process.clone());
            map.insert(flow.reverse(), process);
        }
    }

    pub fn lookup(&self, flow: &Flow5Tuple) -> Option<ProcessAttribution> {
        let map = self.inner.read().unwrap();
        map.get(flow).cloned()
    }
}

pub async fn run_unix_socket_listener(path: &str, cache: Arc<AttributionCache>) -> Result<()> {
    let _ = std::fs::remove_file(path);

    let listener = UnixListener::bind(path)
        .with_context(|| format!("Failed to bind attribution unix socket: {}", path))?;

    info!("Attribution listener on unix socket: {}", path);

    loop {
        let (stream, _) = listener.accept().await?;
        let cache = Arc::clone(&cache);

        tokio::spawn(async move {
            let reader = BufReader::new(stream);
            let mut lines = reader.lines();

            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                match serde_json::from_str::<AttributionEvent>(line) {
                    Ok(evt) => {
                        cache.upsert(evt.flow, evt.process);
                    }
                    Err(e) => {
                        warn!("Failed to parse attribution event: {}", e);
                    }
                }
            }
        });
    }
}

pub fn now_rfc3339() -> String {
    let ts: DateTime<Utc> = Utc::now();
    ts.to_rfc3339()
}
