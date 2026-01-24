use anyhow::{Context, Result};
use std::io::Write;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{error, info};
use sha2::{Digest, Sha256};

use crate::capture;
use crate::capture::{CaptureConfig, CaptureDriver, CaptureSession};
use crate::config::signatures::{Signatures, TorSignatures, TransferThresholds};
use crate::forensics::ForensicsEngine;
use crate::processing::PacketProcessor;
use crate::storage::PacketStore;
use crate::attribution::{AttributionCache, Flow5Tuple, IpProto as AttrIpProto};

pub mod packetrecorder {
    tonic::include_proto!("packetrecorder.v1");
}

fn enforce_db_path(requested: &str, allowed: &str) -> Result<String, Status> {
    if requested.is_empty() {
        return Ok(allowed.to_string());
    }

    if requested == allowed {
        return Ok(allowed.to_string());
    }

    Err(Status::permission_denied("database_path is not allowed"))
}

use packetrecorder::packet_recorder_server::{PacketRecorder, PacketRecorderServer};
use packetrecorder::*;

#[derive(Clone)]
pub struct GrpcConfig {
    pub default_database_path: String,
    pub max_concurrent_captures: usize,
    pub max_capture_duration_seconds: u64,
    pub max_capture_packets: u64,
    pub max_download_packets: i64,
    pub max_filter_len: usize,
    pub encryption_key: Option<String>,
}

impl GrpcConfig {
    pub fn new(default_database_path: String, encryption_key: Option<String>) -> Self {
        let max_concurrent_captures = std::env::var("PACKETRECORDER_MAX_CONCURRENT_CAPTURES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let max_capture_duration_seconds = std::env::var("PACKETRECORDER_MAX_CAPTURE_DURATION_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);

        let max_capture_packets = std::env::var("PACKETRECORDER_MAX_CAPTURE_PACKETS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5_000_000);

        let max_download_packets = std::env::var("PACKETRECORDER_MAX_DOWNLOAD_PACKETS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2_000_000);

        let max_filter_len = std::env::var("PACKETRECORDER_MAX_FILTER_LEN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4096);

        Self {
            default_database_path,
            max_concurrent_captures,
            max_capture_duration_seconds,
            max_capture_packets,
            max_download_packets,
            max_filter_len,
            encryption_key,
        }
    }
}

#[derive(Clone)]
pub struct ApiKeyConfig {
    pub keys_env: Option<String>,
    pub key_env: Option<String>,
    pub keys_file_env: Option<String>,
}

impl ApiKeyConfig {
    pub fn from_env() -> Self {
        Self {
            keys_env: std::env::var("PACKETRECORDER_API_KEYS").ok(),
            key_env: std::env::var("PACKETRECORDER_API_KEY").ok(),
            keys_file_env: std::env::var("PACKETRECORDER_API_KEYS_FILE").ok(),
        }
    }

    fn load_keys(&self) -> Result<HashSet<String>> {
        let mut keys = HashSet::new();

        if let Some(key) = self.key_env.as_ref() {
            let k = key.trim();
            if !k.is_empty() {
                keys.insert(k.to_string());
            }
        }

        if let Some(keys_env) = self.keys_env.as_ref() {
            for k in keys_env.split(',') {
                let t = k.trim();
                if !t.is_empty() {
                    keys.insert(t.to_string());
                }
            }
        }

        if let Some(path) = self.keys_file_env.as_ref() {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read key file: {}", path))?;
            for line in content.lines() {
                let t = line.trim();
                if !t.is_empty() {
                    keys.insert(t.to_string());
                }
            }
        }

        Ok(keys)
    }

    fn validate_key(&self, key: &str) -> bool {
        if key.len() > 256 {
            return false;
        }
        match self.load_keys() {
            Ok(keys) => keys.contains(key),
            Err(e) => {
                error!("Failed to load API keys: {:?}", e);
                false
            }
        }
    }
}

#[derive(Clone)]
struct CaptureHandle {
    stop: Arc<AtomicBool>,
}

#[derive(Default)]
struct CaptureManager {
    active: Arc<Mutex<HashMap<String, CaptureHandle>>>,
}

impl CaptureManager {
    fn start_capture(&self, req: &StartCaptureRequest, config: &GrpcConfig) -> Result<String> {
        let mut active = self.active.lock().unwrap();
        if active.len() >= config.max_concurrent_captures {
            anyhow::bail!("Too many active captures");
        }

        let db_path = config.default_database_path.clone();

        let store = PacketStore::new(&db_path, config.encryption_key.as_deref()).context("Failed to open database")?;
        let session_id = store
            .create_session(
                &req.interface,
                if req.filter.is_empty() { None } else { Some(req.filter.as_str()) },
            )
            .context("Failed to create database session")?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let capture_config = CaptureConfig {
            driver: CaptureDriver::Pcap,
            interface: req.interface.clone(),
            snaplen: if req.snaplen == 0 { 65535 } else { req.snaplen },
            promisc: req.promisc,
            timeout: 1000,
            buffer_size: if req.buffer_size == 0 { 10 * 1024 * 1024 } else { req.buffer_size },
            filter: if req.filter.is_empty() { None } else { Some(req.filter.clone()) },
        };

        let max_packets = if req.max_packets == 0 {
            config.max_capture_packets
        } else {
            std::cmp::min(req.max_packets, config.max_capture_packets)
        };

        let max_duration_seconds = if req.max_duration_seconds == 0 {
            config.max_capture_duration_seconds
        } else {
            std::cmp::min(req.max_duration_seconds, config.max_capture_duration_seconds)
        };

        let session_id_for_task = session_id.clone();
        let db_path_for_task = db_path.clone();
        let active_for_cleanup = Arc::clone(&self.active);
        let session_id_for_cleanup = session_id.clone();
        let encryption_key = config.encryption_key.clone();
        let join = tokio::task::spawn_blocking(move || {
            if let Err(e) = run_capture_loop(
                capture_config,
                db_path_for_task,
                session_id_for_task,
                stop_clone,
                max_packets,
                max_duration_seconds,
                encryption_key,
            ) {
                error!("Capture loop failed: {:?}", e);
            }
        });

        tokio::spawn(async move {
            let _ = join.await;
            let mut active = active_for_cleanup.lock().unwrap();
            active.remove(&session_id_for_cleanup);
        });

        active.insert(
            session_id.clone(),
            CaptureHandle {
                stop,
            },
        );

        Ok(session_id)
    }

    fn stop_capture(&self, session_id: &str) -> bool {
        let mut active = self.active.lock().unwrap();
        if let Some(handle) = active.remove(session_id) {
            handle.stop.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    fn is_active(&self, session_id: &str) -> bool {
        let active = self.active.lock().unwrap();
        active.contains_key(session_id)
    }
}

fn run_capture_loop(
    config: CaptureConfig,
    db_path: String,
    session_id: String,
    stop: Arc<AtomicBool>,
    max_packets: u64,
    max_duration_seconds: u64,
    encryption_key: Option<String>,
) -> Result<()> {
    let signatures = match Signatures::load("signatures.json") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Failed to load signatures.json: {}", e);
            Signatures {
                tor: TorSignatures {
                    ja3_hashes: HashSet::new(),
                    sni_suffixes: Vec::new(),
                },
                chat: HashMap::new(),
                cloud_storage: HashMap::new(),
                transfer: TransferThresholds {
                    high_volume_threshold_bytes: 0,
                    large_packet_ratio_threshold: 1.0,
                },
            }
        }
    };
    let forensics = ForensicsEngine::new(signatures);
    let mut processor = PacketProcessor::new(forensics);

    let store = PacketStore::new(&db_path, encryption_key.as_deref()).context("Failed to open database")?;

    let mut session = CaptureSession::new(config)
        .context("Failed to create capture session")?;

    info!("Capture started");

    let start_time = std::time::Instant::now();
    let mut packet_count = 0u64;

    loop {
        if stop.load(Ordering::Relaxed) {
            info!("Stopping capture due to stop request");
            break;
        }

        if max_packets > 0 && packet_count >= max_packets {
            info!("Reached max_packets limit");
            break;
        }

        if max_duration_seconds > 0 && start_time.elapsed().as_secs() >= max_duration_seconds {
            info!("Reached max_duration_seconds limit");
            break;
        }

        match session.next_packet() {
            Ok(packet) => {
                let timestamp = chrono::Utc::now();
                let data = packet.data.to_vec();

                if let Err(e) = store.save_packet(&session_id, timestamp, &data) {
                    error!("Failed to save packet: {:?}", e);
                }

                packet_count += 1;

                if let Err(e) = processor.process(timestamp, &data) {
                    error!("Failed to process packet: {:?}", e);
                }
            }
            Err(e) => {
                if e.to_string().contains("timeout") {
                    continue;
                }
                error!("Error capturing packet: {:?}", e);
            }
        }
    }

    store.end_session(&session_id).ok();
    Ok(())
}

#[derive(Clone)]
pub struct PacketRecorderService {
    config: GrpcConfig,
    api_key_config: ApiKeyConfig,
    captures: Arc<CaptureManager>,
    attribution: Arc<AttributionCache>,
    key_file_lock: Arc<Mutex<()>>,
}

impl PacketRecorderService {
    pub fn new(config: GrpcConfig, api_key_config: ApiKeyConfig, attribution: Arc<AttributionCache>) -> Self {
        Self {
            config,
            api_key_config,
            captures: Arc::new(CaptureManager::default()),
            attribution,
            key_file_lock: Arc::new(Mutex::new(())),
        }
    }
}

fn sha256_prefix(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let digest = h.finalize();
    let hexed = hex::encode(digest);
    hexed.chars().take(16).collect()
}

fn read_keys_file(path: &str) -> Result<Vec<String>, Status> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(Status::internal("failed to read keys file")),
    }
}

fn write_keys_file(path: &str, keys: &[String]) -> Result<(), Status> {
    let mut out = String::new();
    for k in keys {
        out.push_str(k);
        out.push('\n');
    }

    let tmp = format!("{}.tmp", path);
    std::fs::write(&tmp, out).map_err(|_| Status::internal("failed to write keys file"))?;
    std::fs::rename(&tmp, path).map_err(|_| Status::internal("failed to commit keys file"))?;
    Ok(())
}

fn parse_flow_tuple(flow: &FlowTuple) -> Result<Flow5Tuple, Status> {
    let proto = match flow.proto() {
        IpProto::Tcp => AttrIpProto::Tcp,
        IpProto::Udp => AttrIpProto::Udp,
        _ => return Err(Status::invalid_argument("proto is required")),
    };

    let src_ip: std::net::IpAddr = flow
        .src_ip
        .parse()
        .map_err(|_| Status::invalid_argument("invalid src_ip"))?;
    let dst_ip: std::net::IpAddr = flow
        .dst_ip
        .parse()
        .map_err(|_| Status::invalid_argument("invalid dst_ip"))?;

    let src_port = u16::try_from(flow.src_port)
        .map_err(|_| Status::invalid_argument("invalid src_port"))?;
    let dst_port = u16::try_from(flow.dst_port)
        .map_err(|_| Status::invalid_argument("invalid dst_port"))?;

    Ok(Flow5Tuple {
        proto,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    })
}

#[tonic::async_trait]
impl PacketRecorder for PacketRecorderService {
    async fn list_interfaces(
        &self,
        _request: Request<ListInterfacesRequest>,
    ) -> Result<Response<ListInterfacesResponse>, Status> {
        let interfaces = capture::list_interfaces().map_err(|e| Status::internal(e.to_string()))?;

        let resp = ListInterfacesResponse {
            interfaces: interfaces
                .into_iter()
                .map(|i| NetworkInterface {
                    name: i.name,
                    description: i.description.unwrap_or_default(),
                    addresses: i.addresses,
                })
                .collect(),
        };

        Ok(Response::new(resp))
    }

    async fn start_capture(
        &self,
        request: Request<StartCaptureRequest>,
    ) -> Result<Response<StartCaptureResponse>, Status> {
        let req = request.into_inner();

        if req.interface.is_empty() {
            return Err(Status::invalid_argument("interface is required"));
        }

        if req.interface.len() > 64 {
            return Err(Status::invalid_argument("interface is too long"));
        }

        if !req.filter.is_empty() && req.filter.len() > self.config.max_filter_len {
            return Err(Status::invalid_argument("filter is too long"));
        }

        if !req.database_path.is_empty() {
            enforce_db_path(&req.database_path, &self.config.default_database_path)?;
        }

        if req.snaplen != 0 && (req.snaplen < 64 || req.snaplen > 65535) {
            return Err(Status::invalid_argument("snaplen out of range"));
        }

        if req.buffer_size != 0 && (req.buffer_size < 1024 * 1024 || req.buffer_size > 256 * 1024 * 1024) {
            return Err(Status::invalid_argument("buffer_size out of range"));
        }

        let session_id = self
            .captures
            .start_capture(&req, &self.config)
            .map_err(|e| Status::resource_exhausted(e.to_string()))?;

        info!("grpc StartCapture session_id={} interface={} filter_present={}", session_id, req.interface, !req.filter.is_empty());

        Ok(Response::new(StartCaptureResponse { session_id }))
    }

    async fn stop_capture(
        &self,
        request: Request<StopCaptureRequest>,
    ) -> Result<Response<StopCaptureResponse>, Status> {
        let session_id = request.into_inner().session_id;
        if session_id.is_empty() {
            return Err(Status::invalid_argument("session_id is required"));
        }

        if uuid::Uuid::parse_str(&session_id).is_err() {
            return Err(Status::invalid_argument("invalid session_id"));
        }

        let stopped = self.captures.stop_capture(&session_id);

        info!("grpc StopCapture session_id={} stopped={}", session_id, stopped);
        Ok(Response::new(StopCaptureResponse { stopped }))
    }

    async fn get_session(
        &self,
        request: Request<GetSessionRequest>,
    ) -> Result<Response<GetSessionResponse>, Status> {
        let req = request.into_inner();

        if uuid::Uuid::parse_str(&req.session_id).is_err() {
            return Err(Status::invalid_argument("invalid session_id"));
        }

        let db_path = enforce_db_path(&req.database_path, &self.config.default_database_path)?;

        let store = PacketStore::new(&db_path, self.config.encryption_key.as_deref()).map_err(|e| Status::internal(e.to_string()))?;
        let session = store
            .get_session(&req.session_id)
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("session not found"))?;

        let resp = GetSessionResponse {
            session: Some(Session {
                id: session.id,
                interface: session.interface,
                filter: session.filter.unwrap_or_default(),
                start_time_rfc3339: session.start_time.to_rfc3339(),
                end_time_rfc3339: session.end_time.map(|t| t.to_rfc3339()).unwrap_or_default(),
                packet_count: session.packet_count,
            }),
        };

        Ok(Response::new(resp))
    }

    async fn list_sessions(
        &self,
        request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let req = request.into_inner();

        let db_path = enforce_db_path(&req.database_path, &self.config.default_database_path)?;

        let store = PacketStore::new(&db_path, self.config.encryption_key.as_deref()).map_err(|e| Status::internal(e.to_string()))?;
        let sessions = store.list_sessions().map_err(|e| Status::internal(e.to_string()))?;

        let resp = ListSessionsResponse {
            sessions: sessions
                .into_iter()
                .map(|s| Session {
                    id: s.id,
                    interface: s.interface,
                    filter: s.filter.unwrap_or_default(),
                    start_time_rfc3339: s.start_time.to_rfc3339(),
                    end_time_rfc3339: s.end_time.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    packet_count: s.packet_count,
                })
                .collect(),
        };

        Ok(Response::new(resp))
    }

    type DownloadPcapStream = ReceiverStream<Result<DownloadPcapResponse, Status>>;

    async fn download_pcap(
        &self,
        request: Request<DownloadPcapRequest>,
    ) -> Result<Response<Self::DownloadPcapStream>, Status> {
        let req = request.into_inner();

        if req.session_id.is_empty() {
            return Err(Status::invalid_argument("session_id is required"));
        }

        if uuid::Uuid::parse_str(&req.session_id).is_err() {
            return Err(Status::invalid_argument("invalid session_id"));
        }

        let db_path = enforce_db_path(&req.database_path, &self.config.default_database_path)?;

        if self.captures.is_active(&req.session_id) {
            return Err(Status::failed_precondition("session is still capturing"));
        }

        let effective_limit = if req.limit_packets > 0 {
            std::cmp::min(req.limit_packets, self.config.max_download_packets)
        } else {
            self.config.max_download_packets
        };

        let (tx, rx) = mpsc::channel::<Result<DownloadPcapResponse, Status>>(16);

        let tx_err = tx.clone();
        let session_id = req.session_id.clone();
        let encryption_key = self.config.encryption_key.clone();
        info!("grpc DownloadPcap session_id={} limit_packets={}", session_id, effective_limit);

        tokio::task::spawn_blocking(move || {
            if let Err(e) = stream_pcap_from_db(&db_path, &session_id, effective_limit, tx, encryption_key.as_deref()) {
                error!("PCAP stream failed: {:?}", e);
                let _ = tx_err.blocking_send(Err(Status::internal("pcap stream failed")));
            }
        });

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(stream))
    }

    async fn lookup_attribution(
        &self,
        request: Request<LookupAttributionRequest>,
    ) -> Result<Response<LookupAttributionResponse>, Status> {
        let req = request.into_inner();
        let Some(flow) = req.flow.as_ref() else {
            return Err(Status::invalid_argument("flow is required"));
        };

        let tuple = parse_flow_tuple(flow)?;
        let attr = self.attribution.lookup(&tuple);

        let resp = if let Some(attr) = attr {
            LookupAttributionResponse {
                found: true,
                attribution: Some(ProcessAttribution {
                    pid: attr.pid,
                    uid: attr.uid.unwrap_or(0),
                    process: attr.process,
                    bundle_id: attr.bundle_id.unwrap_or_default(),
                    signing_id: attr.signing_id.unwrap_or_default(),
                    timestamp_rfc3339: attr.timestamp_rfc3339.unwrap_or_default(),
                }),
            }
        } else {
            LookupAttributionResponse {
                found: false,
                attribution: None,
            }
        };

        Ok(Response::new(resp))
    }

    async fn list_api_keys(
        &self,
        _request: Request<ListApiKeysRequest>,
    ) -> Result<Response<ListApiKeysResponse>, Status> {
        let mut keys: Vec<ApiKeyInfo> = Vec::new();

        if let Some(k) = self.api_key_config.key_env.as_ref() {
            let t = k.trim();
            if !t.is_empty() {
                keys.push(ApiKeyInfo {
                    sha256_prefix: sha256_prefix(t),
                    source: "env".to_string(),
                });
            }
        }

        if let Some(env_keys) = self.api_key_config.keys_env.as_ref() {
            for k in env_keys.split(',') {
                let t = k.trim();
                if !t.is_empty() {
                    keys.push(ApiKeyInfo {
                        sha256_prefix: sha256_prefix(t),
                        source: "env".to_string(),
                    });
                }
            }
        }

        if let Some(path) = self.api_key_config.keys_file_env.as_ref() {
            let file_keys = read_keys_file(path)?;
            for k in file_keys {
                keys.push(ApiKeyInfo {
                    sha256_prefix: sha256_prefix(&k),
                    source: "file".to_string(),
                });
            }
        }

        Ok(Response::new(ListApiKeysResponse { keys }))
    }

    async fn add_api_key(
        &self,
        request: Request<AddApiKeyRequest>,
    ) -> Result<Response<AddApiKeyResponse>, Status> {
        let Some(path) = self.api_key_config.keys_file_env.as_ref() else {
            return Err(Status::failed_precondition("PACKETRECORDER_API_KEYS_FILE is not configured"));
        };

        let key = request.into_inner().key;
        let key = key.trim();
        if key.is_empty() {
            return Err(Status::invalid_argument("key is required"));
        }
        if key.len() > 256 {
            return Err(Status::invalid_argument("key is too long"));
        }

        let _guard = self.key_file_lock.lock().unwrap();
        let mut keys = read_keys_file(path)?;
        if !keys.iter().any(|k| k == key) {
            keys.push(key.to_string());
            write_keys_file(path, &keys)?;
        }

        Ok(Response::new(AddApiKeyResponse {
            sha256_prefix: sha256_prefix(key),
        }))
    }

    async fn remove_api_key(
        &self,
        request: Request<RemoveApiKeyRequest>,
    ) -> Result<Response<RemoveApiKeyResponse>, Status> {
        let Some(path) = self.api_key_config.keys_file_env.as_ref() else {
            return Err(Status::failed_precondition("PACKETRECORDER_API_KEYS_FILE is not configured"));
        };

        let key = request.into_inner().key;
        let key = key.trim();
        if key.is_empty() {
            return Err(Status::invalid_argument("key is required"));
        }
        if key.len() > 256 {
            return Err(Status::invalid_argument("key is too long"));
        }

        let _guard = self.key_file_lock.lock().unwrap();
        let mut keys = read_keys_file(path)?;
        let before = keys.len();
        keys.retain(|k| k != key);
        let removed = keys.len() != before;
        if removed {
            write_keys_file(path, &keys)?;
        }

        Ok(Response::new(RemoveApiKeyResponse {
            removed,
            sha256_prefix: sha256_prefix(key),
        }))
    }
}

fn stream_pcap_from_db(
    db_path: &str,
    session_id: &str,
    limit_packets: i64,
    tx: mpsc::Sender<Result<DownloadPcapResponse, Status>>,
    encryption_key: Option<&str>,
) -> Result<()> {
    struct ChunkingWriter {
        tx: mpsc::Sender<Result<DownloadPcapResponse, Status>>,
        buf: Vec<u8>,
        threshold: usize,
    }

    impl std::io::Write for ChunkingWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.buf.extend_from_slice(data);
            if self.buf.len() >= self.threshold {
                let chunk = std::mem::take(&mut self.buf);
                let _ = self.tx.blocking_send(Ok(DownloadPcapResponse { chunk }));
            }
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if !self.buf.is_empty() {
                let chunk = std::mem::take(&mut self.buf);
                let _ = self.tx.blocking_send(Ok(DownloadPcapResponse { chunk }));
            }
            Ok(())
        }
    }

    let store = PacketStore::new(db_path, encryption_key)?;

    let limit = if limit_packets > 0 { Some(limit_packets) } else { None };

    let mut out = ChunkingWriter {
        tx,
        buf: Vec::with_capacity(64 * 1024),
        threshold: 64 * 1024,
    };

    write_pcap_global_header(&mut out)?;

    store.for_each_packet(session_id, limit, |timestamp, data| {
        write_pcap_packet(&mut out, timestamp, &data)
    })?;

    out.flush()?;

    Ok(())
}

fn write_pcap_global_header<W: std::io::Write>(w: &mut W) -> Result<()> {
    let mut hdr = [0u8; 24];
    hdr[0..4].copy_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    hdr[4..6].copy_from_slice(&2u16.to_le_bytes());
    hdr[6..8].copy_from_slice(&4u16.to_le_bytes());
    hdr[8..12].copy_from_slice(&0i32.to_le_bytes());
    hdr[12..16].copy_from_slice(&0u32.to_le_bytes());
    hdr[16..20].copy_from_slice(&65535u32.to_le_bytes());
    hdr[20..24].copy_from_slice(&1u32.to_le_bytes());
    w.write_all(&hdr).context("Failed to write pcap global header")?;
    Ok(())
}

fn write_pcap_packet<W: std::io::Write>(w: &mut W, timestamp: chrono::DateTime<chrono::Utc>, data: &[u8]) -> Result<()> {
    let ts_sec = std::cmp::max(0, timestamp.timestamp());
    let ts_usec = timestamp.timestamp_subsec_micros();
    let incl_len = data.len() as u32;

    let mut phdr = [0u8; 16];
    phdr[0..4].copy_from_slice(&(ts_sec as u32).to_le_bytes());
    phdr[4..8].copy_from_slice(&(ts_usec as u32).to_le_bytes());
    phdr[8..12].copy_from_slice(&incl_len.to_le_bytes());
    phdr[12..16].copy_from_slice(&incl_len.to_le_bytes());

    w.write_all(&phdr).context("Failed to write pcap packet header")?;
    w.write_all(data).context("Failed to write pcap packet data")?;
    Ok(())
}

pub async fn serve_grpc(addr: SocketAddr, svc: PacketRecorderService) -> Result<()> {
    let api_key_config = svc.api_key_config.clone();

    let interceptor = move |req: Request<()>| -> Result<Request<()>, Status> {
        let key = if let Some(v) = req.metadata().get("x-api-key") {
            v.to_str().ok().map(|s| s.to_string())
        } else if let Some(v) = req.metadata().get("authorization") {
            v.to_str()
                .ok()
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(|s| s.to_string())
        } else {
            None
        };

        let Some(key) = key else {
            return Err(Status::unauthenticated("missing api key"));
        };

        if !api_key_config.validate_key(&key) {
            return Err(Status::permission_denied("invalid api key"));
        }

        Ok(req)
    };

    info!("gRPC server listening on {}", addr);

    tonic::transport::Server::builder()
        .add_service(PacketRecorderServer::with_interceptor(svc, interceptor))
        .serve(addr)
        .await
        .context("gRPC server failed")
}
