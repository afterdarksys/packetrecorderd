mod capture;
mod cli;
mod replay;
mod storage;
mod protocols;
mod config;
mod forensics;
mod decoders;
mod analysis;
mod processing;
mod metrics;
mod api;
mod grpc;
mod attribution;
mod manage;
mod model_manifest;
mod model_client;
mod ml;
mod swarm;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tracing::{error, info};
use cli::{Cli, Commands};
use storage::PacketStore;
use attribution::{AttributionCache, run_unix_socket_listener};
use crossbeam_channel::{unbounded, Sender, Receiver};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use chrono::DateTime;

fn get_flow_hash(packet: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    if let Ok(sliced) = etherparse::SlicedPacket::from_ethernet(packet) {
        if let Some(ref net) = sliced.net {
            match net {
                etherparse::NetSlice::Ipv4(ipv4) => {
                    let mut src = ipv4.header().source();
                    let mut dst = ipv4.header().destination();
                    if src > dst { std::mem::swap(&mut src, &mut dst); }
                    src.hash(&mut hasher);
                    dst.hash(&mut hasher);
                    ipv4.header().protocol().hash(&mut hasher);
                },
                etherparse::NetSlice::Ipv6(ipv6) => {
                    let mut src = ipv6.header().source();
                    let mut dst = ipv6.header().destination();
                    if src > dst { std::mem::swap(&mut src, &mut dst); }
                    src.hash(&mut hasher);
                    dst.hash(&mut hasher);
                    ipv6.header().next_header().hash(&mut hasher);
                }
            }
        }
        
        if let Some(ref transport) = sliced.transport {
            match transport {
                 etherparse::TransportSlice::Tcp(tcp) => {
                     let mut src = tcp.source_port();
                     let mut dst = tcp.destination_port();
                     if src > dst { std::mem::swap(&mut src, &mut dst); }
                     src.hash(&mut hasher);
                     dst.hash(&mut hasher);
                 },
                 etherparse::TransportSlice::Udp(udp) => {
                     let mut src = udp.source_port();
                     let mut dst = udp.destination_port();
                     if src > dst { std::mem::swap(&mut src, &mut dst); }
                     src.hash(&mut hasher);
                     dst.hash(&mut hasher);
                 },
                 _ => {}
            }
        }
    }
    hasher.finish()
}

#[tokio::main]
async fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();
    
    // Initialize tracing
    let log_level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();
    
    // Initialize metrics
    metrics::register_metrics();
    
    // Execute command
    if let Err(e) = run_command(cli.command, cli.encryption_key).await {
        error!("Error: {:?}", e);
        std::process::exit(1);
    }
}

async fn run_command(command: Commands, encryption_key: Option<String>) -> Result<()> {
    match command {
        Commands::ListInterfaces => cmd_list_interfaces(),
        Commands::Capture(args) => cmd_capture(args, encryption_key).await,
        Commands::Replay(args) => cmd_replay(args, encryption_key).await,
        Commands::Query(args) => cmd_query(args, encryption_key),
        Commands::Sessions(args) => cmd_sessions(args, encryption_key),
        Commands::Export(args) => cmd_export(args, encryption_key),
        Commands::Manage(args) => manage::cmd_manage(args).await,
        Commands::Serve(args) => cmd_serve(args, encryption_key).await,
    }
}

async fn cmd_serve(args: cli::ServeArgs, encryption_key: Option<String>) -> Result<()> {
    let addr: std::net::SocketAddr = args.grpc_addr.parse()
        .context("Failed to parse grpc_addr")?;

    let http_addr: std::net::SocketAddr = args.http_addr.parse()
        .context("Failed to parse http_addr")?;

    let config = grpc::GrpcConfig::new(args.database.to_string_lossy().to_string(), encryption_key.clone());

    let api_store = PacketStore::new(&config.default_database_path, encryption_key.as_deref())
        .context("Failed to open database for HTTP API")?;
    let api_state = api::ApiState::new(Arc::new(Mutex::new(api_store)));
    tokio::spawn(async move {
        api::serve(http_addr, api_state).await;
    });

    let attribution_cache = Arc::new(AttributionCache::new());
    if let Ok(sock_path) = std::env::var("PACKETRECORDER_ATTRIBUTION_SOCKET") {
        if !sock_path.trim().is_empty() {
            let cache = Arc::clone(&attribution_cache);
            tokio::spawn(async move {
                if let Err(e) = run_unix_socket_listener(&sock_path, cache).await {
                    tracing::error!("attribution listener failed: {:?}", e);
                }
            });
        }
    }

    let api_key_config = grpc::ApiKeyConfig::from_env();
    let svc = grpc::PacketRecorderService::new(config, api_key_config, attribution_cache);

    grpc::serve_grpc(addr, svc).await
}

fn cmd_list_interfaces() -> Result<()> {
    let interfaces = capture::list_interfaces()
        .context("Failed to list network interfaces")?;
    
    if interfaces.is_empty() {
        println!("No network interfaces found");
        return Ok(());
    }
    
    println!("Available network interfaces:\n");
    for iface in interfaces {
        println!("  {}", iface.name);
        if let Some(desc) = iface.description {
            println!("    Description: {}", desc);
        }
        if !iface.addresses.is_empty() {
            println!("    Addresses: {}", iface.addresses.join(", "));
        }
        println!();
    }
    
    Ok(())
}

async fn cmd_capture(args: cli::CaptureArgs, encryption_key: Option<String>) -> Result<()> {
    use capture::writer::{AsyncPacketWriter, DatabaseWriter, PcapWriter, MultiWriter};
    use capture::{CaptureConfig, CaptureSession};
    use config::signatures::Signatures;
    use forensics::ForensicsEngine;
    use processing::PacketProcessor;
    use std::thread;
    
    info!("Starting packet capture on interface: {}", args.interface);

    // Load signatures
    let signatures = match Signatures::load("signatures.json") {
        Ok(s) => {
            info!("Loaded signatures from signatures.json");
            s
        },
        Err(e) => {
            tracing::warn!("Failed to load signatures.json: {}. Forensics will be limited.", e);
            return Err(e);
        }
    };

    let forensics = ForensicsEngine::new(signatures);
    
    // Open database
    let store = Arc::new(Mutex::new(PacketStore::new(&args.database, encryption_key.as_deref())
        .context("Failed to open database")?));
    
    // Create writer(s)
    let db_writer = DatabaseWriter::new(
        store.clone(),
        &args.interface,
        args.filter.as_deref(),
    )?;
    let session_id = db_writer.session_id().to_string();
    info!("Created capture session: {}", session_id);
    
    // Set up writer (database + optional PCAP)
    let writer: AsyncPacketWriter = if let Some(pcap_path) = &args.pcap {
        let pcap_writer = PcapWriter::new(pcap_path)
            .context("Failed to create PCAP writer")?;
        info!("Writing packets to PCAP file: {:?}", pcap_path);
        
        let multi = MultiWriter::new(vec![
            Box::new(db_writer),
            Box::new(pcap_writer),
        ]);
        AsyncPacketWriter::new(Box::new(multi))
    } else {
        AsyncPacketWriter::new(Box::new(db_writer))
    };
    
    // Initialize Worker Pool
    let num_threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    info!("Initializing worker pool with {} threads", num_threads);
    
    let mut senders = Vec::new();
    let mut handles = Vec::new();
    
    for i in 0..num_threads {
        let (tx, rx): (Sender<(DateTime<Utc>, Vec<u8>)>, Receiver<(DateTime<Utc>, Vec<u8>)>) = unbounded();
        senders.push(tx);
        
        // Clone forensics for sharing
        let forensics_clone = forensics.clone();
        
        // Spawn worker
        let handle = thread::spawn(move || {
            let mut processor = PacketProcessor::new(forensics_clone);
            info!("Worker {} started", i);
            
            while let Ok((timestamp, data)) = rx.recv() {
                if let Err(e) = processor.process(timestamp, &data) {
                    error!("Worker {} error: {:?}", i, e);
                }
            }
            info!("Worker {} stopped", i);
        });
        handles.push(handle);
    }
    
    // Configure capture
    let config = CaptureConfig {
        driver: capture::CaptureDriver::Pcap,
        interface: args.interface.clone(),
        snaplen: args.snaplen,
        promisc: args.promisc,
        timeout: 1000,
        buffer_size: args.buffer_size,
        filter: args.filter.clone(),
    };
    
    // Start capture session
    let mut session = CaptureSession::new(config)
        .context("Failed to create capture session")?;
    
    info!("Capture started. Press Ctrl+C to stop.");
    
    let mut packet_count = 0u64;
    let start_time = std::time::Instant::now();
    
    // Set up Ctrl+C handler
    let writer_clone = writer.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Stopping capture...");
        // In a real app, we might want to signal workers to stop here
        if let Err(e) = writer_clone.close().await {
            error!("Failed to close writer: {:?}", e);
        }
        std::process::exit(0);
    });
    
    // Capture loop
    loop {
        match session.next_packet() {
            Ok(packet) => {
                let timestamp = Utc::now();
                let data = packet.data.to_vec();
                
                // 1. Write packet (I/O bound, async)
                if let Err(e) = writer.write_packet(timestamp, data.clone()).await {
                    error!("Failed to write packet: {:?}", e);
                }

                packet_count += 1;
                
                // 2. Dispatch to worker (CPU bound)
                // Shard based on flow hash to ensure same flow goes to same worker
                // (Preserves flow state/context)
                let hash = get_flow_hash(&data);
                let worker_idx = (hash as usize) % num_threads;
                
                if let Err(e) = senders[worker_idx].send((timestamp, data)) {
                    error!("Failed to send packet to worker {}: {:?}", worker_idx, e);
                }
                
                if packet_count.is_multiple_of(1000) {
                    info!("Captured {} packets", packet_count);
                }
                
                // Check limits
                if args.count > 0 && packet_count >= args.count {
                    info!("Reached packet count limit: {}", args.count);
                    break;
                }
                
                if args.duration > 0 && start_time.elapsed().as_secs() >= args.duration {
                    info!("Reached time limit: {} seconds", args.duration);
                    break;
                }
            }
            Err(e) => {
                // Timeout is normal, just continue
                if e.to_string().contains("timeout") {
                    continue;
                }
                error!("Error capturing packet: {:?}", e);
            }
        }
    }
    
    // Cleanup
    drop(senders); // Close channels to stop workers
    for handle in handles {
        let _ = handle.join();
    }
    
    writer.close().await?;
    info!("Capture complete: {} packets captured", packet_count);
    println!("\nSession ID: {}", session_id);
    
    Ok(())
}

async fn cmd_replay(args: cli::ReplayArgs, encryption_key: Option<String>) -> Result<()> {
    use replay::{ReplayConfig, ReplaySession};
    
    let store = Arc::new(Mutex::new(PacketStore::new(&args.database, encryption_key.as_deref())
        .context("Failed to open database")?));
    
    let config = ReplayConfig {
        speed: args.speed,
        max_packets: args.count,
        display_only: args.display_only || args.interface.is_none(),
    };
    
    let mut session = ReplaySession::new(store, args.session.clone(), config)?;
    
    info!("Starting replay of session: {}", args.session);
    let stats = session.replay().await?;
    
    println!("\nReplay Statistics:");
    println!("  Packets replayed: {}", stats.packets_replayed);
    println!("  Bytes replayed: {}", stats.bytes_replayed);
    println!("  Elapsed time: {} seconds", stats.elapsed_time.num_seconds());
    
    Ok(())
}

fn cmd_query(args: cli::QueryArgs, encryption_key: Option<String>) -> Result<()> {
    let store = PacketStore::new(&args.database, encryption_key.as_deref())
        .context("Failed to open database")?;
    
    let session = store.get_session(&args.session)?
        .ok_or_else(|| anyhow::anyhow!("Session not found: {}", args.session))?;
    
    println!("Session: {}", session.id);
    println!("  Interface: {}", session.interface);
    if let Some(filter) = &session.filter {
        println!("  Filter: {}", filter);
    }
    println!("  Start time: {}", session.start_time);
    if let Some(end_time) = session.end_time {
        println!("  End time: {}", end_time);
    }
    println!("  Total packets: {}", session.packet_count);
    println!();
    
    let packets = store.get_packets(&args.session, Some(args.limit))?;
    
    if packets.is_empty() {
        println!("No packets found");
        return Ok(());
    }
    
    println!("Packets (showing up to {}):", args.limit);
    for packet in packets {
        println!(
            "  [{}] {} bytes",
            packet.timestamp.format("%Y-%m-%d %H:%M:%S"),
            packet.length
        );
        
        if args.show_data {
            print!("    ");
            for (i, byte) in packet.data.iter().enumerate() {
                print!("{:02x} ", byte);
                if (i + 1) % 16 == 0 {
                    println!();
                    print!("    ");
                }
            }
            println!();
        }
    }
    
    Ok(())
}

fn cmd_sessions(args: cli::SessionsArgs, encryption_key: Option<String>) -> Result<()> {
    let store = PacketStore::new(&args.database, encryption_key.as_deref())
        .context("Failed to open database")?;
    
    let sessions = store.list_sessions()?;
    
    if sessions.is_empty() {
        println!("No sessions found");
        return Ok(());
    }
    
    println!("Capture Sessions:\n");
    for session in sessions {
        println!("  ID: {}", session.id);
        println!("    Interface: {}", session.interface);
        if let Some(filter) = &session.filter {
            println!("    Filter: {}", filter);
        }
        println!("    Start: {}", session.start_time.format("%Y-%m-%d %H:%M:%S"));
        if let Some(end_time) = session.end_time {
            println!("    End: {}", end_time.format("%Y-%m-%d %H:%M:%S"));
        } else {
            println!("    Status: In progress");
        }
        println!("    Packets: {}", session.packet_count);
        println!();
    }
    
    Ok(())
}

fn cmd_export(args: cli::ExportArgs, encryption_key: Option<String>) -> Result<()> {
    use capture::writer::{PcapWriter, PacketWriter};
    
    info!("Exporting session {} to PCAP file: {:?}", args.session, args.output);
    
    let store = PacketStore::new(&args.database, encryption_key.as_deref())
        .context("Failed to open database")?;
    
    // Verify session exists
    let session = store.get_session(&args.session)?
        .ok_or_else(|| anyhow::anyhow!("Session not found: {}", args.session))?;
    
    info!("Found session with {} packets", session.packet_count);
    
    // Create PCAP writer
    let mut pcap_writer = PcapWriter::new(&args.output)
        .context("Failed to create PCAP writer")?;
    
    // Get packets from database
    let limit = if args.limit > 0 { Some(args.limit) } else { None };
    let packets = store.get_packets(&args.session, limit)?;
    
    println!("Exporting {} packets...", packets.len());
    
    // Write packets to PCAP
    for (i, packet) in packets.iter().enumerate() {
        pcap_writer.write_packet(packet.timestamp, &packet.data)?;
        
        if (i + 1) % 1000 == 0 {
            print!("\rExported {}/{} packets", i + 1, packets.len());
            use std::io::Write;
            std::io::stdout().flush()?;
        }
    }
    
    pcap_writer.close()?;
    
    println!("\n\nSuccessfully exported {} packets to {:?}", packets.len(), args.output);
    println!("You can now open this file in Wireshark or tcpdump");
    
    Ok(())
}
