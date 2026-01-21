mod capture;
mod cli;
mod replay;
mod storage;
mod protocols;
mod config;
mod forensics;
mod decoders;
mod analysis;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tracing::{error, info};
use cli::{Cli, Commands};
use storage::PacketStore;

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
    
    // Execute command
    if let Err(e) = run_command(cli.command).await {
        error!("Error: {:?}", e);
        std::process::exit(1);
    }
}

async fn run_command(command: Commands) -> Result<()> {
    match command {
        Commands::ListInterfaces => cmd_list_interfaces(),
        Commands::Capture(args) => cmd_capture(args).await,
        Commands::Replay(args) => cmd_replay(args).await,
        Commands::Query(args) => cmd_query(args),
        Commands::Sessions(args) => cmd_sessions(args),
    }
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

async fn cmd_capture(args: cli::CaptureArgs) -> Result<()> {
    use capture::writer::{AsyncPacketWriter, DatabaseWriter};
    use capture::{CaptureConfig, CaptureSession};
    use config::signatures::Signatures;
    use forensics::{ForensicsEngine, ForensicsAlert};
use protocols::{tls::TlsParser, ldap::LdapParser, netbios::NetbiosParser, ProtocolParser};
    
    info!("Starting packet capture on interface: {}", args.interface);

    // Load signatures
    let signatures = match Signatures::load("signatures.json") {
        Ok(s) => {
            info!("Loaded signatures from signatures.json");
            s
        },
        Err(e) => {
            tracing::warn!("Failed to load signatures.json: {}. Forensics will be limited.", e);
            // Return or create default/empty signatures? 
            // For now, let's just fail if we can't load, or maybe make it optional.
            // But the user requested this feature.
            return Err(e);
        }
    };

    let forensics = ForensicsEngine::new(signatures);
    let tls_parser = TlsParser::new();
    let ldap_parser = LdapParser::new();
    let netbios_parser = NetbiosParser::new();
    
    // Open database
    let store = Arc::new(Mutex::new(PacketStore::new(&args.database)
        .context("Failed to open database")?));
    
    // Create writer
    let db_writer = DatabaseWriter::new(
        store.clone(),
        &args.interface,
        args.filter.as_deref(),
    )?;
    let session_id = db_writer.session_id().to_string();
    info!("Created capture session: {}", session_id);
    
    let writer = AsyncPacketWriter::new(Box::new(db_writer));
    
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
                
                if let Err(e) = writer.write_packet(timestamp, data.clone()).await {
                    error!("Failed to write packet: {:?}", e);
                }

                packet_count += 1;
                
                // Analysis
    if let Ok(sliced) = etherparse::SlicedPacket::from_ethernet(&data) {
        let mut src_ip = "0.0.0.0".to_string();
        let mut dst_ip = "0.0.0.0".to_string();
        let mut src_port = 0;
        let mut dst_port = 0;
        let mut payload: &[u8] = &[];

        if let Some(net) = sliced.net {
            match net {
                etherparse::NetSlice::Ipv4(ipv4) => {
                    src_ip = std::net::Ipv4Addr::from(ipv4.header().source()).to_string();
                    dst_ip = std::net::Ipv4Addr::from(ipv4.header().destination()).to_string();
                },
                etherparse::NetSlice::Ipv6(ipv6) => {
                    src_ip = std::net::Ipv6Addr::from(ipv6.header().source()).to_string();
                    dst_ip = std::net::Ipv6Addr::from(ipv6.header().destination()).to_string();
                }
            }
        }

        if let Some(transport) = sliced.transport {
                match transport {
                    etherparse::TransportSlice::Tcp(tcp) => {
                        src_port = tcp.source_port();
                        dst_port = tcp.destination_port();
                        payload = tcp.payload();
                    },
                    etherparse::TransportSlice::Udp(udp) => {
                        src_port = udp.source_port();
                        dst_port = udp.destination_port();
                        payload = udp.payload();
                    },
                    _ => {}
                }
        }

                    if !payload.is_empty() {
                         // Protocol detection chain
                         let mut protocol_info = protocols::ProtocolInfo::Unknown;
                         
                         // Try TLS
                         if let Ok(info) = tls_parser.parse(payload) {
                             if !matches!(info, protocols::ProtocolInfo::Unknown) {
                                 protocol_info = info;
                             }
                         }
                         
                         // Try LDAP if unknown
                         if matches!(protocol_info, protocols::ProtocolInfo::Unknown) {
                             if let Ok(info) = ldap_parser.parse(payload) {
                                 if !matches!(info, protocols::ProtocolInfo::Unknown) {
                                     protocol_info = info;
                                 }
                             }
                         }

                         // Try NetBIOS if unknown
                         if matches!(protocol_info, protocols::ProtocolInfo::Unknown) {
                             if let Ok(info) = netbios_parser.parse(payload) {
                                 if !matches!(info, protocols::ProtocolInfo::Unknown) {
                                     protocol_info = info;
                                 }
                             }
                         }

                         let alerts = forensics.analyze(&src_ip, &dst_ip, src_port, dst_port, &protocol_info, data.len());
                         for alert in alerts {
                             match alert {
                                 ForensicsAlert::TorDetected { src_ip, dst_ip, reason } => {
                                     tracing::warn!("TOR DETECTED: {} -> {}: {}", src_ip, dst_ip, reason);
                                 },
                                 ForensicsAlert::ChatDetected { src_ip, dst_ip, app, protocol } => {
                                     info!("CHAT DETECTED: {} -> {}: App={}, Proto={}", src_ip, dst_ip, app, protocol);
                                 },
                                 ForensicsAlert::CloudStorageDetected { src_ip, dst_ip, service } => {
                                     tracing::warn!("CLOUD STORAGE DETECTED: {} -> {}: Service={}", src_ip, dst_ip, service);
                                 },
                                 ForensicsAlert::HighVolumeTransfer { src_ip, dst_ip, bytes } => {
                                     info!("TRANSFER DETECTED: {} -> {}: {} bytes", src_ip, dst_ip, bytes);
                                 }
                             }
                         }
                    }
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
    
    writer.close().await?;
    info!("Capture complete: {} packets captured", packet_count);
    println!("\nSession ID: {}", session_id);
    
    Ok(())
}

async fn cmd_replay(args: cli::ReplayArgs) -> Result<()> {
    use replay::{ReplayConfig, ReplaySession};
    
    let store = Arc::new(Mutex::new(PacketStore::new(&args.database)
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

fn cmd_query(args: cli::QueryArgs) -> Result<()> {
    let store = PacketStore::new(&args.database)
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

fn cmd_sessions(args: cli::SessionsArgs) -> Result<()> {
    let store = PacketStore::new(&args.database)
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
