mod capture;
mod cli;
mod replay;
mod storage;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber;

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
    
    info!("Starting packet capture on interface: {}", args.interface);
    
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
                
                if let Err(e) = writer.write_packet(timestamp, data).await {
                    error!("Failed to write packet: {:?}", e);
                }
                
                packet_count += 1;
                
                if packet_count % 1000 == 0 {
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
