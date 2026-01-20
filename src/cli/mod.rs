use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "packetrecorder")]
#[command(about = "A network packet capture and replay daemon", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List available network interfaces
    ListInterfaces,
    
    /// Capture packets from a network interface
    Capture(CaptureArgs),
    
    /// Replay captured packets
    Replay(ReplayArgs),
    
    /// Query and display captured packets
    Query(QueryArgs),
    
    /// List capture sessions
    Sessions(SessionsArgs),
}

#[derive(Parser, Debug)]
pub struct CaptureArgs {
    /// Network interface to capture from
    #[arg(short, long)]
    pub interface: String,
    
    /// BPF filter expression (e.g., "tcp port 80")
    #[arg(short, long)]
    pub filter: Option<String>,
    
    /// Database file to store packets (default: packets.db)
    #[arg(short, long, default_value = "packets.db")]
    pub database: PathBuf,
    
    /// Also save packets to a pcap file
    #[arg(short, long)]
    pub pcap: Option<PathBuf>,
    
    /// Maximum number of packets to capture (0 = unlimited)
    #[arg(short = 'c', long, default_value = "0")]
    pub count: u64,
    
    /// Duration to capture in seconds (0 = unlimited)
    #[arg(short = 't', long, default_value = "0")]
    pub duration: u64,
    
    /// Snapshot length (max bytes per packet)
    #[arg(short, long, default_value = "65535")]
    pub snaplen: i32,
    
    /// Enable promiscuous mode
    #[arg(long, default_value = "true")]
    pub promisc: bool,
    
    /// Buffer size in bytes
    #[arg(short, long, default_value = "10485760")]
    pub buffer_size: i32,
}

#[derive(Parser, Debug)]
pub struct ReplayArgs {
    /// Database file containing captured packets
    #[arg(short, long, default_value = "packets.db")]
    pub database: PathBuf,
    
    /// Session ID to replay
    #[arg(short, long)]
    pub session: String,
    
    /// Speed multiplier (1.0 = real-time, 2.0 = 2x speed, 0 = as fast as possible)
    #[arg(long, default_value = "1.0")]
    pub speed: f64,
    
    /// Maximum number of packets to replay (0 = all)
    #[arg(short, long, default_value = "0")]
    pub count: u64,
    
    /// Network interface to send packets to (requires root)
    #[arg(short, long)]
    pub interface: Option<String>,
    
    /// Display packets instead of sending them
    #[arg(long)]
    pub display_only: bool,
}

#[derive(Parser, Debug)]
pub struct QueryArgs {
    /// Database file containing captured packets
    #[arg(short, long, default_value = "packets.db")]
    pub database: PathBuf,
    
    /// Session ID to query
    #[arg(short, long)]
    pub session: String,
    
    /// Maximum number of packets to display
    #[arg(short, long, default_value = "10")]
    pub limit: i64,
    
    /// Show full packet data in hex
    #[arg(long)]
    pub show_data: bool,
}

#[derive(Parser, Debug)]
pub struct SessionsArgs {
    /// Database file containing captured packets
    #[arg(short, long, default_value = "packets.db")]
    pub database: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parse() {
        // Verify the CLI can be constructed
        Cli::command().debug_assert();
    }

    #[test]
    fn test_capture_args() {
        let args = Cli::parse_from(&[
            "packetrecorder",
            "capture",
            "--interface", "eth0",
            "--filter", "tcp port 80",
        ]);
        
        match args.command {
            Commands::Capture(capture_args) => {
                assert_eq!(capture_args.interface, "eth0");
                assert_eq!(capture_args.filter, Some("tcp port 80".to_string()));
            }
            _ => panic!("Expected Capture command"),
        }
    }

    #[test]
    fn test_replay_args() {
        let args = Cli::parse_from(&[
            "packetrecorder",
            "replay",
            "--session", "test-session-id",
            "--speed", "2.0",
        ]);
        
        match args.command {
            Commands::Replay(replay_args) => {
                assert_eq!(replay_args.session, "test-session-id");
                assert_eq!(replay_args.speed, 2.0);
            }
            _ => panic!("Expected Replay command"),
        }
    }
}
