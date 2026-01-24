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

    /// Database encryption key
    #[arg(long, global = true, env = "PACKETRECORDER_DB_KEY")]
    pub encryption_key: Option<String>,
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
    
    /// Export a session to PCAP file
    Export(ExportArgs),

    /// Remote management CLI (gRPC client)
    Manage(ManageArgs),

    /// Run the daemon with gRPC management enabled
    Serve(ServeArgs),
}

#[derive(Parser, Debug)]
pub struct ManageArgs {
    /// gRPC endpoint to connect to (e.g. 127.0.0.1:50051 or https://host:50051)
    #[arg(long, default_value = "127.0.0.1:50051")]
    pub endpoint: String,

    /// API key for authentication (falls back to PACKETRECORDER_API_KEY)
    #[arg(long)]
    pub api_key: Option<String>,

    #[command(subcommand)]
    pub command: ManageCommands,
}

#[derive(Subcommand, Debug)]
pub enum ManageCommands {
    ListInterfaces(ManageListInterfacesArgs),
    StartCapture(ManageStartCaptureArgs),
    StopCapture(ManageStopCaptureArgs),
    Sessions(ManageSessionsArgs),
    GetSession(ManageGetSessionArgs),
    DownloadPcap(ManageDownloadPcapArgs),
    LookupAttribution(ManageLookupAttributionArgs),
    Keys(ManageKeysArgs),
    InspectPcap(ManageInspectPcapArgs),
}

#[derive(Parser, Debug)]
pub struct ManageKeysArgs {
    #[command(subcommand)]
    pub command: ManageKeysCommand,
}

#[derive(Subcommand, Debug)]
pub enum ManageKeysCommand {
    List(ManageKeysListArgs),
    Add(ManageKeysAddArgs),
    Remove(ManageKeysRemoveArgs),
}

#[derive(Parser, Debug)]
pub struct ManageKeysListArgs {}

#[derive(Parser, Debug)]
pub struct ManageKeysAddArgs {
    #[arg(long)]
    pub key: String,
}

#[derive(Parser, Debug)]
pub struct ManageKeysRemoveArgs {
    #[arg(long)]
    pub key: String,
}

#[derive(Parser, Debug)]
pub struct ManageListInterfacesArgs {}

#[derive(Parser, Debug)]
pub struct ManageSessionsArgs {}

#[derive(Parser, Debug)]
pub struct ManageStartCaptureArgs {
    #[arg(long)]
    pub interface: String,

    #[arg(long)]
    pub filter: Option<String>,

    #[arg(long, default_value = "0")]
    pub max_packets: u64,

    #[arg(long, default_value = "0")]
    pub max_duration_seconds: u64,

    #[arg(long, default_value = "65535")]
    pub snaplen: i32,

    #[arg(long, default_value = "true")]
    pub promisc: bool,

    #[arg(long, default_value = "10485760")]
    pub buffer_size: i32,
}

#[derive(Parser, Debug)]
pub struct ManageStopCaptureArgs {
    #[arg(long)]
    pub session_id: String,
}

#[derive(Parser, Debug)]
pub struct ManageGetSessionArgs {
    #[arg(long)]
    pub session_id: String,
}

#[derive(Parser, Debug)]
pub struct ManageDownloadPcapArgs {
    #[arg(long)]
    pub session_id: String,

    #[arg(short, long)]
    pub output: PathBuf,

    #[arg(long, default_value = "0")]
    pub limit_packets: i64,
}

#[derive(Parser, Debug)]
pub struct ManageLookupAttributionArgs {
    #[arg(long)]
    pub proto: String,

    #[arg(long)]
    pub src_ip: String,

    #[arg(long)]
    pub src_port: u16,

    #[arg(long)]
    pub dst_ip: String,

    #[arg(long)]
    pub dst_port: u16,
}

#[derive(Parser, Debug)]
pub struct ManageInspectPcapArgs {
    #[arg(long)]
    pub path: PathBuf,

    #[arg(long, default_value = "10")]
    pub limit: usize,

    #[arg(long, value_enum, default_value = "none")]
    pub payload: crate::manage::InspectPayloadMode,

    #[arg(long, default_value = "true")]
    pub mime: bool,

    #[arg(long, default_value = "false")]
    pub gzip_decode: bool,

    #[arg(long, default_value = "false")]
    pub zip_decode: bool,
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

#[derive(Parser, Debug)]
pub struct ExportArgs {
    /// Database file containing captured packets
    #[arg(short, long, default_value = "packets.db")]
    pub database: PathBuf,
    
    /// Session ID to export
    #[arg(short, long)]
    pub session: String,
    
    /// Output PCAP file
    #[arg(short, long)]
    pub output: PathBuf,
    
    /// Maximum number of packets to export (0 = all)
    #[arg(short = 'n', long, default_value = "0")]
    pub limit: i64,
}

#[derive(Parser, Debug)]
pub struct ServeArgs {
    #[arg(long, default_value = "0.0.0.0:50051")]
    pub grpc_addr: String,

    #[arg(long, default_value = "0.0.0.0:8080")]
    pub http_addr: String,

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
