# packetrecorderd

A high-performance network packet capture and replay daemon written in Rust with advanced threat detection, protocol analysis, and distributed management capabilities.

## Features

### Core Capabilities
- **Packet Capture**: Capture packets from any network interface with BPF filtering support
- **Encrypted Storage**: Store captured packets in encrypted SQLite database (SQLCipher)
- **Packet Replay**: Replay captured packets with configurable timing control
- **Multiple Interfaces**: List and select from available network interfaces
- **Session Management**: Organize captures into sessions with metadata
- **Multi-format Export**: Export to PCAP, database, or custom formats

### Protocol Analysis
Support for 20+ protocols including:
- **Application**: HTTP, HTTPS/TLS, DNS, SMTP, SSH, LDAP, NetBIOS
- **Transport**: TCP, UDP with flow tracking
- **Network**: IPv4, IPv6, ICMP/ICMPv6
- **Routing**: BGP, OSPF, EIGRP, RIP
- **Management**: SNMP, NTP
- **Specialized**: NetFlow, sFlow

#### Advanced Protocol Features
- **TLS**: JA3 fingerprinting, SNI extraction, server certificate parsing
- **DNS**: Query/response parsing, threat detection (tunneling, DGA, fast-flux)
- **HTTP**: Request parsing, bot detection, header analysis

### Forensics & Threat Detection
- **Tor Detection**: Exit node identification, bridge detection
- **Chat Application Detection**: Signal, WhatsApp, Telegram, Discord, Slack
- **Cloud Storage Detection**: Dropbox, Google Drive, OneDrive, iCloud
- **Data Transfer Monitoring**: Large transfer detection with configurable thresholds
- **DNS Threats**: Tunneling, DGA (Domain Generation Algorithm), Fast-Flux, suspicious TLDs
- **IP Reputation**: Datacenter detection, network classification, malicious IP detection
- **Bot Detection**: User-agent analysis, behavioral patterns
- **API Integration**: DarkAPI threat intelligence, DNSScience lookups

### Management & Monitoring
- **gRPC API**: Full remote management via Protocol Buffers
- **REST API**: HTTP endpoints for health, metrics, and statistics
- **Prometheus Metrics**: Built-in metrics exporter
- **Process Attribution**: Unix socket integration for process-level packet attribution
- **CLI & Remote Management**: Local and remote control via unified CLI

### Machine Learning
- **Model Integration**: Hugging Face Hub support
- **Candle Framework**: Efficient ML inference
- **Model Manifest**: Versioned model management

### Distributed Capabilities
- **Swarm Mode**: Gossip protocol for distributed capture
- **Multi-node Coordination**: Coordinated packet capture across multiple hosts

## Requirements

- Rust 1.70+ (2021 edition)
- Root/sudo privileges for packet capture (on macOS/Linux)
- libpcap (usually pre-installed on macOS/Linux)
- For eBPF support (Linux only): Kernel 5.4+

### Optional Dependencies
- **API Keys** (for enhanced threat detection):
  - DarkAPI key (set via `DARKAPI_KEY` environment variable)
  - Additional threat intelligence APIs

## Installation

### Standard Build

```bash
cargo build --release
```

The binary will be available at `target/release/packetrecorder`.

### With eBPF Support (Linux)

```bash
# eBPF support is automatically enabled on Linux
cargo build --release --target x86_64-unknown-linux-gnu
```

### Using Build Script

```bash
./build.sh
```

## Quick Start

See [QUICKSTART.md](QUICKSTART.md) for detailed getting started guide.

### 1. List Network Interfaces

```bash
sudo ./target/release/packetrecorder list-interfaces
```

### 2. Start Capture

```bash
sudo ./target/release/packetrecorder capture \
  --interface en0 \
  --filter "tcp port 443" \
  --database packets.db \
  --count 1000
```

### 3. Query Packets

```bash
./target/release/packetrecorder query \
  --database packets.db \
  --session <session-id> \
  --limit 10
```

## Usage

### Database Encryption

Encrypt your packet database:

```bash
# Set encryption key via environment variable
export PACKETRECORDER_DB_KEY="your-secret-key"

# Or pass directly
sudo ./target/release/packetrecorder capture \
  --interface en0 \
  --encryption-key "your-secret-key" \
  --database encrypted.db
```

### Capture Packets

Capture packets from an interface (requires root):

```bash
sudo ./target/release/packetrecorder capture \
  --interface en0 \
  --filter "tcp port 80" \
  --database packets.db \
  --count 100 \
  --pcap capture.pcap
```

Options:
- `-i, --interface`: Network interface to capture from (required)
- `-f, --filter`: BPF filter expression (e.g., "tcp port 80", "host 192.168.1.1")
- `-d, --database`: Database file to store packets (default: packets.db)
- `-c, --count`: Maximum number of packets to capture (0 = unlimited)
- `-t, --duration`: Duration to capture in seconds (0 = unlimited)
- `-s, --snaplen`: Snapshot length in bytes (default: 65535)
- `--promisc`: Enable promiscuous mode (default: true)
- `-b, --buffer-size`: Buffer size in bytes (default: 10MB)
- `-p, --pcap`: Optional PCAP file output

### Run as Daemon with APIs

Start the gRPC and HTTP management server:

```bash
sudo ./target/release/packetrecorder serve \
  --grpc-addr 127.0.0.1:50051 \
  --http-addr 127.0.0.1:8080 \
  --database packets.db
```

This enables:
- **gRPC API** on port 50051 for remote management
- **HTTP API** on port 8080 for metrics and health checks

#### API Endpoints

HTTP API:
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `GET /api/v1/stats` - Statistics
- `GET /api/v1/sessions` - List sessions
- `GET /api/v1/events` - Server-Sent Events stream

### Remote Management

Manage a remote packetrecorderd instance:

```bash
# List interfaces on remote server
./target/release/packetrecorder manage \
  --endpoint 192.168.1.100:50051 \
  --api-key "your-api-key" \
  list-interfaces

# Start remote capture
./target/release/packetrecorder manage \
  --endpoint 192.168.1.100:50051 \
  --api-key "your-api-key" \
  start-capture \
  --interface eth0 \
  --filter "tcp port 443" \
  --max-packets 10000

# Download PCAP from remote
./target/release/packetrecorder manage \
  --endpoint 192.168.1.100:50051 \
  --api-key "your-api-key" \
  download-pcap \
  --session-id <session-id> \
  --output capture.pcap
```

Set API key via environment:
```bash
export PACKETRECORDER_API_KEY="your-api-key"
```

### Process Attribution

Enable process-level packet attribution (macOS/Linux):

```bash
# Set attribution socket path
export PACKETRECORDER_ATTRIBUTION_SOCKET="/tmp/packetrecorder.sock"

# Start daemon
sudo ./target/release/packetrecorder serve \
  --grpc-addr 127.0.0.1:50051 \
  --http-addr 127.0.0.1:8080 \
  --database packets.db

# In another terminal, send attribution data via Unix socket
# (Requires external process monitor integration)
```

### Export Session

Export a capture session to PCAP:

```bash
./target/release/packetrecorder export \
  --database packets.db \
  --session <session-id> \
  --output capture.pcap \
  --limit 1000
```

### List Capture Sessions

```bash
./target/release/packetrecorder sessions --database packets.db
```

### Query Captured Packets

Display packets from a capture session:

```bash
./target/release/packetrecorder query \
  --database packets.db \
  --session <session-id> \
  --limit 10 \
  --show-data
```

Options:
- `-s, --session`: Session ID to query (required)
- `-l, --limit`: Maximum number of packets to display (default: 10)
- `--show-data`: Show full packet data in hex format

### Replay Packets

Replay captured packets:

```bash
sudo ./target/release/packetrecorder replay \
  --database packets.db \
  --session <session-id> \
  --speed 2.0 \
  --display-only
```

Options:
- `-s, --session`: Session ID to replay (required)
- `--speed`: Speed multiplier (1.0 = real-time, 2.0 = 2x speed, 0 = max speed)
- `-c, --count`: Maximum number of packets to replay (0 = all)
- `--display-only`: Display packets instead of sending them to network

## Configuration

### Environment Variables

- `PACKETRECORDER_DB_KEY`: Database encryption key
- `PACKETRECORDER_API_KEY`: API key for authentication
- `PACKETRECORDER_ATTRIBUTION_SOCKET`: Unix socket path for process attribution
- `DARKAPI_KEY`: DarkAPI threat intelligence key
- `DARKAPI_BASE_URL`: DarkAPI base URL (default: https://api.darkapi.io)
- `DNSSCIENCE_API_KEY`: DNSScience API key

### Signatures Configuration

Create `signatures.json` for threat detection:

```json
{
  "tor": {
    "exit_nodes": ["1.2.3.4"],
    "bridges": ["5.6.7.8"]
  },
  "transfer_thresholds": {
    "default": 104857600,
    "known_large_file_services": 1073741824
  }
}
```

## Prometheus Metrics

When running in `serve` mode, the following metrics are exposed:

- `packetrecorder_packets_total`: Total packets captured (by protocol)
- `packetrecorder_bytes_total`: Total bytes captured (by protocol)
- `packetrecorder_active_sessions`: Number of active capture sessions
- `packetrecorder_flow_table_size`: Current flow table size
- `packetrecorder_packet_processing_seconds`: Packet processing latency histogram

## Development

### Build

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

### Test Forensics

```bash
./test_forensics.sh
```

### Run Linter

```bash
cargo clippy
```

### Format Code

```bash
cargo fmt
```

## Architecture

The project is organized into several modules:

- **capture**: Packet capture functionality using libpcap
  - `mod.rs`: Core capture session and interface management
  - `writer.rs`: Packet writers (database, PCAP, multi-writer)
- **storage**: Encrypted SQLite database layer for packet persistence
- **replay**: Packet replay with timing control
- **protocols**: Protocol parsers for 20+ protocols
- **forensics**: Threat detection and intelligence
  - `tor.rs`, `chat.rs`, `cloud.rs`: Application detection
  - `dns_threats.rs`: DNS-based threat detection
  - `ip_reputation.rs`: IP classification
  - `darkapi.rs`: Threat intelligence API integration
- **grpc**: gRPC service implementation
- **api**: HTTP REST API
- **metrics**: Prometheus metrics
- **attribution**: Process-level packet attribution
- **processing**: Asynchronous packet processing pipeline
- **ml**: Machine learning model integration
- **swarm**: Distributed capture coordination
- **cli**: Command-line interface using clap
- **main.rs**: Application entry point and command routing

## Protocol Detection

The forensics engine automatically detects and analyzes:

### Applications
- Tor (exit nodes, bridges, ORPort connections)
- Chat apps (Signal, WhatsApp, Telegram, Discord, Slack, Teams, Zoom)
- Cloud storage (Dropbox, Google Drive, OneDrive, Box, iCloud)

### Threats
- DNS tunneling
- Domain Generation Algorithms (DGA)
- Fast-flux networks
- Malicious IPs and domains
- Bot activity
- Datacenter/proxy traffic

### Alerts

The system generates alerts for:
- `TorConnection`: Tor network usage
- `ChatApplication`: Messaging app usage
- `CloudStorage`: Cloud storage access
- `LargeTransfer`: Large data transfers
- `MaliciousIp`: Known malicious IPs
- `MaliciousDomain`: Known malicious domains
- `DnsTunneling`: DNS tunneling detected
- `DgaDetected`: DGA domain detected
- `FastFlux`: Fast-flux network detected
- `SuspiciousTld`: Suspicious TLD usage
- `BotDetected`: Bot activity
- `DatacenterIp`: Datacenter/proxy IP

## BPF Filter Examples

- Capture only HTTP traffic: `"tcp port 80"`
- Capture HTTPS traffic: `"tcp port 443"`
- Capture traffic to/from a specific host: `"host 192.168.1.1"`
- Capture ICMP packets: `"icmp"`
- Capture SSH traffic: `"tcp port 22"`
- Capture UDP DNS: `"udp port 53"`
- Capture DNS over TLS: `"tcp port 853"`
- Combine filters: `"tcp port 80 or tcp port 443"`
- Exclude traffic: `"not port 22"`

## Documentation

- [QUICKSTART.md](QUICKSTART.md) - Quick start guide
- [FORENSICS.md](FORENSICS.md) - Forensics and threat detection guide
- [SUMMARY.md](SUMMARY.md) - Implementation summary
- [ENHANCEMENTS.md](ENHANCEMENTS.md) - Enhancement details
- [PACKETCLIENT_DESIGN.md](PACKETCLIENT_DESIGN.md) - Client design documentation

## Notes

- **Permissions**: Packet capture requires elevated privileges. On macOS/Linux, run with `sudo`.
- **Thread Safety**: The storage layer uses Mutex for thread-safe access to the SQLite database.
- **Performance**: The capture module uses buffering, async processing, and prepared statements for optimal performance.
- **Security**: Database encryption is strongly recommended for sensitive packet data.
- **API Authentication**: Always use API keys in production environments.

## License

This project is available under your preferred license.
