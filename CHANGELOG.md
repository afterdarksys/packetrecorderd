# Changelog

All notable changes to packetrecorderd will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Core Features
- **Database Encryption**: SQLCipher integration for encrypted packet storage
  - Global `--encryption-key` CLI flag
  - `PACKETRECORDER_DB_KEY` environment variable support
- **gRPC Management API**: Full remote management capabilities
  - Protocol Buffer service definition in `proto/packetrecorder/v1/packetrecorder.proto`
  - Remote capture control (start/stop)
  - Session management and listing
  - PCAP download streaming
  - Process attribution lookup
  - API key management
  - API key authentication via interceptor
- **HTTP REST API**: Monitoring and statistics endpoints
  - `GET /health` - Health check endpoint
  - `GET /metrics` - Prometheus metrics export
  - `GET /api/v1/stats` - Real-time statistics
  - `GET /api/v1/sessions` - Session listing
  - `GET /api/v1/events` - Server-Sent Events stream
  - API key authentication support
- **Process Attribution**: Unix socket integration for process-level packet correlation
  - Flow 5-tuple tracking (protocol, src/dst IP/port)
  - Process metadata (PID, UID, process name, bundle_id, signing_id)
  - `PACKETRECORDER_ATTRIBUTION_SOCKET` environment variable
- **Prometheus Metrics**: Built-in metrics collection and export
  - `packetrecorder_packets_total` counter (by protocol)
  - `packetrecorder_bytes_total` counter (by protocol)
  - `packetrecorder_active_sessions` gauge
  - `packetrecorder_flow_table_size` gauge
  - `packetrecorder_packet_processing_seconds` histogram
- **Async Packet Processing**: Multi-threaded packet processing pipeline
  - Crossbeam channel-based architecture
  - Flow hashing and deduplication
  - Configurable worker threads

#### Protocol Support
- **New Protocols**:
  - SNMP (Simple Network Management Protocol) - full v1/v2c/v3 support
  - NTP (Network Time Protocol) - mode and stratum detection
  - RIP (Routing Information Protocol) - v1/v2 support
  - SMTP (Simple Mail Transfer Protocol) - command/response parsing, STARTTLS detection
  - SSH (Secure Shell) - version string parsing
  - BGP (Border Gateway Protocol) - message type parsing
  - OSPF (Open Shortest Path First) - header parsing
  - EIGRP (Enhanced Interior Gateway Routing Protocol) - Cisco proprietary
  - ICMP/ICMPv6 - Enhanced detection with type/code descriptions

- **Enhanced Protocols**:
  - **TLS**: Server certificate parsing and extraction
  - **DNS**: Integrated threat detection (tunneling, DGA, fast-flux)
  - **HTTP**: Bot detection via user-agent analysis
  - **All protocols**: Added `Clone` trait derives for better composability

#### Forensics & Threat Detection
- **DNS Threat Detection**:
  - DNS tunneling detection (entropy, subdomain analysis)
  - Domain Generation Algorithm (DGA) detection
  - Fast-flux network detection with tracking
  - Suspicious TLD monitoring (.tk, .ml, .ga, etc.)
- **IP Reputation**:
  - Datacenter IP detection
  - Network type classification (residential, mobile, hosting, cloud, VPN)
  - Bot detection via user-agent fingerprinting
  - Known malicious IP checking
- **API Integration**:
  - DarkAPI threat intelligence client
  - DNSScience API integration
  - Configurable API keys via environment variables
- **New Alert Types**:
  - `MaliciousIp` - Known malicious IP addresses
  - `MaliciousDomain` - Known malicious domains
  - `DnsTunneling` - DNS tunneling activity
  - `DgaDetected` - DGA-generated domains
  - `FastFlux` - Fast-flux network activity
  - `SuspiciousTld` - Suspicious TLD usage
  - `BotDetected` - Bot/crawler detection
  - `DatacenterIp` - Datacenter/proxy traffic

#### CLI & Management
- **New Commands**:
  - `serve` - Run as daemon with gRPC and HTTP APIs
    - `--grpc-addr` - gRPC listener address (default: 127.0.0.1:50051)
    - `--http-addr` - HTTP listener address (default: 127.0.0.1:8080)
  - `manage` - Remote management client with subcommands:
    - `list-interfaces` - List remote network interfaces
    - `start-capture` - Start remote capture session
    - `stop-capture` - Stop remote capture session
    - `sessions` - List remote sessions
    - `get-session` - Get session details
    - `download-pcap` - Download PCAP from remote session
    - `lookup-attribution` - Query process attribution
    - `keys` - Manage API keys (list/add/remove)
    - `inspect-pcap` - Inspect PCAP files
  - `export` - Export session to PCAP format
    - `--session` - Session ID to export
    - `--output` - Output PCAP file path
    - `--limit` - Limit number of packets

- **Enhanced Commands**:
  - `capture` - Added `--pcap` flag for simultaneous PCAP output
  - All commands now support `--encryption-key` global flag

#### Machine Learning
- **ML Infrastructure**:
  - Hugging Face Hub integration for model downloads
  - Model manifest system for versioned models
  - Candle framework integration for inference
  - Model client abstraction layer

#### Distributed Capabilities
- **Swarm Mode Foundation**:
  - Gossip protocol implementation
  - Multi-node coordination framework
  - Distributed capture orchestration

#### Build & Development
- **Build System**:
  - `build.rs` for Protocol Buffer compilation
  - Automatic tonic code generation
  - eBPF support via Aya framework (Linux only)
  - Updated `.cargo/config.toml` for optimized builds
- **Scripts**:
  - `scripts/capture_all.sh` - Capture from all interfaces
  - `scripts/capture_dns.sh` - DNS-focused capture script
  - `scripts/run.sh` - Quick development runner
  - `test_forensics.sh` - Forensics engine test suite
- **Documentation**:
  - `QUICKSTART.md` - Quick start guide
  - `FORENSICS.md` - Forensics and threat detection guide
  - `SUMMARY.md` - Implementation summary
  - `ENHANCEMENTS.md` - Detailed enhancement documentation
  - `PACKETCLIENT_DESIGN.md` - Client architecture design
  - `IMPLEMENTATION_COMPLETE.md` - Implementation completion status
  - `.env.example` - Environment variable template

#### Dependencies
- **New Dependencies**:
  - `tonic` - gRPC framework
  - `prost` - Protocol Buffer implementation
  - `axum` - HTTP web framework
  - `tower-http` - HTTP middleware (CORS)
  - `prometheus` - Metrics collection
  - `reqwest` - HTTP client for API integrations
  - `hf-hub` - Hugging Face Hub client
  - `candle-transformers` - ML transformers
  - `flate2`, `zip` - Compression support
  - `sha2` - Cryptographic hashing
  - `serde_yaml` - YAML configuration
  - `crossbeam-channel` - Multi-producer multi-consumer channels
  - `lazy_static` - Static initialization

- **Updated Dependencies**:
  - `rusqlite` - Now uses `bundled-sqlcipher` feature for encryption
  - `clap` - Added `env` feature for environment variable support

### Changed

#### Core Improvements
- **Storage Layer**: All storage operations now support optional encryption
- **Capture Writer**: Refactored to support multiple simultaneous writers (DB + PCAP)
  - New `MultiWriter` for composing writers
  - `PcapWriter` for direct PCAP output
  - `DatabaseWriter` with encryption support
- **Main Application**: Restructured for modular service architecture
  - Flow hashing for efficient deduplication
  - Metrics registration on startup
  - Unified command routing with encryption support
- **Protocol Module**: All protocol info structs now implement `Clone`
- **Forensics Engine**: Enhanced with API clients and advanced detection

#### Breaking Changes
- **Database Encryption**: Databases created without encryption key cannot be opened with one (and vice versa)
- **API Changes**: All storage functions now accept `Option<&str>` for encryption key
- **CLI**: Global `--encryption-key` flag added to all commands

### Fixed
- **SMTP Parser**: Fixed bounds checking on short strings to prevent panics
- **Flow Table**: Added TTL-based cleanup (5 minute expiry) to prevent memory leaks
- **Protocol Parsing**: Fixed `IpNumber` type conversion in protocol detection
- **Payload Access**: Corrected etherparse API usage for payload extraction
- **Missing Derives**: Added `Clone` to all protocol structs for better composability

### Security
- **Database Encryption**: SQLCipher integration for at-rest encryption
- **API Authentication**: API key-based authentication for gRPC and HTTP endpoints
- **Environment Variables**: Sensitive configuration via environment variables
- **Credential Management**: Secure API key storage and validation

## [0.1.0] - Initial Release

### Added
- Basic packet capture functionality
- SQLite storage backend
- Packet replay capability
- Session management
- CLI interface with subcommands:
  - `list-interfaces`
  - `capture`
  - `query`
  - `sessions`
  - `replay`
- Protocol detection:
  - TLS with JA3 fingerprinting
  - HTTP request parsing
  - DNS query/response parsing
  - LDAP basic parsing
  - NetBIOS detection
- Forensics engine:
  - Tor detection
  - Chat application detection
  - Cloud storage detection
  - Large transfer monitoring
- BPF filtering support
- Promiscuous mode capture
- Configurable snaplen and buffer size

[Unreleased]: https://github.com/yourusername/packetrecorderd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/packetrecorderd/releases/tag/v0.1.0
