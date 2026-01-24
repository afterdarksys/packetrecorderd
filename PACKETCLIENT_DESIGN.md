# packetclient Design

## Architecture

```
packetrecorderd (daemon)           packetclient (CLI)
├─ Packet capture                  ├─ Send commands
├─ Protocol analysis               ├─ Query data
├─ Storage                         ├─ Stream logs
├─ HTTP/gRPC API                   ├─ Export formats
└─ Runs as root                    └─ Runs as user
```

## API Endpoints

### Control Operations
```
POST   /api/v1/capture/start       - Start capture
POST   /api/v1/capture/stop        - Stop capture
GET    /api/v1/capture/status      - Get status
```

### Query Operations
```
GET    /api/v1/sessions            - List sessions
GET    /api/v1/sessions/:id        - Get session details
GET    /api/v1/sessions/:id/packets - Get packets
GET    /api/v1/sessions/:id/export  - Export session
```

### Monitoring
```
GET    /api/v1/health              - Health check
GET    /api/v1/stats               - Statistics
GET    /api/v1/metrics             - Prometheus metrics
GET    /api/v1/logs                - Stream logs (WebSocket)
```

## packetclient Commands

### Basic Usage
```bash
# Local daemon (default)
packetclient status
packetclient list-sessions
packetclient capture --interface eth0 --duration 60

# Remote daemon
packetclient --host 10.0.1.5:8080 --token $TOKEN status
packetclient -H prod-server1 list-sessions
```

### Configuration File
```yaml
# ~/.packetclient/config.yaml
default_host: localhost:8080
hosts:
  prod-server1:
    url: https://10.0.1.5:8443
    token_file: ~/.packetclient/tokens/prod-server1
    tls_verify: true
  dev-server:
    url: http://192.168.1.10:8080
    token: dev-token-123
```

### Commands

#### Status & Health
```bash
packetclient status                # Current capture status
packetclient health                # Health check
packetclient version               # Version info
```

#### Capture Control
```bash
packetclient start --interface eth0 --filter "port 443"
packetclient stop --session abc123
packetclient restart --session abc123
```

#### Query
```bash
packetclient sessions              # List all sessions
packetclient show abc123           # Show session details
packetclient packets abc123        # Show packets
packetclient packets abc123 --limit 100 --filter "tcp"
```

#### Export
```bash
packetclient export abc123 --format pcap -o capture.pcap
packetclient export abc123 --format json -o session.json
packetclient export abc123 --format csv > stats.csv
```

#### Statistics
```bash
packetclient stats                 # Overall statistics
packetclient stats --session abc123  # Session stats
packetclient top-talkers           # Top IPs by traffic
packetclient protocols             # Protocol distribution
```

#### Logs & Monitoring
```bash
packetclient logs                  # Stream logs
packetclient logs --follow         # Tail logs
packetclient logs --session abc123 # Session-specific logs
```

#### Multi-Host Operations
```bash
# Manage multiple servers
packetclient --all status          # Status of all configured hosts
packetclient --hosts prod-server1,prod-server2 start --interface eth0

# Compare across hosts
packetclient compare --hosts prod-server1,prod-server2
```

## Implementation Plan

### Phase 1: Core Client
1. HTTP client with auth
2. Basic commands: status, sessions, show
3. Configuration file support
4. Output formatting (JSON, table, YAML)

### Phase 2: Advanced Features
5. Multi-host support
6. Interactive mode (REPL)
7. Session export
8. Statistics commands

### Phase 3: Real-time Features
9. Log streaming
10. Live statistics dashboard
11. Event notifications
12. Alerting

## Code Structure

```
packetclient/
├─ Cargo.toml
├─ src/
│  ├─ main.rs              # Entry point
│  ├─ client/
│  │  ├─ mod.rs           # HTTP/gRPC client
│  │  └─ auth.rs          # Authentication
│  ├─ commands/
│  │  ├─ mod.rs
│  │  ├─ status.rs
│  │  ├─ sessions.rs
│  │  ├─ capture.rs
│  │  ├─ export.rs
│  │  └─ stats.rs
│  ├─ config.rs           # Configuration
│  ├─ output.rs           # Formatters
│  └─ interactive.rs      # REPL mode
```

## Example Session

```bash
$ packetclient status
Status: Running
Active Sessions: 2
Packets Captured: 145,234
Uptime: 2d 5h 23m

$ packetclient sessions
ID          Interface  Start Time           Packets  Status
abc123      eth0       2026-01-21 09:00     45,234   Running
def456      wlan0      2026-01-21 08:30     100,000  Stopped

$ packetclient show abc123
Session: abc123
Interface: eth0
Filter: port 443
Start: 2026-01-21 09:00:15
Duration: 45m 23s
Packets: 45,234
Bytes: 34.2 MB
Protocols:
  - TLS: 89.2%
  - HTTP: 8.3%
  - DNS: 2.5%

$ packetclient export abc123 --format pcap -o capture.pcap
Exported 45,234 packets to capture.pcap
```

## Security

### Authentication
- Bearer tokens (JWT)
- API keys
- mTLS client certificates

### Authorization
- Role-based access control
- Per-session permissions
- Audit logging

### Transport Security
- TLS 1.3 required for remote
- Certificate pinning
- Token rotation

## Dependencies

```toml
[dependencies]
clap = { version = "4.5", features = ["derive"] }
reqwest = { version = "0.11", features = ["json"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
prettytable-rs = "0.10"  # Table formatting
anyhow = "1.0"
config = "0.13"          # Configuration management
dirs = "5.0"             # User directories
```
