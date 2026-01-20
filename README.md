# packetrecorderd

A high-performance network packet capture and replay daemon written in Rust.

## Features

- **Packet Capture**: Capture packets from any network interface with BPF filtering support
- **SQLite Storage**: Store captured packets in a SQLite database for efficient querying
- **Packet Replay**: Replay captured packets with configurable timing control
- **Multiple Interfaces**: List and select from available network interfaces
- **Session Management**: Organize captures into sessions with metadata
- **CLI Interface**: Intuitive command-line interface with subcommands

## Requirements

- Rust 1.70+ (2021 edition)
- Root/sudo privileges for packet capture (on macOS/Linux)
- libpcap (usually pre-installed on macOS/Linux)

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/packetrecorder`.

## Usage

### List Network Interfaces

```bash
cargo run -- list-interfaces
```

Or with the built binary:
```bash
sudo ./target/release/packetrecorder list-interfaces
```

### Capture Packets

Capture packets from an interface (requires root):

```bash
sudo cargo run -- capture \
  --interface en0 \
  --filter "tcp port 80" \
  --database packets.db \
  --count 100
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

### List Capture Sessions

```bash
cargo run -- sessions --database packets.db
```

### Query Captured Packets

Display packets from a capture session:

```bash
cargo run -- query \
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
cargo run -- replay \
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

## Development

### Build

```bash
cargo build
```

### Run Tests

```bash
cargo test
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
  - `writer.rs`: Packet writers (database, with trait for extensibility)
- **storage**: SQLite database layer for packet persistence
- **replay**: Packet replay with timing control
- **cli**: Command-line interface using clap
- **main.rs**: Application entry point and command routing

## BPF Filter Examples

- Capture only HTTP traffic: `"tcp port 80"`
- Capture traffic to/from a specific host: `"host 192.168.1.1"`
- Capture ICMP packets: `"icmp"`
- Capture SSH traffic: `"tcp port 22"`
- Capture UDP DNS: `"udp port 53"`
- Combine filters: `"tcp port 80 or tcp port 443"`

## Notes

- **Permissions**: Packet capture requires elevated privileges. On macOS/Linux, run with `sudo`.
- **Thread Safety**: The storage layer uses Mutex for thread-safe access to the SQLite database.
- **Performance**: The capture module uses buffering and prepared statements for optimal performance.

## License

This project is available under your preferred license.
