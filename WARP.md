# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

`packetrecorderd` is a Rust-based network packet capture and recording daemon. The project is in early development stages with basic packet capture infrastructure in place but the main application logic is not yet implemented (main.rs is still a placeholder).

**Key Technologies:**
- **pcap**: Core packet capture functionality via libpcap bindings
- **etherparse**: Network packet parsing
- **tokio**: Async runtime for concurrent operations
- **rusqlite**: SQLite database for packet storage
- **tracing**: Structured logging
- **clap**: CLI argument parsing (not yet wired up)

## Project Structure

```
src/
├── main.rs              # Application entry point (stub)
├── capture/
│   └── mod.rs          # Packet capture logic (NetworkInterface, CaptureSession)
├── cli/                # Empty - planned CLI implementation
├── storage/            # Empty - planned database storage layer
└── replay/             # Empty - planned packet replay functionality
```

### Architecture Notes

**capture/mod.rs** is the most developed module:
- `NetworkInterface`: Represents available network interfaces
- `list_interfaces()`: Enumerates network devices
- `CaptureConfig`: Configuration for packet capture sessions (snaplen, promiscuous mode, BPF filters, buffer size)
- `CaptureSession`: Active packet capture with support for BPF filters and statistics
- Note: declares `pub mod writer;` but writer.rs doesn't exist yet

**Planned modules** (directories exist but are empty):
- `cli/`: Command-line interface (clap is in dependencies)
- `storage/`: SQLite-based packet storage (rusqlite is in dependencies)
- `replay/`: Packet replay functionality

## Development Commands

### Building
```bash
cargo build                    # Build debug version
cargo build --release          # Build optimized release version
```

### Running
```bash
cargo run                      # Run with placeholder main
cargo run -- [args]            # Run with arguments (CLI not implemented yet)
```

### Testing
```bash
cargo test                     # Run all tests (currently only capture::tests::test_list_interfaces)
cargo test test_list_interfaces  # Run specific test
cargo test -- --nocapture      # Run tests with stdout visible
```

**Note:** The test `test_list_interfaces` requires network permissions and will enumerate actual network interfaces on the system.

### Code Quality
```bash
cargo fmt                      # Format code
cargo clippy                   # Run linter
cargo clippy -- -W clippy::all # Run all clippy lints
```

### Cleaning
```bash
cargo clean                    # Remove build artifacts
```

## Development Considerations

### Permissions
Packet capture requires elevated privileges on most systems. When implementing CLI functionality, consider:
- Running with `sudo` on macOS/Linux
- Setting appropriate capabilities on the binary
- Providing clear error messages when permissions are insufficient

### BPF Filters
The `CaptureConfig` supports Berkeley Packet Filter (BPF) syntax for filtering packets. Common examples:
- `"tcp port 80"` - Capture HTTP traffic
- `"host 192.168.1.1"` - Capture traffic to/from specific host
- `"icmp"` - Capture only ICMP packets

### Module Integration
When implementing the remaining modules:
- **cli/**: Use clap's derive API (already in dependencies with "derive" feature)
- **storage/**: Use rusqlite with bundled feature (already configured)
- **capture/writer**: Implement the declared but missing writer module for saving captured packets
- **replay/**: Consider timing precision for accurate packet replay

### Error Handling
The project uses `anyhow::Result` for error handling. Provide context with `.context()` for better error messages, following the pattern in capture/mod.rs.

### Logging
Use the `tracing` crate for structured logging:
- `debug!()` for verbose development info
- `info!()` for important events (interface opens, filter application)
- `warn!()` for recoverable issues
- `error!()` for serious problems
