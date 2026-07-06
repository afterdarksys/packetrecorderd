# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`packetrecorder` — a high-performance network packet capture and replay daemon in Rust, with encrypted storage, 20+ protocol parsers, forensic threat detection, gRPC/REST management APIs, ML inference, and distributed "swarm" capture. Crate name is `packetrecorder` (the binary), directory is `packetrecorderd`. Extensive docs accompany the code: `README.md`, `QUICKSTART.md`, `FORENSICS.md`, `SUMMARY.md`, `ENHANCEMENTS.md`, `PACKETCLIENT_DESIGN.md`, `WARP.md`, `REVIEW.md`.

**Note on location:** `/Users/ryan/development/packetrecorderd` is a symlink to this directory (`experiments-no-claude/packetrecorderd`) — they are the same tree, not two copies.

## Commands

```bash
cargo build                  # debug build
cargo build --release        # release -> target/release/packetrecorder
./build.sh                   # build script
cargo test                   # run tests
cargo clippy                 # lint
cargo fmt                    # format
./test_forensics.sh          # forensics integration test

# Running (capture requires root/sudo on macOS/Linux)
sudo ./target/release/packetrecorder list-interfaces
sudo ./target/release/packetrecorder capture -i en0 -f "tcp port 443" -d packets.db -c 1000
sudo ./target/release/packetrecorder serve --grpc-addr 127.0.0.1:50051 --http-addr 127.0.0.1:8080 -d packets.db
```

Requires Rust 1.70+ (2021 edition) and libpcap. eBPF support (via `aya`) is Linux-only, cfg-gated. A `build.rs` compiles the gRPC protobufs (`proto/packetrecorder/v1/`) with `tonic-build`.

## Architecture

`main.rs` routes clap subcommands into module-owned pipelines. Packets flow: **capture -> async processing -> storage/forensics -> APIs/metrics**.

- `capture/` — libpcap capture sessions and interface management; packet writers (database, PCAP, multi-writer)
- `storage/` — encrypted SQLite (SQLCipher via `rusqlite` bundled-sqlcipher), Mutex-guarded for thread safety
- `processing.rs` — asynchronous packet processing pipeline
- `protocols/`, `decoders/` — parsers for 20+ protocols (HTTP, TLS w/ JA3, DNS, BGP/OSPF/EIGRP/RIP, SNMP, NetFlow/sFlow, etc.)
- `forensics/` — threat detection (Tor, chat/cloud apps, DNS tunneling/DGA/fast-flux, IP reputation, DarkAPI/DNSScience integration) generating typed alerts
- `attribution.rs` — process-level packet attribution over a Unix socket
- `grpc/` + `api.rs` — gRPC (tonic) and Axum REST/SSE management surfaces
- `metrics.rs` — Prometheus exporter
- `ml/` — Candle / `tch` / hf-hub model inference; `model_client.rs`, `model_manifest.rs`
- `replay/` — timed packet replay
- `swarm/` — gossip-based distributed capture coordination
- `cli/`, `manage.rs` — local CLI and remote-management client

## Configuration

Runtime config is env-driven: `PACKETRECORDER_DB_KEY`, `PACKETRECORDER_API_KEY`, `PACKETRECORDER_ATTRIBUTION_SOCKET`, `DARKAPI_KEY`/`DARKAPI_BASE_URL`, `DNSSCIENCE_API_KEY` (see `.env.example`). Threat-detection signatures load from `signatures.json`; plugins from `plugins.json`. Database encryption is strongly recommended for captured data.
