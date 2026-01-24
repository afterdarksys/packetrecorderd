#!/bin/bash
# Wrapper script for running packetrecorderd with sudo
# Usage: ./scripts/run.sh [command] [arguments...]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_ROOT/target/release/packetrecorder"

# Set up libtorch path (adjust if your Python version differs)
LIBTORCH_PATH="$HOME/Library/Python/3.9/lib/python/site-packages/torch/lib"
if [ -d "$LIBTORCH_PATH" ]; then
    export DYLD_LIBRARY_PATH="$LIBTORCH_PATH:$DYLD_LIBRARY_PATH"
fi

# Build if binary doesn't exist
if [ ! -f "$BINARY" ]; then
    echo "Binary not found. Building release version..."
    cd "$PROJECT_ROOT"
    cargo build --release
fi

# Check if we need sudo
if [ "$(id -u)" -ne 0 ]; then
    echo "Running with sudo (packet capture requires elevated privileges)..."
    exec sudo "$BINARY" "$@"
else
    exec "$BINARY" "$@"
fi
