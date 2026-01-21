#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[BUILD]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Usage Help
usage() {
    echo "Usage: ./build.sh [option]"
    echo "Options:"
    echo "  release (default)  Build release binary"
    echo "  debug              Build debug binary"
    echo "  test               Run tests"
    echo "  clean              Clean build artifacts"
    echo "  help               Show this help message"
}

if [ "$1" == "help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    usage
    exit 0
fi

# OS Detection
OS="$(uname -s)"
log "Detected OS: $OS"

# Check for Rust
if ! command -v cargo &> /dev/null; then
    error "Rust (cargo) not found. Please install via https://rustup.rs/"
fi

# Libtorch / PyTorch Check
# The project uses 'tch' which requires libtorch. We configure it to use the Python installation.
log "Checking PyTorch installation for libtorch bindings..."
if command -v python3 &> /dev/null; then
    if python3 -c "import torch" &> /dev/null; then
        TORCH_PATH=$(python3 -c "import torch; print(torch.__file__)")
        log "Found PyTorch at: $TORCH_PATH"
        export LIBTORCH_USE_PYTORCH=1
        # Bypass version check allows using newer PyTorch versions (e.g. 2.2) with older tch crates
        export LIBTORCH_BYPASS_VERSION_CHECK=1
    else
        warn "PyTorch not found in python3. Build may fail if LIBTORCH is not set manually."
        warn "To fix: pip3 install torch"
    fi
else
    warn "python3 not found. Cannot auto-detect PyTorch location."
fi

# OS Specific Checks
if [ "$OS" = "Linux" ]; then
    log "Running Linux specific checks..."
    
    # Check for libpcap headers
    if command -v pkg-config &> /dev/null; then
        if ! pkg-config --exists libpcap; then
            warn "libpcap not found via pkg-config. Ensure libpcap-dev is installed."
            warn "Debian/Ubuntu: sudo apt-get install libpcap-dev"
            warn "RHEL/CentOS: sudo dnf install libpcap-devel"
        fi
        
        if ! pkg-config --exists openssl; then
            warn "OpenSSL dev libraries not found. Build might fall back to vendored or fail."
            warn "Debian/Ubuntu: sudo apt-get install libssl-dev"
        fi
    else
        warn "pkg-config not found. Cannot verify library dependencies."
    fi

elif [ "$OS" = "Darwin" ]; then # macOS
    log "Running macOS specific checks..."
    
    # Check for Xcode Command Line Tools (provides headers)
    if ! xcode-select -p &> /dev/null; then
        warn "Xcode Command Line Tools not found. You might need them for headers."
        warn "Run: xcode-select --install"
    fi
    
    # Check for Homebrew openssl (common issue on macOS)
    if [ -d "/opt/homebrew/opt/openssl@3" ]; then
        log "Found Homebrew OpenSSL"
        export OPENSSL_DIR="/opt/homebrew/opt/openssl@3"
    elif [ -d "/usr/local/opt/openssl@3" ]; then
        log "Found Homebrew OpenSSL (Intel)"
        export OPENSSL_DIR="/usr/local/opt/openssl@3"
    fi
fi

# Build
BUILD_TYPE="release"
CMD="cargo build --release"

if [ "$1" == "debug" ]; then
    BUILD_TYPE="debug"
    CMD="cargo build"
elif [ "$1" == "test" ]; then
    log "Running tests..."
    cargo test
    exit $?
elif [ "$1" == "clean" ]; then
    log "Cleaning build artifacts..."
    cargo clean
    exit $?
fi

log "Starting build ($BUILD_TYPE)..."
$CMD

log "Build complete!"
if [ "$BUILD_TYPE" == "release" ]; then
    BIN_PATH="target/release/packetrecorder"
else
    BIN_PATH="target/debug/packetrecorder"
fi

if [ -f "$BIN_PATH" ]; then
    log "Binary available at: $BIN_PATH"
    
    # Capability check for Linux
    if [ "$OS" = "Linux" ]; then
        if command -v setcap &> /dev/null; then
            echo ""
            warn "Packet capture requires elevated privileges or capabilities."
            echo "To run without sudo, execute:"
            echo "  sudo setcap cap_net_raw,cap_net_admin=eip $BIN_PATH"
        fi
    fi
fi
