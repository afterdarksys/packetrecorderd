#!/bin/bash
# Capture DNS traffic (includes DNS, DOT, DOH)
# Usage: ./scripts/capture_dns.sh <interface> [duration_seconds]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <interface> [duration_seconds]"
    exit 1
fi

INTERFACE="$1"
DURATION="${2:-0}"
DATABASE="dns_captures.db"

# BPF filter for DNS traffic:
# - Port 53 (UDP/TCP DNS)
# - Port 853 (DNS over TLS)
# - Port 443 (DNS over HTTPS - will also capture other HTTPS)
FILTER="port 53 or port 853 or port 443"

echo "Capturing DNS traffic on $INTERFACE"
echo "Filter: $FILTER"
echo ""

ARGS="capture --interface $INTERFACE --database $DATABASE --filter \"$FILTER\""

if [ "$DURATION" -gt 0 ]; then
    ARGS="$ARGS --duration $DURATION"
fi

eval "$SCRIPT_DIR/run.sh" $ARGS
