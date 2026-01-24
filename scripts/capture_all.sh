#!/bin/bash
# Example script to capture all traffic on a network interface
# Usage: ./scripts/capture_all.sh <interface> [duration_seconds]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <interface> [duration_seconds]"
    echo ""
    echo "To list available interfaces:"
    echo "  $0 list"
    exit 1
fi

if [ "$1" = "list" ]; then
    "$SCRIPT_DIR/run.sh" list-interfaces
    exit 0
fi

INTERFACE="$1"
DURATION="${2:-0}"  # Default: capture indefinitely
DATABASE="captures.db"

echo "Starting packet capture on interface: $INTERFACE"
echo "Database: $DATABASE"
if [ "$DURATION" -gt 0 ]; then
    echo "Duration: $DURATION seconds"
else
    echo "Duration: indefinite (press Ctrl+C to stop)"
fi
echo ""

ARGS="capture --interface $INTERFACE --database $DATABASE"

if [ "$DURATION" -gt 0 ]; then
    ARGS="$ARGS --duration $DURATION"
fi

"$SCRIPT_DIR/run.sh" $ARGS
