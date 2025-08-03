#!/bin/bash
set -e

# Function to handle shutdown gracefully
cleanup() {
    echo "Received shutdown signal, stopping Zeek..."
    if [ -n "$ZEEK_PID" ]; then
        kill -TERM "$ZEEK_PID" 2>/dev/null || true
        wait "$ZEEK_PID" 2>/dev/null || true
    fi
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Set default interface if not provided
if [ "$1" = "zeek" ] && [ "$2" = "-i" ] && [ "$3" = "eth0" ]; then
    # Check if interface exists, if not try to find a suitable one
    if ! ip link show eth0 >/dev/null 2>&1; then
        # Find first non-loopback interface
        INTERFACE=$(ip link show | grep -E '^[0-9]+:' | grep -v lo | head -1 | cut -d: -f2 | tr -d ' ')
        if [ -n "$INTERFACE" ]; then
            echo "Interface eth0 not found, using $INTERFACE instead"
            set -- zeek -i "$INTERFACE" "${@:4}"
        fi
    fi
fi

# Create logs directory if it doesn't exist
mkdir -p /opt/zeek/logs

# Start Zeek in background
echo "Starting Zeek with command: $@"
"$@" &
ZEEK_PID=$!

# Wait for Zeek process
wait "$ZEEK_PID" 