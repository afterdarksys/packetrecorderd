#!/bin/bash
# Test script for forensics features

set -e

echo "=== PacketRecorder Forensics Test ==="
echo ""

# Set API keys from ~/useful_api_keys
export DARKAPI_API_KEY="internal-dnsscience-unlimited"
export DARKAPI_BASE_URL="https://api.darkapi.io"

echo "✓ DarkAPI configured"
echo ""

# Build if needed
if [ ! -f "./target/release/packetrecorder" ]; then
    echo "Building packetrecorder..."
    cargo build --release
    echo ""
fi

echo "=== Testing DNS Threat Detection ===" 
echo "The following should trigger local forensics alerts:"
echo ""
echo "1. DGA Detection: random-looking domains"
echo "2. Suspicious TLDs: .tk, .ml, .ga domains"
echo "3. DNS Tunneling: long subdomains"
echo "4. Bot Detection: curl/wget/python-requests User-Agents"
echo "5. Datacenter IPs: AWS/GCP/Azure ranges"
echo ""

# Create test DNS queries using dig
echo "Testing with curl (should detect bot):"
curl -A "python-requests/2.28.0" -s http://httpbin.org/user-agent || true
echo ""

echo "Testing DGA-like domain:"
dig xqzvkpwmlrtjkb.com +short || true
echo ""

echo "Testing suspicious TLD:"
dig malware.tk +short || true
echo ""

echo "=== Run actual packet capture ===" 
echo "To test live:"
echo ""
echo "sudo ./target/release/packetrecorder capture \\"
echo "  --interface en0 \\"
echo "  --database test_forensics.db \\"
echo "  --duration 60 \\"
echo "  --verbose"
echo ""
echo "Then visit various sites, run curl commands, etc."
echo "Watch for forensics alerts in the output!"
echo ""
echo "Examples to trigger alerts:"
echo "  curl http://example.com  # Bot detection"
echo "  wget http://example.com  # Bot detection"  
echo "  dig very.long.subdomain.name.example.com  # DNS tunneling"
echo "  dig xbhklmwqrtz.com  # DGA detection"
echo ""
