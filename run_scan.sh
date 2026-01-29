#!/bin/bash
# ShadowRecon v3.0 - Stealth Security Reconnaissance Framework
# All scans routed through Tor network
# Usage: ./run_scan.sh <target_ip>

if [ -z "$1" ]; then
    echo "Usage: ./run_scan.sh <target_ip>"
    echo "Example: ./run_scan.sh 192.168.1.1"
    echo ""
    echo "Note: Tor must be running before scanning!"
    exit 1
fi

TARGET=$1

echo ""
echo "==============================================="
echo " ShadowRecon v3.0"
echo " Target: $TARGET"
echo " Mode: Tor-Routed Stealth Scan"
echo "==============================================="
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3 is not installed"
    exit 1
fi

# Install dependencies if needed
echo "[*] Checking dependencies..."
pip3 install -q -r requirements.txt

echo "[*] Starting scan..."
echo ""

python3 main.py "$TARGET" --verbose

echo ""
echo "==============================================="
echo " Scan Complete!"
echo " Reports: reports/$TARGET/<timestamp>/"
echo "==============================================="
