#!/bin/bash
# ShadowRecon - Stealth Security Reconnaissance Framework
# Usage: ./run_scan.sh <target_ip>

if [ -z "$1" ]; then
    echo "Usage: ./run_scan.sh <target_ip>"
    echo "Example: ./run_scan.sh 192.168.1.1"
    exit 1
fi

TARGET=$1

echo ""
echo "==============================================="
echo " ShadowRecon v2.0"
echo " Target: $TARGET"
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
echo " Scan Complete! Check the reports/ directory"
echo "==============================================="
