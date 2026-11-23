#!/usr/bin/env bash
set -e

# Change to script directory
cd "$(dirname "$0")"

if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

echo "==================================================="
echo "  SWA AI - Security Operations Center & Cyber Hub"
echo "==================================================="
echo "[+] Starting SNMK Web Server (default port 8000; first free port is used)."
echo "[+] Browser will open automatically at the actual address."
echo "[+] Keep this terminal window OPEN while using SWA."
echo ""

python3 run.py "$@"
