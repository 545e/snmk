#!/usr/bin/env bash
# SNMK — Linux/macOS Server Shutdown Script
set -e

cd "$(dirname "$0")"

echo "==================================================="
echo "  SNMK — Shutdown Server"
echo "==================================================="

CONFIGURED_PORT="${SWA_PORT:-8000}"
stop_pid() {
    local pid="$1"
    [ -n "$pid" ] || return 1
    # Never kill an unrelated process just because a PID file went stale.
    if ! ps -p "$pid" > /dev/null 2>&1; then
        return 1
    fi
    local cmd=""
    cmd="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    case "$cmd" in
        *run.py*|*web.server*|*uvicorn*) ;;
        *) return 1 ;;
    esac
    echo "[+] Stopping SNMK server (PID $pid)..."
    kill -TERM "$pid" 2>/dev/null || kill -9 "$pid" 2>/dev/null || true
    return 0
}

if [ -f ".swa.pid" ]; then
    PID=$(cat .swa.pid 2>/dev/null || true)
    if stop_pid "$PID"; then
        rm -f .swa.pid
        echo "[OK] SNMK server stopped."
        exit 0
    fi
    rm -f .swa.pid
fi

# Fallback: configured port plus the automatic fallback used by run.py.
for port in "$CONFIGURED_PORT" 8000 8001; do
    L_PID=$(lsof -ti:"$port" 2>/dev/null || true)
    if [ -n "$L_PID" ] && stop_pid "$L_PID"; then
        echo "[OK] SNMK server stopped."
        exit 0
    fi
done

echo "[i] No active SNMK server found."
