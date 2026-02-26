#!/usr/bin/env bash
# BoredRoom CRM — Phase 14 Launcher
# Starts API server (3001) + frontend (8769) + Cloudflare tunnel
set -e

CRM_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_DIR="$CRM_DIR/server"
PID_FILE="/tmp/crm-pids.txt"
URL_FILE="/tmp/crm-url.txt"
TUNNEL_LOG="/tmp/crm-tunnel.log"

echo "🚀 Starting BoredRoom CRM Phase 14..."
echo ""

# Kill any existing processes
if [ -f "$PID_FILE" ]; then
  echo "🛑 Stopping old processes..."
  while IFS= read -r pid; do
    kill "$pid" 2>/dev/null || true
  done < "$PID_FILE"
  rm -f "$PID_FILE"
  sleep 1
fi

# Kill anything still using these ports
pkill -f "node server.js" 2>/dev/null || true
pkill -f "python3 -m http.server 8769" 2>/dev/null || true
pkill -f "cloudflared tunnel --url http://localhost:8769" 2>/dev/null || true
# macOS: also try lsof if available
if command -v lsof &> /dev/null; then
  lsof -ti:3001 | xargs kill -9 2>/dev/null || true
  lsof -ti:8769 | xargs kill -9 2>/dev/null || true
fi
sleep 1

# ── Start API Server (port 3001) ───────────────────────────────────────────
echo "📦 Starting API server on port 3001..."
cd "$SERVER_DIR"
node server.js >> /tmp/crm-api.log 2>&1 &
API_PID=$!
echo $API_PID >> "$PID_FILE"
echo "   PID: $API_PID"

# Wait for API to be ready
echo "   Waiting for API..."
for i in $(seq 1 15); do
  if curl -sf http://localhost:3001/api/health > /dev/null 2>&1; then
    echo "   ✅ API ready"
    break
  fi
  sleep 0.5
done

echo "   ✅ Frontend served from API → http://localhost:3001"

# ── Start Cloudflare Tunnel on API port ────────────────────────────────────
echo ""
echo "☁️  Starting Cloudflare tunnel on port 3001..."
rm -f "$TUNNEL_LOG"
cloudflared tunnel --url http://localhost:3001 >> "$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!
echo $TUNNEL_PID >> "$PID_FILE"

# Wait for tunnel URL
echo "   Waiting for tunnel URL..."
TUNNEL_URL=""
for i in $(seq 1 40); do
  TUNNEL_URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$TUNNEL_LOG" 2>/dev/null | head -1)

  if [ -n "$TUNNEL_URL" ]; then
    break
  fi
  sleep 1
done

if [ -n "$TUNNEL_URL" ]; then
  echo "$TUNNEL_URL" > "$URL_FILE"
  echo "   ✅ Tunnel live: $TUNNEL_URL"
else
  echo "   ⚠️  Tunnel URL not captured yet. Check $TUNNEL_LOG"
  echo "http://localhost:8769 (local only)" > "$URL_FILE"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  BoredRoom CRM Phase 14 — LIVE"
echo "  API:      http://localhost:3001"
echo "  Local:    http://localhost:8769"
if [ -n "$TUNNEL_URL" ]; then
  echo "  Public:   $TUNNEL_URL"
fi
echo "  Login:    admin@boredroom.com / BoredRoom2025!"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  Log files:"
echo "    API:      /tmp/crm-api.log"
echo "    Frontend: /tmp/crm-frontend.log"
echo "    Tunnel:   /tmp/crm-tunnel.log"
echo ""
echo "  Press Ctrl+C to stop all services."
echo ""

# Keep alive and watch for Ctrl+C
trap 'echo ""; echo "Stopping..."; while IFS= read -r pid; do kill "$pid" 2>/dev/null || true; done < "$PID_FILE"; rm -f "$PID_FILE"; echo "Done."; exit 0' INT TERM

wait
