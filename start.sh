#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

# Install deps if needed
if [ ! -d "$ROOT/backend/.venv" ]; then
  echo "→ Creating Python venv..."
  python3 -m venv "$ROOT/backend/.venv"
  "$ROOT/backend/.venv/bin/pip" install -q --no-cache-dir -r "$ROOT/backend/requirements.txt"
fi

if [ ! -d "$ROOT/frontend/node_modules" ]; then
  echo "→ Installing frontend dependencies..."
  (cd "$ROOT/frontend" && npm install --silent)
fi

# Cleanup on exit
cleanup() {
  echo ""
  echo "→ Shutting down..."
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

# Start backend
echo "→ Starting backend on http://localhost:8001"
cd "$ROOT/backend"
PYTHONPATH="$ROOT/backend" \
  "$ROOT/backend/.venv/bin/uvicorn" main:app --host 0.0.0.0 --port 8001 --reload &
BACKEND_PID=$!

# Start frontend
echo "→ Starting frontend on http://localhost:3000"
cd "$ROOT/frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "  Frontend : http://localhost:3000"
echo "  API      : http://localhost:8001/web/api/v2.1"
echo "  Swagger  : http://localhost:8001/web/api/v2.1/doc"
echo ""
echo "  Press Ctrl+C to stop"
echo ""

wait
