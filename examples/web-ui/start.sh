#!/usr/bin/env bash
# Start the web UI server.
# Usage: PORT=8080 ./start.sh
set -euo pipefail
PORT="${PORT:-3000}"
echo "Starting VuleEngine Web UI on port $PORT..."
bun run examples/web-ui/start.ts
