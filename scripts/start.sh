#!/bin/bash
set -e
echo "═══════════════════════════════════════"
echo "  ArgusWatch AI - Starting"
echo "═══════════════════════════════════════"
# Support both docker compose v2 and docker-compose v1
if command -v docker compose &>/dev/null; then
  docker compose up -d
else
  docker-compose up -d
fi
echo ""
echo "  Dashboard: http://localhost:7777"
echo "  API Docs:  http://localhost:7777/docs"
echo ""
echo "  Auto-runs: migration -> seed -> CISA KEV"
echo "  Logs: docker logs -f arguswatch-backend"
echo "═══════════════════════════════════════"
