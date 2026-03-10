#!/usr/bin/env bash
set -e
echo "═══════════════════════════════════════════════════"
echo "  ArgusWatch AI-Agentic Threat Intelligence v16.4.7"
echo "  Solvent CyberSecurity LLC"
echo "═══════════════════════════════════════════════════"
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Start Docker Desktop first."
    exit 1
fi
docker compose up -d --build
echo ""
echo "  All 10 services starting..."
echo "  Backend auto-migrates, auto-seeds, then serves."
echo ""
echo "  Dashboard:  http://localhost:7777"
echo "  HTTPS:      https://localhost"
echo "  API Docs:   http://localhost:7777/docs"
echo "  Prometheus: http://localhost:9091"
echo ""
echo "  Logs:   docker compose logs -f backend"
echo "  Status: docker ps"
echo "  Stop:   ./stop.sh"
echo "═══════════════════════════════════════════════════"
