#!/bin/bash
# ═══════════════════════════════════════════════════════════
# ArgusWatch V13 - Clean Deploy Script
# Wipes old database, rebuilds, and seeds fresh data
# ═══════════════════════════════════════════════════════════
set -e

echo "═══════════════════════════════════════════════════════"
echo "  ArgusWatch V13 - CLEAN DEPLOY"
echo "═══════════════════════════════════════════════════════"

echo ""
echo "  [1/4] Stopping all containers and removing volumes..."
docker compose down -v 2>/dev/null || docker-compose down -v 2>/dev/null || true

echo "  [2/4] Rebuilding backend image..."
docker compose build --no-cache backend 2>/dev/null || docker-compose build --no-cache backend 2>/dev/null

echo "  [3/4] Starting fresh (clean database)..."
docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null

echo "  [4/4] Waiting for startup (seeding demo data)..."
echo "         This takes ~30 seconds..."
sleep 30

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅ ArgusWatch V13 READY"
echo "  Dashboard: http://localhost:7777"
echo "  API Docs:  http://localhost:7777/docs"
echo ""
echo "  Check logs: docker compose logs -f backend"
echo "═══════════════════════════════════════════════════════"
