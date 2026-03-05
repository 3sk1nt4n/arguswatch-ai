#!/usr/bin/env bash
echo "🛑 ArgusWatch AI - Stopping all services..."
docker compose down
echo "✅ All services stopped."
echo "   Data preserved. Run ./start.sh to restart."
echo "   Run ./fresh-start.sh to wipe and rebuild."
