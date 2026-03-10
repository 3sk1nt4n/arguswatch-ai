#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════
#  ArgusWatch AI v16.4.7 -  One Command Launch
#  Solvent CyberSecurity LLC
#
#  What happens automatically:
#   1. Nukes all existing containers + volumes (clean slate)
#   2. Builds all images from scratch
#   3. Starts 10 Docker services
#   4. entrypoint.sh: waits for PG -> runs 7 migrations -> seeds demo data
#   5. main.py lifespan: 30+ ALTER TABLE -> auto-seeds 4 demo customers (Yahoo, Uber, Shopify, Starbucks)
#      -> triggers recon for each customer domain
#      -> waits for Intel Proxy to collect real threat intel
#      -> auto-correlates detections -> findings
#      -> customer intel matching (links global threats to your customers)
#      -> attribution engine (maps findings to MITRE threat actors)
#      -> campaign detection (clusters related findings)
#      -> exposure scoring (D1-D5 hybrid model per customer)
#   6. Intel Proxy auto-collects from 19+ real public feeds:
#      CISA KEV, MITRE ATT&CK, Feodo, ThreatFox, MalwareBazaar,
#      OpenPhish, NVD+EPSS, RansomWatch, RSS, Pastebin, Hudson Rock,
#      PhishTank+URLhaus, CIRCL MISP, VX-Underground, Grep.app, Ahmia,
#      Pulsedive, + any key-activated: Shodan, OTX, URLScan, HIBP, etc.
#   7. Celery Beat schedules recurring collection every 15 min
#
#  Usage:  ./fresh-start.sh
#  Stop:   ./stop.sh
#  Logs:   docker compose logs -f backend
# ═══════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  ⚡ ArgusWatch AI v16.4.7 -  Fresh Start${NC}"
echo -e "${BOLD}  🛡️  AI-Agentic Multi-Tenant Threat Intelligence${NC}"
echo -e "${BOLD}  ⚠️  This destroys ALL data and rebuilds from scratch${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# ── Pre-flight ──
if ! docker info > /dev/null 2>&1; then
  echo -e "${RED}[✗] Docker is not running. Start Docker Desktop first.${NC}"
  exit 1
fi
echo -e "${GREEN}[✓]${NC} Docker running"

if ! docker compose version > /dev/null 2>&1; then
  echo -e "${RED}[✗] Docker Compose v2 not found.${NC}"
  exit 1
fi
echo -e "${GREEN}[✓]${NC} Docker Compose v2"

# ── Check .env (optional but helpful) ──
if [ -f .env ]; then
  KEY_COUNT=$(grep -c "API_KEY\|TOKEN\|SECRET" .env 2>/dev/null || echo "0")
  echo -e "${GREEN}[✓]${NC} .env found (${KEY_COUNT} API key entries)"
else
  echo -e "${YELLOW}[!]${NC} No .env file -  running with free-tier collectors only"
  echo "    Create .env with API keys to activate more collectors:"
  echo "    SHODAN_API_KEY, OTX_API_KEY, URLSCAN_API_KEY, HIBP_API_KEY"
fi

# ── Nuke everything ──
echo ""
echo -e "${CYAN}[->]${NC} Stopping existing containers..."
docker compose down -v --remove-orphans 2>/dev/null || true
docker network prune -f > /dev/null 2>&1 || true
echo -e "${GREEN}[✓]${NC} Clean slate"

# ── Build + Launch ──
echo ""
echo -e "${CYAN}[->]${NC} Building all images (2-5 min first time)..."
echo ""
docker compose build 2>&1 | grep -E "^(Step|Successfully|Building|#)" | tail -20
echo ""
echo -e "${GREEN}[✓]${NC} Images built"

echo ""
echo -e "${CYAN}[->]${NC} Launching 10 services..."
docker compose up -d
echo ""
echo -e "${GREEN}[✓]${NC} All services started"

echo ""
echo -e "${BOLD}  What's happening now (fully automatic):${NC}"
echo ""
echo "    postgres ......... Database starting"
echo "    redis ............ Cache + queue starting"
echo "    ollama ........... Downloading qwen3:8b (~6.6GB first time)"
echo "    intel-proxy ...... Waiting for DB -> then collecting 19+ feeds"
echo "    recon-engine ..... Waiting for DB -> ready for asset discovery"
echo "    backend .......... Waiting for DB -> migrations -> seed -> bootstrap"
echo "    celery_worker .... Processing async tasks"
echo "    celery_beat ...... Scheduling recurring collection"
echo "    nginx ............ Reverse proxy + self-signed TLS"
echo "    prometheus ....... Metrics collection"
echo ""
echo -e "${BOLD}  The backend will:${NC}"
echo "    1. Run 7 migration scripts + 30 ALTER TABLE statements"
echo "    2. Auto-seed 4 demo customers (Yahoo, Uber, Shopify, Starbucks)"
echo "    3. Trigger recon for each customer domain"
echo "    4. Wait for Intel Proxy to collect real threat intel (~60-90s)"
echo "    5. Correlate detections -> findings"
echo "    6. Match threats to customers"
echo "    7. Attribute to MITRE threat actors"
echo "    8. Detect campaigns"
echo "    9. Calculate exposure scores"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  ACCESS (available after bootstrap completes ~2-3 min):${NC}"
echo ""
echo -e "    Dashboard:   ${CYAN}http://localhost:7777${NC}"
echo -e "    API Docs:    ${CYAN}http://localhost:7777/docs${NC}"
echo -e "    HTTPS:       ${CYAN}https://localhost:9443${NC}"
echo -e "    Proxy Docs:  ${CYAN}http://localhost:9010/docs${NC}"
echo -e "    Recon Docs:  ${CYAN}http://localhost:9011/docs${NC}"
echo -e "    Prometheus:  ${CYAN}http://localhost:9091${NC}"
echo ""
echo -e "${BOLD}  COMMANDS:${NC}"
echo "    Watch logs:     docker compose logs -f backend"
echo "    Watch proxy:    docker compose logs -f intel-proxy"
echo "    Watch all:      docker compose logs -f"
echo "    Status:         docker ps"
echo "    Stop:           ./stop.sh"
echo "    Restart fresh:  ./fresh-start.sh"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  ${BOLD}Solvent CyberSecurity LLC${NC}"
echo -e "  Defending what matters. One command at a time."
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# ── Auto-tail backend logs so user watches the magic ──
echo -e "${YELLOW}[!]${NC} Tailing backend + intel-proxy logs (Ctrl+C to stop watching, services keep running):"
echo ""
docker compose logs -f backend intel-proxy 2>&1
