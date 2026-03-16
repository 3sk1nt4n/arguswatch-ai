#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════
#  ArgusWatch AI v16.4.7 - Interactive Token Setup
#  Solvent CyberSecurity LLC
#
#  Guided wizard to configure API keys and tokens.
#  Creates or updates .env with your credentials.
#
#  Usage:  ./setup-token.sh
#          ./setup-token.sh --check     (show configured keys)
#          ./setup-token.sh --category  (setup specific category)
# ═══════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

ENV_FILE=".env"
ENV_EXAMPLE=".env.example"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Helpers ──────────────────────────────────────────────

banner() {
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  ArgusWatch AI v16.4.7 - Token Setup Wizard${NC}"
  echo -e "${BOLD}  Solvent CyberSecurity LLC${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo ""
}

# Read current value of a key from .env (empty string if unset)
get_env_value() {
  local key="$1"
  if [ -f "$ENV_FILE" ]; then
    grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d'=' -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
  fi
}

# Set a key=value in .env (updates existing or appends)
set_env_value() {
  local key="$1"
  local value="$2"

  if [ ! -f "$ENV_FILE" ]; then
    touch "$ENV_FILE"
  fi

  if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
    # Use a temp file for portable sed in-place editing
    local tmpfile
    tmpfile=$(mktemp)
    sed "s|^${key}=.*|${key}=${value}|" "$ENV_FILE" > "$tmpfile"
    mv "$tmpfile" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

# Prompt for a token with description and current value display
prompt_token() {
  local key="$1"
  local description="$2"
  local signup_url="${3:-}"
  local current
  current=$(get_env_value "$key")

  echo ""
  echo -e "  ${BOLD}${key}${NC}"
  echo -e "  ${DIM}${description}${NC}"
  if [ -n "$signup_url" ]; then
    echo -e "  ${DIM}Get yours: ${signup_url}${NC}"
  fi

  if [ -n "$current" ] && [ "$current" != "CHANGE_ME_TO_A_STRONG_PASSWORD" ] && [ "$current" != "CHANGE_ME_RANDOM_64_CHAR_STRING" ] && [ "$current" != "CHANGE_ME_STRONG_ADMIN_PASSWORD" ]; then
    local masked="${current:0:4}****${current: -4}"
    echo -e "  ${GREEN}Current: ${masked}${NC}"
    read -r -p "  New value (Enter to keep, 'clear' to remove): " input
  else
    read -r -p "  Value (Enter to skip): " input
  fi

  if [ "$input" = "clear" ]; then
    set_env_value "$key" ""
    echo -e "  ${YELLOW}[cleared]${NC}"
  elif [ -n "$input" ]; then
    set_env_value "$key" "$input"
    echo -e "  ${GREEN}[saved]${NC}"
  else
    echo -e "  ${DIM}[skipped]${NC}"
  fi
}

# Section header
section() {
  echo ""
  echo -e "${CYAN}──────────────────────────────────────────────────────────${NC}"
  echo -e "${BOLD}  $1${NC}"
  echo -e "${CYAN}──────────────────────────────────────────────────────────${NC}"
}

# Count configured keys in .env
count_configured() {
  if [ ! -f "$ENV_FILE" ]; then
    echo "0"
    return
  fi
  grep -cE "^[A-Z_]+(API_KEY|TOKEN|SECRET|PASSWORD)=.+" "$ENV_FILE" 2>/dev/null | head -1 || echo "0"
}

# ── Check Mode ───────────────────────────────────────────

check_tokens() {
  banner
  echo -e "${BOLD}  Configured Token Status:${NC}"
  echo ""

  if [ ! -f "$ENV_FILE" ]; then
    echo -e "  ${RED}No .env file found.${NC} Run ./setup-token.sh to create one."
    echo ""
    exit 0
  fi

  # Required
  section "Required"
  for key in POSTGRES_PASSWORD JWT_SECRET_KEY ADMIN_PASSWORD; do
    val=$(get_env_value "$key")
    if [ -n "$val" ] && [[ "$val" != CHANGE_ME* ]]; then
      echo -e "  ${GREEN}[ok]${NC} ${key}"
    else
      echo -e "  ${RED}[missing]${NC} ${key}"
    fi
  done

  # AI Providers
  section "AI Providers (optional - Ollama is free default)"
  for key in ANTHROPIC_API_KEY OPENAI_API_KEY GOOGLE_AI_API_KEY; do
    val=$(get_env_value "$key")
    if [ -n "$val" ]; then
      echo -e "  ${GREEN}[ok]${NC} ${key}"
    else
      echo -e "  ${DIM}[  ]${NC} ${key}"
    fi
  done

  # Free threat intel
  section "Free Threat Intel Keys"
  for key in GITHUB_TOKEN OTX_API_KEY URLSCAN_API_KEY CENSYS_API_ID CENSYS_API_SECRET ABUSEIPDB_API_KEY VIRUSTOTAL_API_KEY; do
    val=$(get_env_value "$key")
    if [ -n "$val" ]; then
      echo -e "  ${GREEN}[ok]${NC} ${key}"
    else
      echo -e "  ${DIM}[  ]${NC} ${key}"
    fi
  done

  # Paid keys
  section "Paid Keys"
  for key in HIBP_API_KEY SHODAN_API_KEY GRAYHATWARFARE_API_KEY LEAKIX_API_KEY PULSEDIVE_API_KEY INTELX_API_KEY BREACH_DIRECTORY_API_KEY GREYNOISE_API_KEY BINARYEDGE_API_KEY; do
    val=$(get_env_value "$key")
    if [ -n "$val" ]; then
      echo -e "  ${GREEN}[ok]${NC} ${key}"
    else
      echo -e "  ${DIM}[  ]${NC} ${key}"
    fi
  done

  # Enterprise
  section "Enterprise Keys"
  for key in SPYCLOUD_API_KEY RECORDED_FUTURE_KEY CROWDSTRIKE_CLIENT_ID CROWDSTRIKE_SECRET SOCRADAR_API_KEY CYBERINT_API_KEY FLARE_API_KEY CYBERSIXGILL_CLIENT_ID CYBERSIXGILL_SECRET MANDIANT_API_KEY; do
    val=$(get_env_value "$key")
    if [ -n "$val" ]; then
      echo -e "  ${GREEN}[ok]${NC} ${key}"
    else
      echo -e "  ${DIM}[  ]${NC} ${key}"
    fi
  done

  # Notifications
  section "Notifications"
  for key in SLACK_WEBHOOK_URL TELEGRAM_BOT_TOKEN SMTP_HOST; do
    val=$(get_env_value "$key")
    if [ -n "$val" ]; then
      echo -e "  ${GREEN}[ok]${NC} ${key}"
    else
      echo -e "  ${DIM}[  ]${NC} ${key}"
    fi
  done

  echo ""
  local total
  total=$(count_configured)
  echo -e "  ${BOLD}Total configured: ${total} keys${NC}"
  echo ""
}

# ── Setup Categories ─────────────────────────────────────

setup_required() {
  section "Required Configuration"
  echo -e "  These are needed for the platform to run securely."
  echo ""

  # Generate defaults for convenience
  local default_jwt
  default_jwt=$(head -c 48 /dev/urandom 2>/dev/null | base64 2>/dev/null | tr -d '/+=' | head -c 64 || echo "")

  # Database
  local pg_val
  pg_val=$(get_env_value "POSTGRES_PASSWORD")
  echo ""
  echo -e "  ${BOLD}POSTGRES_PASSWORD${NC}"
  echo -e "  ${DIM}Database password - use a strong random string${NC}"
  if [ -n "$pg_val" ] && [[ "$pg_val" != CHANGE_ME* ]]; then
    echo -e "  ${GREEN}Already configured${NC}"
    read -r -p "  Change? (y/N): " change
    if [[ "$change" =~ ^[Yy] ]]; then
      read -r -p "  New password: " input
      [ -n "$input" ] && set_env_value "POSTGRES_PASSWORD" "$input" && echo -e "  ${GREEN}[saved]${NC}"
    fi
  else
    read -r -p "  Password (Enter for auto-generated): " input
    if [ -n "$input" ]; then
      set_env_value "POSTGRES_PASSWORD" "$input"
    else
      local auto_pw
      auto_pw=$(head -c 24 /dev/urandom 2>/dev/null | base64 2>/dev/null | tr -d '/+=' | head -c 32 || echo "arguswatch_$(date +%s)")
      set_env_value "POSTGRES_PASSWORD" "$auto_pw"
      echo -e "  ${GREEN}[auto-generated]${NC}"
    fi
  fi

  # JWT Secret
  echo ""
  echo -e "  ${BOLD}JWT_SECRET_KEY${NC}"
  echo -e "  ${DIM}Secret for signing auth tokens - must be random 64+ chars${NC}"
  local jwt_val
  jwt_val=$(get_env_value "JWT_SECRET_KEY")
  if [ -n "$jwt_val" ] && [[ "$jwt_val" != CHANGE_ME* ]]; then
    echo -e "  ${GREEN}Already configured${NC}"
  else
    if [ -n "$default_jwt" ]; then
      set_env_value "JWT_SECRET_KEY" "$default_jwt"
      echo -e "  ${GREEN}[auto-generated 64-char secret]${NC}"
    else
      read -r -p "  Secret key: " input
      [ -n "$input" ] && set_env_value "JWT_SECRET_KEY" "$input" && echo -e "  ${GREEN}[saved]${NC}"
    fi
  fi

  # Admin password
  echo ""
  echo -e "  ${BOLD}ADMIN_PASSWORD${NC}"
  echo -e "  ${DIM}Password for the bootstrap admin account${NC}"
  local admin_val
  admin_val=$(get_env_value "ADMIN_PASSWORD")
  if [ -n "$admin_val" ] && [[ "$admin_val" != CHANGE_ME* ]]; then
    echo -e "  ${GREEN}Already configured${NC}"
    read -r -p "  Change? (y/N): " change
    if [[ "$change" =~ ^[Yy] ]]; then
      read -r -p "  New admin password: " input
      [ -n "$input" ] && set_env_value "ADMIN_PASSWORD" "$input" && echo -e "  ${GREEN}[saved]${NC}"
    fi
  else
    read -r -p "  Admin password: " input
    if [ -n "$input" ]; then
      set_env_value "ADMIN_PASSWORD" "$input"
      echo -e "  ${GREEN}[saved]${NC}"
    else
      echo -e "  ${YELLOW}[skipped - you must set this before running]${NC}"
    fi
  fi
}

setup_ai_providers() {
  section "AI Providers (optional)"
  echo -e "  Local Ollama (Qwen 3 8B) runs for free by default."
  echo -e "  Add cloud providers for better reasoning quality."

  prompt_token "ANTHROPIC_API_KEY" \
    "Claude - best reasoning, \$5/\$25 per M tokens" \
    "https://console.anthropic.com/settings/keys"

  prompt_token "OPENAI_API_KEY" \
    "GPT-4o - fastest responses, \$1.75/\$14 per M tokens" \
    "https://platform.openai.com/api-keys"

  prompt_token "GOOGLE_AI_API_KEY" \
    "Gemini - strong benchmarks, \$2/\$12 per M tokens" \
    "https://aistudio.google.com/app/apikey"
}

setup_free_intel() {
  section "Free Threat Intel Keys (\$0/month)"
  echo -e "  These are all free - each takes ~2 minutes to get."
  echo -e "  They significantly expand your threat intelligence coverage."

  prompt_token "GITHUB_TOKEN" \
    "Classic token (zero scopes) - GitHub secrets search + Gist scraper (5000 req/hr)" \
    "https://github.com/settings/tokens"

  prompt_token "OTX_API_KEY" \
    "AlienVault OTX - 200K+ community threat intel pulses" \
    "https://otx.alienvault.com/"

  prompt_token "URLSCAN_API_KEY" \
    "URLScan.io - 1000 phishing/malware URL scans per day" \
    "https://urlscan.io/user/signup/"

  prompt_token "CENSYS_API_ID" \
    "Censys API ID - exposed certificates + services" \
    "https://search.censys.io/account/api"

  prompt_token "CENSYS_API_SECRET" \
    "Censys API Secret (same page as API ID)" \
    "https://search.censys.io/account/api"

  prompt_token "ABUSEIPDB_API_KEY" \
    "AbuseIPDB - IP reputation checks (1000/day free)" \
    "https://www.abuseipdb.com/account/api"

  prompt_token "VIRUSTOTAL_API_KEY" \
    "VirusTotal - malware hash + URL reputation (500/day free)" \
    "https://www.virustotal.com/gui/my-apikey"
}

setup_paid_intel() {
  section "Paid Keys (high value, low cost)"
  echo -e "  Optional paid services that add significant capabilities."

  prompt_token "HIBP_API_KEY" \
    "Have I Been Pwned - breach database (\$3.50/mo)" \
    "https://haveibeenpwned.com/API/Key"

  prompt_token "SHODAN_API_KEY" \
    "Shodan - exposed servers + open ports (\$49/mo or free limited)" \
    "https://account.shodan.io/"

  prompt_token "GRAYHATWARFARE_API_KEY" \
    "GrayHatWarfare - open S3/Azure/GCS buckets (free tier)" \
    "https://grayhatwarfare.com/api"

  prompt_token "LEAKIX_API_KEY" \
    "LeakIX - exposed services + leaked data (free tier)" \
    "https://leakix.net/auth/login"

  prompt_token "PULSEDIVE_API_KEY" \
    "Pulsedive - community threat intel enrichment (free tier)" \
    "https://pulsedive.com/account"

  prompt_token "INTELX_API_KEY" \
    "Intelligence X - dark web + paste + leak search (paid)" \
    "https://intelx.io/account?tab=developer"

  prompt_token "GREYNOISE_API_KEY" \
    "GreyNoise - internet scanner identification (free community)" \
    "https://greynoise.io"

  prompt_token "BINARYEDGE_API_KEY" \
    "BinaryEdge - exposed services + vulnerabilities (free tier)" \
    "https://binaryedge.io"
}

setup_enterprise() {
  section "Enterprise Keys (sales-gated)"
  echo -e "  Only configure these if you have an active subscription."

  prompt_token "SPYCLOUD_API_KEY" \
    "SpyCloud - live stealer logs"

  prompt_token "RECORDED_FUTURE_KEY" \
    "Recorded Future - credential alerts"

  prompt_token "CROWDSTRIKE_CLIENT_ID" \
    "CrowdStrike Falcon - client ID"

  prompt_token "CROWDSTRIKE_SECRET" \
    "CrowdStrike Falcon - client secret"

  prompt_token "MANDIANT_API_KEY" \
    "Mandiant - threat intelligence"

  prompt_token "SOCRADAR_API_KEY" \
    "SocRadar - brand monitoring"

  prompt_token "CYBERINT_API_KEY" \
    "CyberInt - ATO confirmation"

  prompt_token "FLARE_API_KEY" \
    "Flare - dark web credentials"

  prompt_token "CYBERSIXGILL_CLIENT_ID" \
    "Cybersixgill - client ID"

  prompt_token "CYBERSIXGILL_SECRET" \
    "Cybersixgill - client secret"
}

setup_notifications() {
  section "Notifications (optional)"
  echo -e "  Configure alert delivery channels."

  prompt_token "SLACK_WEBHOOK_URL" \
    "Slack incoming webhook for real-time alerts" \
    "https://api.slack.com/messaging/webhooks"

  prompt_token "TELEGRAM_BOT_TOKEN" \
    "Telegram bot token (optional - public channels work without)" \
    "https://core.telegram.org/bots#botfather"

  echo ""
  echo -e "  ${BOLD}Email (SMTP) - configure all 3 for email alerts:${NC}"

  prompt_token "SMTP_HOST" \
    "SMTP server (e.g. smtp.gmail.com)"

  local smtp_host
  smtp_host=$(get_env_value "SMTP_HOST")
  if [ -n "$smtp_host" ]; then
    prompt_token "SMTP_USER" \
      "SMTP username / email address"

    prompt_token "SMTP_PASS" \
      "SMTP password or app password"
  fi
}

# ── Category Menu ────────────────────────────────────────

show_menu() {
  echo -e "  Which tokens would you like to configure?"
  echo ""
  echo -e "    ${BOLD}1${NC}) All (guided walkthrough)"
  echo -e "    ${BOLD}2${NC}) Required only (database + auth)"
  echo -e "    ${BOLD}3${NC}) AI providers (Claude, GPT, Gemini)"
  echo -e "    ${BOLD}4${NC}) Free threat intel keys"
  echo -e "    ${BOLD}5${NC}) Paid threat intel keys"
  echo -e "    ${BOLD}6${NC}) Enterprise keys"
  echo -e "    ${BOLD}7${NC}) Notifications (Slack, Telegram, Email)"
  echo -e "    ${BOLD}c${NC}) Check status (show configured keys)"
  echo -e "    ${BOLD}q${NC}) Quit"
  echo ""
  read -r -p "  Choice [1]: " choice
  choice="${choice:-1}"
}

# ── Summary ──────────────────────────────────────────────

show_summary() {
  echo ""
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  Setup Complete${NC}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo ""

  local total
  total=$(count_configured)
  echo -e "  ${BOLD}${total} keys configured${NC} in .env"
  echo ""

  # Check required
  local missing=0
  for key in POSTGRES_PASSWORD JWT_SECRET_KEY ADMIN_PASSWORD; do
    val=$(get_env_value "$key")
    if [ -z "$val" ] || [[ "$val" == CHANGE_ME* ]]; then
      echo -e "  ${RED}[!] ${key} still needs to be set${NC}"
      missing=$((missing + 1))
    fi
  done

  if [ "$missing" -eq 0 ]; then
    echo -e "  ${GREEN}All required keys are configured.${NC}"
  fi

  echo ""
  echo -e "  ${BOLD}Next steps:${NC}"
  echo "    ./start.sh          Start all services"
  echo "    ./fresh-start.sh    Clean start with demo data"
  echo "    ./setup-token.sh -c Check token status anytime"
  echo ""
  echo -e "  ${DIM}Keys can also be set at runtime via the API:${NC}"
  echo -e "  ${DIM}POST /api/settings/ai-keys (no restart needed)${NC}"
  echo ""
}

# ── Main ─────────────────────────────────────────────────

main() {
  banner

  # Handle flags
  case "${1:-}" in
    --check|-c)
      check_tokens
      exit 0
      ;;
    --category|-C)
      # Jump straight to menu
      ;;
    --help|-h)
      echo "  Usage: ./setup-token.sh [OPTIONS]"
      echo ""
      echo "  Options:"
      echo "    (none)       Interactive setup wizard"
      echo "    --check, -c  Show which tokens are configured"
      echo "    --help, -h   Show this help"
      echo ""
      exit 0
      ;;
  esac

  # Ensure .env exists
  if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
      cp "$ENV_EXAMPLE" "$ENV_FILE"
      echo -e "  ${GREEN}[+]${NC} Created .env from .env.example"
    else
      touch "$ENV_FILE"
      echo -e "  ${GREEN}[+]${NC} Created empty .env"
    fi
  else
    echo -e "  ${GREEN}[ok]${NC} Using existing .env"
  fi

  show_menu

  case "$choice" in
    1)
      setup_required
      setup_ai_providers
      setup_free_intel
      setup_paid_intel
      setup_notifications
      ;;
    2)
      setup_required
      ;;
    3)
      setup_ai_providers
      ;;
    4)
      setup_free_intel
      ;;
    5)
      setup_paid_intel
      ;;
    6)
      setup_enterprise
      ;;
    7)
      setup_notifications
      ;;
    c|C)
      check_tokens
      exit 0
      ;;
    q|Q)
      echo -e "  ${DIM}Bye!${NC}"
      exit 0
      ;;
    *)
      echo -e "  ${RED}Invalid choice${NC}"
      exit 1
      ;;
  esac

  show_summary
}

main "$@"
