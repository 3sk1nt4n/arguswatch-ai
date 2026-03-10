<div align="center">

<img src="backend/arguswatch/static/solvent-icon.svg" alt="Solvent CyberSecurity" width="48" height="48">

# ArgusWatch AI-Agentic Threat Intelligence Platform

### v16.4.7 -  Multi-Tenant MSSP Platform | 47 Collectors | 111 IOC Types | 99 MITRE Mappings | 21 Admin APIs

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED.svg)](https://docker.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com)
[![Codebase](https://img.shields.io/badge/codebase-33%2C500%2B_lines-orange.svg)]()
[![IOC Types](https://img.shields.io/badge/IOC_types-111-brightgreen.svg)]()
[![Patents](https://img.shields.io/badge/patents-4_USPTO_filed-purple.svg)]()


*Zero fake data. Real threat intelligence. Every finding has a provable evidence trail.*

---

[Quick Start](#-quick-start) · [Architecture](#-system-architecture) · [Docker Services](#-10-docker-services) · [Code Structure](#-code-structure) · [Collectors](#-47-collectors) · [IOC Types](#-86-ioc-types) · [Matching](#-8-strategy-matching-engine) · [AI Pipeline](#-ai-pipeline) · [Dashboard](#-dashboard-pages) · [API](#-api-reference) · [Docker Commands](#-docker-commands) · [Testing](#-testing) · [Roadmap](#️-roadmap)

</div>

---

## What is ArgusWatch?

ArgusWatch is a production-grade, multi-tenant AI-Agentic threat intelligence platform for MSSPs. It collects IOCs from 47 real threat feeds, correlates them against customer assets using 8 matching strategies, and presents every finding with a provable evidence trail. AI runs locally on Qwen 3 8B via Ollama with GPU acceleration (free, private, 2-5s responses), with one-click switching to Claude, GPT, or Gemini from the dashboard header.


<img width="1343" height="964" alt="1" src="https://github.com/user-attachments/assets/9ae21a8b-fd4f-4d86-ba90-95450ad28b2a" />
<img width="1343" height="964" alt="Threat Universe" src="https://github.com/user-attachments/assets/c27fee48-a8ed-4d07-a140-ed154241257f" />
<img width="1343" height="964" alt="3" src="https://github.com/user-attachments/assets/3897ba4d-c37f-4e3b-a9c7-d8e63feb2277" />
<img width="1005" height="963" alt="2" src="https://github.com/user-attachments/assets/b32e27f4-0d6e-4b93-855e-19a7aa4fe00e" />





### Why "AI-Agentic"?

The core of ArgusWatch is an **autonomous AI orchestrator** that investigates threats the way a human SOC analyst would -  but faster:

```
Detection arrives: "CVE-2026-3404 found in Uber's tech stack"
  -> AI calls query_customers("Uber")     -> learns: industry=transportation
  -> AI calls search_cve("CVE-2026-3404") -> learns: CVSS 8.1, affects Java
  -> AI calls check_exposure(customer=4)   -> learns: D1=45, high attack surface
  -> AI calls query_actors(sector="transport") -> finds: APT41 targets this sector
  -> DECIDES: "CRITICAL -  active exploitation + targeted sector + high exposure"
```

No human told it which tools to use or in what order. The AI autonomously picks from 9 tools, observes results, reasons, and iterates up to 12 times until it reaches a conclusion.

### What the AI Does vs What Automation Does

| Component | How it works | Type | Adds value vs if-else? |
|-----------|-------------|------|----------------------|
| **AI Bar** | Auto-detects IOC (regex, 0ms) -> compromise check (2-10s) -> LLM investigates results, decides follow-ups, writes analyst brief (30-90s local, 5-10s cloud) | ✅ **Agentic** | **YES** -  LLM decides what to investigate next based on results |
| **Investigation Narrative** | AI writes analyst-quality context from raw IOC data | ✅ **AI-Generated** | **YES** -  can't replicate with templates |
| **Reliable Chat Agent** | NL questions -> classify -> deterministic query -> LLM summarize | ✅ **AI-Powered** | **YES** -  NL against live DB |
| **9-Tool Orchestrator** | AI picks tools, observes, reasons, iterates | ✅ **Agentic** | Redundant -  linear pipeline is faster |
| **Severity Triage** | AI fills in severity JSON per finding | Single LLM call | IOC v10 lookup table is better |
| **FP Check** | AI flags likely FPs | Single LLM call | 12 HIGH-FP types already identified |
| **FP Memory** | Records analyst FP decisions, auto-closes repeats | Hit counter + CIDR | Useful automation (not ML) |
| 47 Collectors | Scheduled HTTP fetch + parse + store | Automation | |
| 8 Matching Strategies | Regex + domain matching + edit distance | Rule-Based | |
| 86 IOC Patterns | Static regex patterns | Pattern Matching | |
| 12 Remediation Playbooks | Template-based response step generation | Rule-Based | |
| 5-Dimension Exposure Score | Weighted mathematical formula | Formula | |

**3 components where AI genuinely adds value code can't replicate:** the AI Bar (unified IOC search + auto-classification + compromise checking), investigation narratives, and the reliable chat agent. The rest is solid engineering.

---

## 🚀 Quick Start

### Prerequisites

- **Docker Desktop** or **Rancher Desktop** (any OS)
- **Ollama** (recommended: native install for GPU acceleration)
- 8GB+ RAM, 20GB disk space

### Step 1: Install Docker

**Windows (Rancher Desktop):**
Download from [rancherdesktop.io](https://rancherdesktop.io/) and install. Select **dockerd (moby)** as the container engine.

**Windows (Docker Desktop):**
Download from [docker.com](https://www.docker.com/products/docker-desktop/) and install. Enable WSL 2 backend.

**macOS / Linux:**
```bash
# macOS
brew install --cask docker

# Linux (Ubuntu/Debian)
curl -fsSL https://get.docker.com | sh
```

### Step 2: Install Ollama (GPU-Accelerated AI)

Native Ollama gets full GPU access. Docker Ollama runs on CPU only (20x slower).

```bash
# Windows
winget install Ollama.Ollama

# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh
```

Pull the AI model (5.2GB download):

```bash
ollama pull qwen3:8b
```

Verify GPU:

```bash
ollama run qwen3:8b "say hello" --verbose
# Look for: eval rate > 40 tokens/s = GPU
# If eval rate < 10 tokens/s = CPU (still works, just slower)
```

**AI Model Options:**

| Model | Size | Speed (GPU) | Speed (CPU) | Best for |
|-------|------|-------------|-------------|----------|
| `qwen3:4b` | 2.7GB | 150+ tok/s | 10-15 tok/s | Low VRAM, fast responses |
| `qwen3:8b` | 5.2GB | 100+ tok/s | 5-8 tok/s | **Recommended** - best balance |
| `qwen3.5:9b` | 6.6GB | 80+ tok/s | 3-5 tok/s | Best quality (when Ollama supports it) |

GPU vs CPU: any NVIDIA GPU with 6GB+ VRAM gives 10-20x speedup. AMD/Apple Silicon also supported via Ollama.

### Step 3: Configure

```bash
cp .env.example .env
# Edit .env - set OLLAMA_URL and paste any API keys you have
```

Key settings in `.env`:

```bash
# Point to native Ollama (GPU) instead of Docker Ollama (CPU)
OLLAMA_URL=http://host.docker.internal:11434
OLLAMA_MODEL=qwen3:8b

# Optional: add cloud AI providers for one-click switching
ANTHROPIC_API_KEY=sk-ant-...    # Claude
OPENAI_API_KEY=sk-...           # GPT
GOOGLE_AI_API_KEY=AIza...       # Gemini
```

### Step 4: Launch

```bash
docker compose up -d --build
# Takes 2-3 minutes on first boot

# Open dashboard (no login required)
# http://localhost:7777
```

### What Happens Automatically on First Boot

```
1. PostgreSQL initializes with 12 migration scripts
2. 6 demo customers auto-seeded (HackerOne bug bounty targets)
3. Intel Proxy collects 3,000-4,000 IOCs from 47 feeds
4. Correlation routes detections to customers
5. 8-strategy matching creates findings
6. Exposure scores calculated (D1-D5 formula)
7. Attribution links findings to 180+ threat actors
8. Campaign detection groups related findings
9. Dashboard fully populated - ready to use
```

No manual steps required. Everything is automatic.

### Demo Customers (Pre-Seeded)

All 6 companies have active HackerOne bug bounty programs, making reconnaissance and threat intel collection fully authorized for security research:

| Customer | Domain | Industry | Why included |
|----------|--------|----------|-------------|
| **Yahoo** | yahoo.com | Technology | Large attack surface, frequent breaches, active bug bounty |
| **Uber** | uber.com | Transportation | High-value target, PII-heavy, active bug bounty |
| **Shopify** | shopify.com | Technology | E-commerce platform, payment data exposure |
| **Starbucks** | starbucks.com | Retail | Brand monitoring, retail-sector threats |
| **GitHub** | github.com | Technology | Code/secret exposure, developer-targeted attacks |
| **VulnWeb Demo** | vulnweb.com | Technology | Acunetix test site, intentionally vulnerable |

### Docker Commands

```bash
# Start
docker compose up -d

# Stop
docker compose down

# Fresh deploy (wipes all data)
docker compose down -v && docker compose up -d --build

# View logs
docker logs arguswatch-backend --tail 50
docker logs arguswatch-intel-proxy --tail 50

# Rebuild single service
docker compose build --no-cache backend && docker compose up -d
```

---

## 🏗️ System Architecture

```
                           ┌──────────────────────────────────────┐
                           │         BROWSER (Port 7777)          │
                           │    Single-Page Dashboard (5,379 LOC) │
                           │    13 pages · clickable everything   │
                           └──────────────────┬───────────────────┘
                                              │
                           ┌──────────────────▼───────────────────┐
                           │            NGINX GATEWAY              │
                           │         Reverse Proxy + SSL           │
                           │        /api/* -> Backend:8000          │
                           │        /collect* -> Intel-Proxy:9999   │
                           │        /* -> Static Dashboard          │
                           └────┬─────────────────────────┬───────┘
                                │                         │
          ┌─────────────────────▼──────┐    ┌─────────────▼──────────────┐
          │     BACKEND (FastAPI)      │    │    INTEL PROXY (FastAPI)   │
          │       Port 8000            │    │       Port 9999            │
          │                            │    │                            │
          │  ┌── Correlation Engine    │    │  ┌── 47 Collectors         │
          │  │   8 matching strategies │    │  │   NVD, CISA, MITRE...   │
          │  │                         │    │  │                         │
          │  ├── AI Pipeline           │    │  ├── Pattern Matcher       │
          │  │   9-tool orchestrator   │    │  │   86 IOC regex types    │
          │  │   triage + FP + narr.   │    │  │                         │
          │  │                         │    │  ├── grep.app Scanner      │
          │  ├── Action Generator      │    │  │   109 search queries    │
          │  │   12 playbook types     │    │  │                         │
          │  │                         │    │  ├── crt.sh Collector      │
          │  ├── Exposure Scorer       │    │  │   CT log subdomain scan │
          │  │   5-dimension formula   │    │  │                         │
          │  │                         │    │  └── Shodan InternetDB     │
          │  ├── Finding Manager       │    │      Free port scanning    │
          │  │   dedup + proof chain   │    │                            │
          │  │                         │    └────────────────────────────┘
          │  └── Attribution Engine    │
          │      actor -> customer      │
          └─────┬──────────┬───────────┘
                │          │
   ┌────────────▼──┐  ┌───▼────────────────┐  ┌─────────────────────┐
   │  PostgreSQL   │  │     Ollama         │  │   Recon Engine      │
   │  Port 5432    │  │   Port 11434       │  │   Port 8888         │
   │               │  │                    │  │                     │
   │  ✦ findings   │  │  qwen3:8b (5.2GB) │  │  subfinder          │
   │  ✦ detections │  │  Orchestrator      │  │  crt.sh CT logs     │
   │  ✦ customers  │  │  Triage hooks      │  │  DNS enumeration    │
   │  ✦ assets     │  │  Chat agent        │  │  200 asset cap      │
   │  ✦ actors     │  │                    │  │                     │
   │  ✦ remeds     │  │  OR Claude/GPT/    │  └─────────────────────┘
   │  ✦ campaigns  │  │  Gemini (1-click)  │
   │  ✦ fp_patterns│  │                    │
   │  + RLS (multi │  └────────────────────┘
   │    tenant)    │
   └───────┬───────┘  ┌────────────────────┐  ┌─────────────────────┐
           │          │      Redis         │  │    Prometheus       │
           │          │    Port 6379       │  │    Port 9090        │
           │          │                    │  │                     │
           │          │  Celery broker     │  │  Metrics collection │
           │          │  AI provider state │  │  Health monitoring  │
           │          │  Session cache     │  │                     │
           │          └────────────────────┘  └─────────────────────┘
           │
   ┌───────▼──────────────────────────────┐
   │     Celery Worker + Celery Beat      │
   │                                      │
   │  Worker: background pipeline tasks   │
   │  Beat: scheduled collection every    │
   │        30-60 min                     │
   └──────────────────────────────────────┘
```

### Data Flow

```
1. COLLECT    Intel Proxy fetches 47 feeds -> raw IOCs stored as Detections
2. SCAN       Pattern Matcher extracts 86 IOC types from raw text
3. MATCH      Correlation Engine routes IOCs to customers (8 strategies)
4. PROMOTE    Finding Manager creates/merges Findings with proof chain
5. TRIAGE     AI Pipeline assesses severity, FP probability, narrative
6. REMEDIATE  Action Generator creates response steps (12 playbooks)
7. SCORE      Exposure Scorer calculates 5-dimension risk score
8. DISPLAY    Dashboard renders everything with clickable drill-down
```

---

## 🐳 10 Docker Services

| # | Service | Container | Port | What it does |
|---|---------|-----------|------|-------------|
| 1 | **backend** | arguswatch-backend | 8000 | FastAPI app -  matching, correlation, AI pipeline, API |
| 2 | **intel-proxy** | arguswatch-intel-proxy | 9999 | 47 collectors, pattern matcher, grep.app, crt.sh |
| 3 | **postgres** | arguswatch-postgres | 5432 | PostgreSQL 16 + Row Level Security (multi-tenant) |
| 4 | **redis** | arguswatch-redis | 6379 | Celery broker, AI provider state, caching |
| 5 | **ollama** | arguswatch-ollama | 11434 | Qwen 3 8B -  local AI (auto-pulls on first boot) |
| 6 | **recon-engine** | arguswatch-recon | 8888 | Subdomain enumeration, DNS, certificate scanning |
| 7 | **celery_worker** | arguswatch-celery-worker | -  | Background pipeline processing |
| 8 | **celery_beat** | arguswatch-celery-beat | -  | Scheduled collection every 30-60 min |
| 9 | **nginx** | aw-nginx | **7777** | Reverse proxy, serves dashboard to browser |
| 10 | **prometheus** | arguswatch-prometheus | 9090 | Metrics collection + health monitoring |

---

## 📂 Code Structure

```
arguswatch-v16.4.7/
│
├── 📄 README.md                              # This file
├── 📄 CHANGELOG-v16.4.7.md                   # 20 bug fixes documented
├── 📄 AGENTIC-AI-HONEST-ASSESSMENT.md         # Honest AI capability analysis
├── 🐳 docker-compose.yml                      # All 10 services defined
├── 🔧 start.sh / stop.sh / fresh-start.sh    # Linux/Mac scripts
├── 🔧 START.bat / FRESH-START.bat             # Windows scripts
│
├── backend/                                   # ═══ FASTAPI BACKEND ═══
│   ├── arguswatch/
│   │   ├── main.py                            # App init, auth, health, onboard (~2,283 lines -  was 5,258)
│   │   ├── api/
│   │   │   ├── ai_routes.py                   # AI endpoints: triage, chat, investigate (896 lines)
│   │   │   ├── stats_routes.py                # Stats, metrics, threat-pressure (282 lines)
│   │   │   ├── findings_routes.py             # Findings, campaigns, SLA, FP patterns (656 lines)
│   │   │   ├── ops_routes.py                  # Collectors, matching, scan, enterprise (387 lines)
│   │   │   ├── settings_routes.py             # Settings, exposure, reports, attribution (1,010 lines)
│   │   ├── config.py                          # Settings, env vars, model names
│   │   ├── models.py                          # SQLAlchemy ORM models (all tables)
│   │   ├── auth.py                            # JWT auth (disabled by default)
│   │   ├── database.py                        # Async SQLAlchemy session
│   │   ├── celery_app.py                      # Celery configuration
│   │   │
│   │   ├── engine/                            # ═══ CORE INTELLIGENCE ENGINE ═══
│   │   │   ├── correlation_engine.py          # 🎯 8-strategy matcher + AI hooks
│   │   │   ├── customer_router.py             # IOC -> customer routing logic
│   │   │   ├── customer_intel_matcher.py      # Bulk matching (match-intel-all)
│   │   │   ├── pattern_matcher.py             # 🔍 86 IOC regex patterns
│   │   │   ├── action_generator.py            # 🔧 12 remediation playbooks
│   │   │   ├── severity_scorer.py             # SLA-based severity scoring
│   │   │   ├── exposure_scorer.py             # 📊 5-dimension scoring (1,064 lines)
│   │   │   ├── finding_manager.py             # Finding create + dedup + merge
│   │   │   ├── attribution_engine.py          # Threat actor -> customer attribution
│   │   │   └── campaign_detector.py           # Multi-finding campaign grouping
│   │   │
│   │   ├── services/                          # ═══ AI + PIPELINE SERVICES ═══
│   │   │   ├── ai_pipeline_orchestrator.py    # 🤖 9-tool autonomous agent (698 lines)
│   │   │   ├── ai_pipeline_hooks.py           # AI triage + FP check + narrative
│   │   │   ├── ai_rag_context.py              # RAG context builder for AI
│   │   │   ├── enrichment_pipeline.py         # VT + AbuseIPDB + OTX enrichment
│   │   │   ├── exposure_scorer.py             # Exposure calculation service
│   │   │   └── ingest_pipeline.py             # Detection -> Finding pipeline
│   │   │
│   │   ├── agent/                             # ═══ LLM PROVIDER LAYER ═══
│   │   │   ├── agent_core.py                  # 4 provider call handlers:
│   │   │                                      #   _call_ollama (Qwen 3 8B local)
│   │   │                                      #   _call_anthropic (Opus 4.6 / Sonnet 4.6)
│   │   │                                      #   _call_openai (GPT-5.3 Codex / GPT-4o)
│   │   │                                      #   _call_google (Gemini 3.1 Pro)
│   │   │   ├── chat_tools.py                  # 6 query tools for chat agent
│   │   │   ├── chat_agent_reliable.py         # Two-phase chat: classify->query->summarize
│   │   │   └── investigate_agent.py           # Agentic investigation after compromise check
│   │   │
│   │   ├── static/                            # ═══ FRONTEND ═══
│   │   │   ├── dashboard.html                 # 🖥️ Single-page app (5,379 lines)
│   │   │   │                                  #   13 pages, all inline CSS/JS
│   │   │   │                                  #   Detection detail modals
│   │   │   │                                  #   Remediation detail modals
│   │   │   │                                  #   Dark web clickable cards
│   │   │   │                                  #   AI chat with countdown timer
│   │   │   │                                  #   Onboard with validation
│   │   │   ├── solvent-icon.svg               # Solvent CyberSecurity icon
│   │   │   └── solvent-logo.svg               # Solvent CyberSecurity logo
│   │   │
│   │   └── api/                               # ═══ SUB-ROUTERS ═══
│   │       ├── customers.py                   # Customer CRUD + onboard
│   │       ├── detections.py                  # Detection CRUD + status
│   │       └── enrichments.py                 # Enrichment + remediation
│   │
│   └── tests/                                 # ═══ 110 UNIT TESTS ═══
│       ├── test_matching_strategies.py        # 35 tests (8 strategies × TP + FP)
│       ├── test_crtsh_collector.py            # 22 tests (parsing + email exclusion)
│       ├── test_onboard_validation.py         # 16 tests (domain-name mismatch)
│       ├── test_v16_4_6_css_fix.py            # 16 tests (CSS FP + sanitizer)
│       ├── test_pattern_matcher.py            # 12 tests (core regex patterns)
│       ├── test_self_referential.py           # 9 tests (exclusion logic)
│       ├── test_matching_helpers.py           # Domain, IP, CIDR helpers
│       ├── test_severity_scorer.py            # Severity + SLA tests
│       ├── test_infrastructure.py             # Docker + schema alignment
│       ├── test_pipeline.py                   # Pipeline integration
│       └── test_collectors.py                 # Collector module validation
│
├── intel-proxy/                               # ═══ INTELLIGENCE COLLECTION ═══
│   └── proxy_server.py                        # 🌐 47 collectors (4,204 lines)
│                                              #   23 free feeds (no API key)
│                                              #   grep.app (109 queries)
│                                              #   crt.sh CT log scanner
│                                              #   Shodan InternetDB
│                                              #   Typosquat detector
│                                              #   Pattern matcher (86 types)
│
├── recon-engine/                              # ═══ RECONNAISSANCE ═══
│   └── recon_server.py                        # subfinder + crt.sh + DNS enum
│                                              # 200-asset cap per domain
│
├── initdb/                                    # ═══ DATABASE ═══
│   ├── 01_schema.sql                          # Core tables (findings, detections, etc.)
│   ├── 08_migrate_v16_4.sql                   # v16.4 additions (fp_patterns, etc.)
│   └── 09_row_level_security.sql              # Multi-tenant RLS policies
│
├── nginx/                                     # ═══ REVERSE PROXY ═══
│   └── nginx.conf                             # Port 7777 -> backend/intel-proxy
│
├── config/                                    # ═══ MONITORING ═══
│   └── prometheus.yml                         # Metrics scrape configuration
│
└── scripts/                                   # ═══ UTILITIES ═══
    └── (migration + seed scripts)
```

---

## 📡 47 Collectors

**23 Free (no key):** NVD, CISA KEV, EPSS, MITRE ATT&CK, OpenPhish, URLhaus, PhishTank, Feodo, ThreatFox, MalwareBazaar, Abuse.ch, CIRCL MISP, grep.app (109 queries), GitHub Gist, Sourcegraph, Ransomwatch, RansomFeed, VX-Underground, Paste Sites, RSS, Pulsedive, DarkSearch, Telegram, **crt.sh** (NEW), **Shodan InternetDB** (NEW), Typosquat Detector

**11+ Keyed:** VirusTotal, AbuseIPDB, Shodan, OTX, URLScan, GitHub Secrets, HudsonRock, HIBP, LeakIX, GrayHatWarfare, Censys, IntelX

---

## 🔍 111 IOC Types

**15 PROVEN** (in live DB) · **64 WORKING** (regex + query verified) · **10 THEORETICAL** · 4 REMOVED noise patterns

**Categories:** API Keys & Tokens · Stolen Credentials · Vulnerability Intel · Network IOCs · Data Exfiltration · Threat Actors · Financial/PII · SaaS Misconfiguration · Dark Web · OAuth/Session

**v16.4.7 fixes:** github_fine_grained_pat (prefix), sendgrid_api_key (length), azure_bearer (pattern), CSS false positive (exclusion). **Removed:** crypto_seed_phrase, stripe_test_key, twilio_auth_token, bearer_token_header.

---

## 🎯 8-Strategy Matching Engine

| Strategy | Example | Tests |
|----------|---------|-------|
| exact_domain | `yahoo.com` -> Yahoo | TP + FP |
| subdomain | `api.yahoo.com` -> Yahoo | TP + FP |
| exact_ip / CIDR | `10.0.0.5` in `10.0.0.0/24` | TP + FP |
| keyword (word boundary) | `starbucks` in dump | TP + FP |
| brand + typosquat | `yah0o.com` (≤2 edits) | TP + FP |
| tech_stack | CVE + Apache -> VulnWeb | TP + FP |
| exec_name | `john.ceo@yahoo.com` | TP + FP |
| cloud_asset | `s3://yahoo-backup` | TP + FP |

**Protections:** Self-referential filter · Domain-name mismatch · DNS validation · Industry default isolation · Recon asset cap (200) · Hostname extraction from connection strings

---

## 🤖 AI Pipeline

**Switch providers from dashboard header:** 🦙 Qwen 3 8B · 🟣 Claude Opus 4.6 · 🤖 GPT-5.3 Codex · 💎 Gemini 3.1 Pro

| Component | Ollama (Local) | Cloud (Claude/GPT/Gemini) | Honest Value |
|-----------|---------------|--------------------------|-------------|
| AI Bar (search + investigate) | ✅ classify->compromise->LLM investigate->brief | ✅ (faster, smarter) | **YES -  genuinely agentic** |
| Investigation Narrative | ✅ | ✅ | **YES -  can't do with if-else** |
| 9-Tool Orchestrator | ✅ 4 iterations | ✅ 12 iterations | Agentic but redundant |
| AI Severity Triage | ✅ | ✅ | Better as lookup table |
| FP Check | ✅ | ✅ | Better as rule |

**Separate endpoints:** `match-intel-all` (fast, no AI) -> `ai-triage?limit=5` (slow, 5 at a time)

> **💡 Startup:** First AI call takes 30-60s (model cold load). After that, 15-45s locally, 2-5s on cloud. Switch providers anytime from the header -  no restart.

### 🏆 Top 10 AI Models -  Local + Cloud (March 2026)

*Your hardware: AMD Ryzen 9 9950X3D · 64GB DDR5 · ~17GB VRAM*

| # | Model | Type | Size | Speed | GPQA | SWE-bench | Context | Tools | Cost (in/out) |
|---|-------|------|------|-------|------|-----------|---------|-------|---------------|
| 🥇 | **Qwen 3 8B** | 🟢 LOCAL | 6.6 GB | 40-60 t/s | 81.7 | -  | 256K | ✅ RL-trained | **FREE** |
| 🥈 | **Gemini 3.1 Pro** | 🟣 CLOUD | Proprietary | 50-70 t/s | **94.3** 🏆 | 80.6% | 1M | ✅ Native+MCP | $2 / $12 |
| 🥉 | **Claude Opus 4.6** | 🟣 CLOUD | Proprietary | 25-35 t/s | 91.3 | **80.8%** | 1M | ✅ Native | $5 / $25 |
| 4 | **GPT-5.3 Codex** | 🟣 CLOUD | Proprietary | 40-60 t/s | 81.0 | 56.8% Pro | 400K | ✅ Native | $1.75 / $14 |
| 5 | GPT-OSS 20B | 🟢 LOCAL | ~13 GB | 80-140 t/s | ~72 | -  | 128K | ✅ Native | **FREE** |
| 6 | GLM-4.6V Flash 9B | 🟢 LOCAL | ~6 GB | 45-65 t/s | ~65 | -  | 128K | ✅ 87.4% τ² | **FREE** |
| 7 | Qwen 3 14B | 🟢 LOCAL | ~8.5 GB | 35-50 t/s | ~68 | -  | 128K | ✅ Yes | **FREE** |
| 8 | Qwen 3.5 4B | 🟢 LOCAL | 2.7 GB | 80-120 t/s | ~70 | -  | 256K | ✅ RL-trained | **FREE** |
| 9 | Qwen3-Coder-Next 80B-A3B | 🟢 LOCAL | ~14 GB | 25-40 t/s | ~75 | 70.6% | 256K | ✅ Strong | **FREE** |
| 10 | Gemma 3 12B | 🟢 LOCAL | ~8 GB | 35-50 t/s | ~60 | -  | 128K | ⚠️ Limited | **FREE** |

> **Strategy:** 🟢 Qwen 3 8B daily (free, private) · 🟣 Gemini 3.1 Pro best value cloud ($2/M) · 🟣 Claude Opus 4.6 deepest reasoning ($5/M) · 🟣 GPT-5.3 Codex terminal king ($1.75/M)
>
> *Benchmarks sourced from Artificial Analysis, vendor model cards, VentureBeat (Feb-Mar 2026). Verify at [artificialanalysis.ai](https://artificialanalysis.ai) before customer-facing use.*

---

## 🔧 96 Remediation Playbooks

Auto-generated per IOC type: `malicious_ip` · `unpatched_cve` · `credential_combo` · `leaked_api_key` · `phishing` · `malware_hash` · `ransomware` · `typosquat` · `exec_exposure` · `cloud_exposure` · `data_leak` · `generic`

Each includes: numbered technical steps · governance steps · evidence required · SLA deadline · role assignment

---

## 📊 Dashboard Pages

| Page | What it shows |
|------|-------------|
| **Overview** | Threat Pressure Index, severity chart, detection timeline, IOC distribution |
| **Findings** | All correlated findings with severity, customer, proof chain |
| **Campaigns** | Multi-finding attack campaigns |
| **Detections** | Raw detections -  click any card -> full detail modal with raw evidence + VirusTotal/NVD/Shodan links |
| **Actors** | 183 MITRE ATT&CK threat actors with TTPs, country, sophistication |
| **Dark Web** | Ransomware claims, paste dumps, DW mentions -  clickable cards -> detail modal |
| **Exposure** | 5-dimension exposure scores per customer (D1-D5 breakdown) |
| **Threat Universe** | Interactive threat graph visualization |
| **Customers** | Customer management + one-click onboarding with validation |
| **Reports** | PDF report generation |
| **Remediations** | All remediation actions -  click -> numbered technical steps, SLA, status buttons |
| **FP Memory** | AI-learned false positive patterns |
| **Settings** | AI provider switching, API keys, 47 collector cards with status |

---

## 📋 API Reference

```
POST /api/customers/onboard          # One-call customer onboarding
POST /api/match-intel-all            # Match all detections to customers (fast)
POST /api/ai-triage?limit=5          # AI triage batch (5 at a time)
POST /api/collect-all                # Trigger all 47 collectors
GET  /api/findings                   # List findings with filters
GET  /api/findings/{id}              # Finding detail + proof chain + sources
GET  /api/detections                 # List raw detections
GET  /api/detections/{id}            # Detection detail + raw evidence
GET  /api/customers                  # List all customers
GET  /api/actors                     # List threat actors (auto-seeds MITRE)
GET  /api/darkweb                    # Dark web mentions
GET  /api/finding-remediations/      # All remediation actions
GET  /api/finding-remediations/stats # Remediation statistics
POST /api/finding-remediations/create # Create manual remediation
GET  /api/fp-patterns                # False positive patterns
GET  /api/settings/ai                # AI provider status
POST /api/settings/active-provider   # Switch AI provider (no restart)
POST /api/pipeline-fixup             # Backfill proofs + remediations
GET  /api/collectors/status          # All collector statuses + IOC counts
```

---

## 🐳 Docker Commands

### Daily Operations

```bash
# Start all services
docker compose up -d

# Start with rebuild (after code changes)
docker compose up -d --build

# Stop all services (keeps data)
docker compose down

# View running services
docker compose ps

# Follow backend logs
docker logs arguswatch-backend -f --tail=50

# Follow Ollama logs (AI model status)
docker logs arguswatch-ollama -f --tail=20

# Follow intel-proxy logs (collector activity)
docker logs arguswatch-intel-proxy -f --tail=20
```

### Data Management

```bash
# Check database counts
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -c \
  "SELECT 'findings' as t, COUNT(*) FROM findings
   UNION ALL SELECT 'detections', COUNT(*) FROM detections
   UNION ALL SELECT 'customers', COUNT(*) FROM customers
   UNION ALL SELECT 'remediations', COUNT(*) FROM finding_remediations
   UNION ALL SELECT 'actors', COUNT(*) FROM threat_actors;"

# Check AI triage progress
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -c \
  "SELECT COUNT(*) as triaged FROM findings WHERE ai_provider IS NOT NULL;
   SELECT COUNT(*) as untriaged FROM findings WHERE ai_provider IS NULL;"

# Check collector IOC counts
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -c \
  "SELECT source, COUNT(*) as iocs FROM detections GROUP BY source ORDER BY iocs DESC LIMIT 15;"

# Export findings to CSV
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -c \
  "COPY (SELECT * FROM findings ORDER BY created_at DESC) TO STDOUT WITH CSV HEADER;" > findings.csv
```

### Troubleshooting

```bash
# Check if Ollama model is loaded
docker exec arguswatch-ollama ollama list

# Test Ollama connectivity from backend
docker exec arguswatch-backend python -c \
  "import httpx; r=httpx.get('http://ollama:11434/api/tags'); print(r.status_code, r.text[:200])"

# Check backend environment variables
docker exec arguswatch-backend env | grep -E "OLLAMA|ANTHROPIC|OPENAI|AUTH"

# Restart single service (without touching others)
docker compose restart backend
docker compose restart ollama
docker compose restart intel-proxy

# View PostgreSQL live queries
docker exec arguswatch-postgres psql -U arguswatch -d arguswatch -c \
  "SELECT pid, state, LEFT(query,80) FROM pg_stat_activity WHERE state='active';"
```

### Nuclear Options

```bash
# ⚠️  Stop + DELETE ALL DATA (volumes, findings, customers, everything)
docker compose down -v

# ⚠️  Full rebuild from scratch
docker compose down -v
docker compose up -d --build

# ⚠️  Remove all Docker images (forces re-download)
docker compose down -v --rmi all

# ⚠️  Clean Docker system (reclaim disk space)
docker system prune -af --volumes
```

### Run Tests

```bash
# All 110 tests
docker exec arguswatch-backend python -m pytest tests/ -v

# Specific test file
docker exec arguswatch-backend python -m pytest tests/test_matching_strategies.py -v

# Quick test count
docker exec arguswatch-backend python -m pytest tests/ -q
```

---

## ⚙️ Configuration

```yaml
# docker-compose.yml environment:
ANTHROPIC_API_KEY: sk-ant-...     # Optional -  Claude Opus 4.6 ($5/$25 per M tokens)
OPENAI_API_KEY: sk-...            # Optional -  GPT-5.3 Codex ($1.75/$14 per M tokens)
GOOGLE_AI_KEY: AIza...            # Optional -  Gemini 3.1 Pro ($2/$12 per M tokens)
VIRUSTOTAL_API_KEY: ...           # Recommended -  free 500/day
ABUSEIPDB_API_KEY: ...            # Recommended -  free 1000/day
OLLAMA_MODEL: qwen3:8b          # Default local AI (5.2GB, auto-pulled, free)
AUTH_DISABLED: true                # No login (default)
```

---

## 🧪 Testing

```bash
# All tests (157 total)
docker exec arguswatch-backend python -m pytest tests/ -v

# Integration tests only -  quick smoke (no DB needed, 2s):
docker exec arguswatch-backend python -m pytest tests/test_integration.py -v -k "not requires_db"

# Integration tests -  full (requires running PostgreSQL):
docker exec arguswatch-backend python -m pytest tests/test_integration.py -v
```

| Test File | Tests | What it covers |
|-----------|-------|---------------|
| `test_integration.py` | **47** | **App boot, endpoint registration, CORS security, input validation, response shapes, model integrity, security fixes, N+1 fixes, datetime deprecation, auth flows, full CRUD lifecycle** |
| `test_matching_strategies.py` | 35 | 8 strategies × TP + FP + cross-customer isolation |
| `test_crtsh_collector.py` | 22 | crt.sh parsing, email exclusion, dedup, cap |
| `test_onboard_validation.py` | 16 | Domain-name mismatch detection |
| `test_v16_4_6_css_fix.py` | 16 | CSS false positive rejection + sanitizer |
| `test_pattern_matcher.py` | 12 | Core IOC regex patterns |
| `test_self_referential.py` | 9 | Self-referential exclusion logic |

---

## 📊 Exposure Scoring (5 Dimensions)

| Dimension | Weight | Data Source |
|-----------|--------|-------------|
| D1: Direct Exposure | 45% | Confirmed CVEs, credentials, malicious IPs |
| D2: Active Exploitation | 20% | EPSS scores, CISA KEV, VirusTotal |
| D3: Threat Actor Intent | 15% | 183 MITRE ATT&CK actors × customer industry |
| D4: Attack Surface | 10% | Shodan InternetDB port scans |
| D5: Asset Criticality | 10% | Customer asset criticality ratings |

**SLA:** CRITICAL 1-4h · HIGH 4-24h · MEDIUM 24-72h · LOW 72h+

---

## 📋 v16.4.7 Changes (March 9, 2026)

### 🔧 Pipeline Wiring -  The Critical Fix

**`_post_match_pipeline()`** -  100-line function that runs Severity -> Enrichment -> Auto-Criticality -> AI Triage -> MITRE Tag -> Remediation -> Campaign for every finding. Before this, all downstream engines (enrichment, scoring, playbooks, campaigns) were dead code for matched findings. Now wired into all 7 finding creation paths:

| Path | Runs every | Status |
|------|-----------|--------|
| `match_customer_intel` | Per onboard + every 30min | ✅ |
| Onboard Step 4a2 (promote) | Per onboard | ✅ |
| `_delayed_rematch` | 90s after onboard | ✅ |
| `correlation_engine` | Every 15min | ✅ |
| Startup bootstrap | Once at boot | ✅ |
| `ingest_pipeline` | Per detection | ✅ (own pipeline) |
| AI manual promote | Manual only | ⚠️ (intentional) |

### 🧬 IOC Registry -  Runtime Extensibility

Replaced 6 hardcoded Python dicts with a single DB table (`ioc_type_registry`). Add new IOC types via API -  zero redeploy.

| Component | Detail |
|-----------|--------|
| `ioc_type_registry` table | 111 types seeded from legacy dicts at startup |
| `criticality_weights` table | 8 adjustable scoring weights |
| `ai_prompts` table | 9 editable system prompts with industry overrides |
| `mitre_sync_log` table | Weekly MITRE ATT&CK sync tracking |
| Admin API | 21 endpoints (CRUD, test regex, preview score, coverage gaps, weights, prompts, MITRE sync) |
| Dashboard tab | Full IOC Registry UI with add/edit/filter/auto-discover/score preview |

### 🎯 Auto-Criticality Scoring (8-Factor Model)

Dynamic severity replaces static lookup. Same IOC type, different context = different severity:

```
aws_access_key + active + today + technology customer = CRITICAL (0.95)
aws_access_key + revoked + 90 days + generic customer = MEDIUM (0.42)
```

Factors: base severity (0.20), kill chain stage (0.15), enrichment data (0.20), source reliability (0.10), temporal freshness (0.05), industry context (0.10), MITRE tactic weight (0.10), exposure confirmed (0.10).

### 🤖 AI Prompt Management

9 AI hooks now read system prompts from DB. Editable per hook, per industry -  swap from generic SOC to HIPAA specialist with one API call. Cache-based (zero DB sessions per hook call).

### 🌐 MITRE ATT&CK Auto-Sync

Weekly pulls from MITRE STIX GitHub. Flags deprecated techniques in registry. Suggests replacements. Logs every sync. Runs via Celery Beat + on-demand via API.

### 🧠 FP Memory -  AI-Powered

5 new functions: AI Analyze (explains why pattern is FP), AI Suggest (scans 30 days of dismissals), Test Pattern, category filters, confidence-colored cards.

### 🔧 Remediations -  AI-Powered

6 new functions: AI Regenerate, Verify Fix (re-checks IOC), Compliance Map (NIST/PCI/HIPAA/SOC2), Bulk Regenerate, Bulk Verify, No Playbook filter.

### 🔄 Cross-Customer FP Learning

3-tier system: Tier 1 (auto-global at 3+ customers, pure if/else), Tier 2 (visibility at 2 customers), Tier 3 (AI for ambiguous cases). Analyst override tracking columns for future prompt evolution.

### 🐛 Bugs Found and Fixed

| Bug | Severity | Impact |
|-----|----------|--------|
| Pipeline not wired to matching | CRITICAL | All downstream was dead code |
| `check_and_create_campaign(int)` | CRITICAL | Zero campaigns ever created |
| `_load_prompt` pool exhaustion | CRITICAL | Onboard deadlocks at finding ~6 |
| Step 4a2 findings skip pipeline | CRITICAL | Promoted findings get no scoring |
| Correlation engine skips pipeline | HIGH | 15-min cycle findings get raw severity |
| `_delayed_rematch` skips pipeline | HIGH | Background findings skip enrichment |
| Enrichment format mismatch | HIGH | Auto-scoring always defaults |
| Registry table not in auto-migrate | HIGH | Startup crash on existing deploys |
| `swift_bic` regex matches every word | HIGH | IOC chart dominated by noise |
| Steps 4b/4d double-execute | MEDIUM | 2x slower onboard |

### 📊 Other Improvements

- **Auto-seed**: 6 demo customers (Yahoo, Uber, Shopify, Starbucks, GitHub, VulnWeb) on fresh deploy - all HackerOne bug bounty targets
- **Full automatic boot pipeline**: collect -> correlate -> match -> promote -> score -> attribute -> campaigns (zero manual steps)
- **GPU-accelerated AI**: native Ollama with qwen3:8b (100+ tok/s on GPU vs 5 tok/s on CPU)
- **Coverage gaps**: Industry-aware (P0/P1/P2), strategy-based %, actionable
- **IOC chart**: Top 12 + Other bucket, severity-aware colors, click -> AI Bar
- **Version**: All 228 files updated to v16.4.7

---

## 🗺️ Roadmap

- ✅ 47 collectors, 111 IOC types, 99 MITRE mappings, 8 matching strategies
- ✅ 4 AI providers (Ollama/Claude/GPT/Gemini), 96 playbooks, 21 admin APIs
- ✅ IOC Registry (runtime-extensible), auto-criticality scoring (8-factor)
- ✅ AI prompt management with industry overrides, MITRE auto-sync
- ✅ Cross-customer FP learning, analyst override tracking
- ✅ Full pipeline wiring (7 finding paths -> scoring -> enrichment -> remediation)
- ✅ GPU-accelerated AI via native Ollama (qwen3:8b, 100+ tok/s)
- ✅ Fully automatic boot pipeline (collect -> match -> score -> attribute -> campaigns)
- ✅ 6 HackerOne bug bounty demo customers auto-seeded
- 🔜 Phase 2: EDR/SIEM webhook ingestion
- 🔜 Sysmon -> MITRE ATT&CK TTP extraction
- 🔜 Cross-correlation (external + internal telemetry)
- 🔜 Per-customer PDF threat reports
- 🔜 Multi-tenant RBAC

---

## Pending-Patents

| Application | Title |
|------------|-------|
| US 63/983,055 | VulnPilot - AI vulnerability prioritization |
| US 63/983,059 | Ghost Risks - undetected threat identification |
| US 63/983,697 | VCTS - vulnerability scenario engine |
| US 63/987,743 | IAMPilot - governance-modulated identity threat assessment |

---

## License

Proprietary - Solvent CyberSecurity LLC. All rights reserved.

---


<div align="center">

<img src="backend/arguswatch/static/solvent-icon.svg" alt="Solvent" width="24" height="24">

 *ArgusWatch: See Everything. Miss Nothing.*
 
 <br>

**Cyber AI Architecture**

Built by [**3sk1nt4n**](https://www.credly.com/users/eskintan/badges)

[Solvent CyberSecurity LLC](https://solventcyber.com) - *Defending what matters. One command at a time.*

<br>

</div>

<div align="center">
