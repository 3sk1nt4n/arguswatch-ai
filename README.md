<div align="center">


<img src="backend/arguswatch/static/solvent-icon.svg" alt="Solvent CyberSecurity" width="48" height="48">

# ArgusWatch AI-Agentic Threat Intelligence Platform

### v16.4.6 — Multi-Tenant MSSP Platform | 47 Collectors | 86 IOC Types | 110 Tests

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED.svg)](https://docker.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com)
[![Codebase](https://img.shields.io/badge/codebase-37%2C000%2B_lines-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-110_passing-brightgreen.svg)]()
[![Patents](https://img.shields.io/badge/patents-4_USPTO_filed-purple.svg)]()

**[Solvent CyberSecurity LLC](https://solventcyber.com) | Created by Adil Eskintan ([@3sk1nt4n](https://github.com/3sk1nt4n))**

*Zero fake data. Real threat intelligence. Every finding has a provable evidence trail.*

---

[Quick Start](#-quick-start) · [Architecture](#-system-architecture) · [Docker Services](#-10-docker-services) · [Code Structure](#-code-structure) · [Collectors](#-47-collectors) · [IOC Types](#-86-ioc-types) · [Matching](#-8-strategy-matching-engine) · [AI Pipeline](#-ai-pipeline) · [Dashboard](#-dashboard-pages) · [API](#-api-reference) · [Docker Commands](#-docker-commands) · [Testing](#-testing) · [Roadmap](#️-roadmap)

</div>

---

## What is ArgusWatch?

ArgusWatch is a production-grade, multi-tenant AI-Agentic threat intelligence platform for MSSPs. It collects IOCs from 47 real threat feeds, correlates them against customer assets using 8 matching strategies, and presents every finding with a provable evidence trail. All AI runs locally on Qwen 2.5 14B via Ollama (free, private), with one-click switching to Claude, GPT-4o, or Gemini from the dashboard header.

### Why "AI-Agentic"?

The core of ArgusWatch is an **autonomous AI orchestrator** that investigates threats the way a human SOC analyst would — but faster:

```
Detection arrives: "CVE-2026-3404 found in Uber's tech stack"
  → AI calls query_customers("Uber")     → learns: industry=transportation
  → AI calls search_cve("CVE-2026-3404") → learns: CVSS 8.1, affects Java
  → AI calls check_exposure(customer=4)   → learns: D1=45, high attack surface
  → AI calls query_actors(sector="transport") → finds: APT41 targets this sector
  → DECIDES: "CRITICAL — active exploitation + targeted sector + high exposure"
```

No human told it which tools to use or in what order. The AI autonomously picks from 9 tools, observes results, reasons, and iterates up to 12 times until it reaches a conclusion.

### What the AI Does vs What Automation Does

| Component | How it works | Type |
|-----------|-------------|------|
| **9-Tool Orchestrator** | AI picks tools, observes, reasons, iterates | ✅ **Agentic AI** |
| **Severity Triage** | AI decides CRITICAL/HIGH/MEDIUM/LOW per finding | ✅ **AI-Decided** |
| **False Positive Check** | AI flags likely FPs before analyst sees them | ✅ **AI-Decided** |
| **Investigation Narrative** | AI writes investigation context from raw data | ✅ **AI-Generated** |
| **FP Memory** | System learns from analyst FP decisions | ✅ **Machine Learning** |
| **Chat Agent** | Natural language Q&A with full platform data | ✅ **AI-Powered** |
| 47 Collectors | Scheduled HTTP fetch + parse + store | Automation |
| 8 Matching Strategies | Regex + domain matching + edit distance | Rule-Based |
| 86 IOC Patterns | Static regex patterns | Pattern Matching |
| 12 Remediation Playbooks | Template-based response step generation | Rule-Based |
| 5-Dimension Exposure Score | Weighted mathematical formula | Formula |

The AI is the **brain** that makes decisions. The automation is the **nervous system** that feeds it data.

---

## 🚀 Quick Start

```bash
# Start all 10 services
docker compose up -d --build

# Open dashboard (no login required)
# http://localhost:7777

# Trigger collection + matching
curl -X POST http://localhost:7777/api/collect-all
curl -X POST http://localhost:7777/api/match-intel-all

# AI triage (5 findings at a time)
curl -X POST "http://localhost:7777/api/ai-triage?limit=5"
```

**Windows:** `START.bat` | **Fresh install:** `FRESH-START.bat` | **Stop:** `stop.sh`

### ⏱️ Important: First 5 Minutes

ArgusWatch needs **~5 minutes after `docker compose up`** before everything works smoothly:

| Time | What's happening | You'll see |
|------|-----------------|-----------|
| 0-30s | Containers starting, PostgreSQL initializing | Dashboard loads but shows "--" |
| 30s-2min | Ollama loading qwen2.5:14b into GPU/RAM (9GB) | AI chat returns "starting up" errors |
| 2-3min | Collectors auto-triggering (if first boot) | Detections start appearing in sidebar |
| 3-5min | Model fully warm, first AI call completes | AI chat + triage working normally |

**Don't panic if AI features show errors in the first 2-3 minutes.** The local Qwen model needs time to load into memory. Once warm, responses take 15-60 seconds depending on query complexity.

```bash
# Quick test to confirm everything is ready (may take 30-60s first time)
curl -X POST http://localhost:7777/api/ai-triage?limit=1
# If you see "triaged": 1 → everything is working
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
                           │        /api/* → Backend:8000          │
                           │        /collect* → Intel-Proxy:9999   │
                           │        /* → Static Dashboard          │
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
          │      actor → customer      │
          └─────┬──────────┬───────────┘
                │          │
   ┌────────────▼──┐  ┌───▼────────────────┐  ┌─────────────────────┐
   │  PostgreSQL   │  │     Ollama         │  │   Recon Engine      │
   │  Port 5432    │  │   Port 11434       │  │   Port 8888         │
   │               │  │                    │  │                     │
   │  ✦ findings   │  │  qwen2.5:14b (9GB) │  │  subfinder          │
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
1. COLLECT    Intel Proxy fetches 47 feeds → raw IOCs stored as Detections
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
| 1 | **backend** | arguswatch-backend | 8000 | FastAPI app — matching, correlation, AI pipeline, API |
| 2 | **intel-proxy** | arguswatch-intel-proxy | 9999 | 47 collectors, pattern matcher, grep.app, crt.sh |
| 3 | **postgres** | arguswatch-postgres | 5432 | PostgreSQL 16 + Row Level Security (multi-tenant) |
| 4 | **redis** | arguswatch-redis | 6379 | Celery broker, AI provider state, caching |
| 5 | **ollama** | arguswatch-ollama | 11434 | Qwen 2.5 14B — local AI (auto-pulls on first boot) |
| 6 | **recon-engine** | arguswatch-recon | 8888 | Subdomain enumeration, DNS, certificate scanning |
| 7 | **celery_worker** | arguswatch-celery-worker | — | Background pipeline processing |
| 8 | **celery_beat** | arguswatch-celery-beat | — | Scheduled collection every 30-60 min |
| 9 | **nginx** | aw-nginx | **7777** | Reverse proxy, serves dashboard to browser |
| 10 | **prometheus** | arguswatch-prometheus | 9090 | Metrics collection + health monitoring |

---

## 📂 Code Structure

```
arguswatch-v16.4.1/
│
├── 📄 README.md                              # This file
├── 📄 CHANGELOG-v16.4.6.md                   # 20 bug fixes documented
├── 📄 AGENTIC-AI-HONEST-ASSESSMENT.md         # Honest AI capability analysis
├── 🐳 docker-compose.yml                      # All 10 services defined
├── 🔧 start.sh / stop.sh / fresh-start.sh    # Linux/Mac scripts
├── 🔧 START.bat / FRESH-START.bat             # Windows scripts
│
├── backend/                                   # ═══ FASTAPI BACKEND ═══
│   ├── arguswatch/
│   │   ├── main.py                            # 🔥 API routes + endpoints (4,836 lines)
│   │   ├── config.py                          # Settings, env vars, model names
│   │   ├── models.py                          # SQLAlchemy ORM models (all tables)
│   │   ├── auth.py                            # JWT auth (disabled by default)
│   │   ├── database.py                        # Async SQLAlchemy session
│   │   ├── celery_app.py                      # Celery configuration
│   │   │
│   │   ├── engine/                            # ═══ CORE INTELLIGENCE ENGINE ═══
│   │   │   ├── correlation_engine.py          # 🎯 8-strategy matcher + AI hooks
│   │   │   ├── customer_router.py             # IOC → customer routing logic
│   │   │   ├── customer_intel_matcher.py      # Bulk matching (match-intel-all)
│   │   │   ├── pattern_matcher.py             # 🔍 86 IOC regex patterns
│   │   │   ├── action_generator.py            # 🔧 12 remediation playbooks
│   │   │   ├── severity_scorer.py             # SLA-based severity scoring
│   │   │   ├── exposure_scorer.py             # 📊 5-dimension scoring (1,064 lines)
│   │   │   ├── finding_manager.py             # Finding create + dedup + merge
│   │   │   ├── attribution_engine.py          # Threat actor → customer attribution
│   │   │   └── campaign_detector.py           # Multi-finding campaign grouping
│   │   │
│   │   ├── services/                          # ═══ AI + PIPELINE SERVICES ═══
│   │   │   ├── ai_pipeline_orchestrator.py    # 🤖 9-tool autonomous agent (698 lines)
│   │   │   ├── ai_pipeline_hooks.py           # AI triage + FP check + narrative
│   │   │   ├── ai_rag_context.py              # RAG context builder for AI
│   │   │   ├── enrichment_pipeline.py         # VT + AbuseIPDB + OTX enrichment
│   │   │   ├── exposure_scorer.py             # Exposure calculation service
│   │   │   └── ingest_pipeline.py             # Detection → Finding pipeline
│   │   │
│   │   ├── agent/                             # ═══ LLM PROVIDER LAYER ═══
│   │   │   └── agent_core.py                  # 4 provider call handlers:
│   │   │                                      #   _call_ollama (local, free)
│   │   │                                      #   _call_anthropic (Claude)
│   │   │                                      #   _call_openai (GPT-4o)
│   │   │                                      #   _call_google (Gemini)
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
│   └── nginx.conf                             # Port 7777 → backend/intel-proxy
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

## 🔍 86 IOC Types

**15 PROVEN** (in live DB) · **64 WORKING** (regex + query verified) · **10 THEORETICAL** · 4 REMOVED noise patterns

**Categories:** API Keys & Tokens · Stolen Credentials · Vulnerability Intel · Network IOCs · Data Exfiltration · Threat Actors · Financial/PII · SaaS Misconfiguration · Dark Web · OAuth/Session

**v16.4.6 fixes:** github_fine_grained_pat (prefix), sendgrid_api_key (length), azure_bearer (pattern), CSS false positive (exclusion). **Removed:** crypto_seed_phrase, stripe_test_key, twilio_auth_token, bearer_token_header.

---

## 🎯 8-Strategy Matching Engine

| Strategy | Example | Tests |
|----------|---------|-------|
| exact_domain | `yahoo.com` → Yahoo | TP + FP |
| subdomain | `api.yahoo.com` → Yahoo | TP + FP |
| exact_ip / CIDR | `10.0.0.5` in `10.0.0.0/24` | TP + FP |
| keyword (word boundary) | `starbucks` in dump | TP + FP |
| brand + typosquat | `yah0o.com` (≤2 edits) | TP + FP |
| tech_stack | CVE + Apache → VulnWeb | TP + FP |
| exec_name | `john.ceo@yahoo.com` | TP + FP |
| cloud_asset | `s3://yahoo-backup` | TP + FP |

**Protections:** Self-referential filter · Domain-name mismatch · DNS validation · Industry default isolation · Recon asset cap (200) · Hostname extraction from connection strings

---

## 🤖 AI Pipeline

**Switch providers from dashboard header:** 🦙 Qwen · + Claude · ◎ GPT · △ Gemini

| Component | Ollama | Claude/GPT/Gemini |
|-----------|--------|-------------------|
| 9-Tool Orchestrator | ✅ 4 iterations | ✅ 12 iterations |
| AI Severity Triage | ✅ | ✅ |
| FP Check | ✅ | ✅ |
| Investigation Narrative | ✅ | ✅ |
| Chat Agent | ✅ | ✅ |

**Separate endpoints:** `match-intel-all` (fast, no AI) → `ai-triage?limit=5` (slow, 5 at a time)

> **💡 Performance tip:** The first AI call after startup takes 60-90s (model cold load). Subsequent calls are 15-45s. If using Claude/GPT instead, responses are 2-5s. Switch providers anytime from the dashboard header — no restart needed.

---

## 🔧 12 Remediation Playbooks

Auto-generated per IOC type: `malicious_ip` · `unpatched_cve` · `credential_combo` · `leaked_api_key` · `phishing` · `malware_hash` · `ransomware` · `typosquat` · `exec_exposure` · `cloud_exposure` · `data_leak` · `generic`

Each includes: numbered technical steps · governance steps · evidence required · SLA deadline · role assignment

---

## 📊 Dashboard Pages

| Page | What it shows |
|------|-------------|
| **Overview** | Threat Pressure Index, severity chart, detection timeline, IOC distribution |
| **Findings** | All correlated findings with severity, customer, proof chain |
| **Campaigns** | Multi-finding attack campaigns |
| **Detections** | Raw detections — click any card → full detail modal with raw evidence + VirusTotal/NVD/Shodan links |
| **Actors** | 183 MITRE ATT&CK threat actors with TTPs, country, sophistication |
| **Dark Web** | Ransomware claims, paste dumps, DW mentions — clickable cards → detail modal |
| **Exposure** | 5-dimension exposure scores per customer (D1-D5 breakdown) |
| **Threat Universe** | Interactive threat graph visualization |
| **Customers** | Customer management + one-click onboarding with validation |
| **Reports** | PDF report generation |
| **Remediations** | All remediation actions — click → numbered technical steps, SLA, status buttons |
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
ANTHROPIC_API_KEY: sk-ant-...     # Optional — Claude
OPENAI_API_KEY: sk-...            # Optional — GPT-4o
GOOGLE_AI_KEY: AIza...            # Optional — Gemini
VIRUSTOTAL_API_KEY: ...           # Recommended — free 500/day
ABUSEIPDB_API_KEY: ...            # Recommended — free 1000/day
OLLAMA_MODEL: qwen2.5:14b        # Default AI (auto-pulled)
AUTH_DISABLED: true               # No login (default)
```

---

## 🧪 Testing

```bash
# 110 tests across 6 core test files
docker exec arguswatch-backend python -m pytest tests/ -v
```

| Test File | Tests | What it covers |
|-----------|-------|---------------|
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

## 🗺️ Roadmap

- ✅ 47 collectors, 86 IOC types, 8 matching strategies, 4 AI providers, 12 playbooks, 110 tests
- 🔜 Phase 2: EDR/SIEM webhook ingestion
- 🔜 Sysmon → MITRE ATT&CK TTP extraction
- 🔜 Cross-correlation (external + internal telemetry)
- 🔜 Per-customer PDF threat reports
- 🔜 Multi-tenant RBAC

---

## 📜 Patents

| Patent | Filing | Status |
|--------|--------|--------|
| VulnPilot AI (Triple-Lock Safety) | US 63/983,055 | Filed |
| Ghost Risks Detection | US 63/983,059 | Filed |
| VCTS Scenario Engine | US 63/983,697 | Filed |
| IAMPilot (Identity Threat Assessment) | US 63/987,743 | Filed |

---

<div align="center">

<img src="backend/arguswatch/static/solvent-icon.svg" alt="Solvent" width="24" height="24">

**[Solvent CyberSecurity LLC](https://solventcyber.com)** — *ArgusWatch: See Everything. Miss Nothing.*

</div>
