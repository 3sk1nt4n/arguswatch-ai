<div align="center">

# 🛡️ ArgusWatch AI-Agentic Threat Intelligence Platform

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

[Quick Start](#-quick-start) · [Architecture](#-architecture) · [Collectors](#-47-collectors) · [IOC Types](#-86-ioc-types) · [Matching](#-8-strategy-matching-engine) · [AI Pipeline](#-ai-pipeline) · [Remediations](#-12-remediation-playbooks) · [Dashboard](#-dashboard) · [API](#-api-reference) · [Testing](#-testing) · [Config](#-configuration)

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

No human told it which tools to use or in what order. The AI autonomously picks from 9 tools, observes results, reasons, and iterates up to 12 times until it reaches a conclusion. That's agentic — goal-driven, tool-using, autonomous decision-making.

### What the AI Does vs What Automation Does

| Component | How it works | AI or Automation? |
|-----------|-------------|-------------------|
| **9-Tool Orchestrator** | AI picks tools, observes, reasons, iterates | ✅ **Agentic AI** |
| **Severity Triage** | AI decides CRITICAL/HIGH/MEDIUM/LOW per finding | ✅ **AI-Decided** |
| **False Positive Check** | AI flags likely FPs before analyst sees them | ✅ **AI-Decided** |
| **Investigation Narrative** | AI writes 2-3 sentence context from raw data | ✅ **AI-Generated** |
| **FP Memory** | System learns from analyst FP decisions | ✅ **Machine Learning** |
| **Chat Agent** | Natural language Q&A with platform data | ✅ **AI-Powered** |
| 47 Collectors | Scheduled HTTP fetch + parse + store | Automation |
| 8 Matching Strategies | Regex + domain matching + edit distance | Rule-Based |
| 86 IOC Patterns | Static regex patterns | Pattern Matching |
| 12 Remediation Playbooks | Template-based response step generation | Rule-Based |
| 5-Dimension Exposure Score | Weighted mathematical formula | Formula |

The AI is the **brain** that makes decisions. The automation is the **nervous system** that feeds it data. Together they form an agentic platform — the AI decides what matters, the automation ensures nothing is missed.

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

**First boot:** Ollama auto-downloads qwen2.5:14b (~9GB one-time). Dashboard auto-triggers collectors if empty.

### ⏱️ Important: First 5 Minutes

ArgusWatch needs **~5 minutes after `docker compose up`** before everything works smoothly. Here's why:

| Time | What's happening | You'll see |
|------|-----------------|-----------|
| 0-30s | Containers starting, PostgreSQL initializing | Dashboard loads but shows "--" |
| 30s-2min | Ollama loading qwen2.5:14b into GPU/RAM (9GB) | AI chat returns "starting up" errors |
| 2-3min | Collectors auto-triggering (if first boot) | Detections start appearing in sidebar |
| 3-5min | Model fully warm, first AI call completes | AI chat + triage working normally |

**Don't panic if AI features show errors in the first 2-3 minutes.** The local Qwen model needs time to load into memory. Once warm, responses take 15-60 seconds depending on query complexity.

**Quick test to confirm everything is ready:**
```bash
# This should return a response (may take 30-60s first time)
curl -X POST http://localhost:7777/api/ai-triage?limit=1
# If you see "triaged": 1 → everything is working
```

---

## 🏗️ Architecture

**10 Docker services:** Backend (FastAPI) · Intel Proxy (47 collectors) · PostgreSQL (RLS) · Redis · Ollama (qwen2.5:14b) · Recon Engine · Celery Worker · Celery Beat · Nginx · Prometheus

**Pipeline flow:** Collectors → Pattern Matcher (86 IOC types) → Customer Router (8 strategies) → Finding Manager → AI Triage (Ollama/Claude/GPT/Gemini) → Remediation Generator (12 playbooks) → Exposure Scorer (5 dimensions)

---

## 📡 47 Collectors

**23 Free (no key):** NVD, CISA KEV, EPSS, MITRE ATT&CK, OpenPhish, URLhaus, PhishTank, Feodo, ThreatFox, MalwareBazaar, Abuse.ch, CIRCL MISP, grep.app (109 queries), GitHub Gist, Sourcegraph, Ransomwatch, RansomFeed, VX-Underground, Paste Sites, RSS, Pulsedive, DarkSearch, Telegram, **crt.sh** (NEW), **Shodan InternetDB** (NEW), Typosquat Detector

**11+ Keyed:** VirusTotal, AbuseIPDB, Shodan, OTX, URLScan, GitHub Secrets, HudsonRock, HIBP, LeakIX, GrayHatWarfare, Censys, IntelX

---

## 🔍 86 IOC Types

**15 PROVEN** (in live DB) · **64 WORKING** (regex + query verified) · **10 THEORETICAL** · 4 REMOVED noise patterns

**Categories:** API Keys & Tokens · Stolen Credentials · Vulnerability Intel · Network IOCs · Data Exfiltration · Threat Actors · Financial/PII · SaaS Misconfiguration · Dark Web · OAuth/Session

**v16.4.6 regex fixes:** github_fine_grained_pat (prefix), sendgrid_api_key (length), azure_bearer (pattern), CSS false positive (exclusion)

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

Overview · Findings · Campaigns · **Detections** (clickable → raw evidence + external verify links) · Actors (183 MITRE ATT&CK) · **Dark Web** (clickable cards → detail modal) · Exposure · Threat Universe · Customers · Reports · **Remediations** (clickable → numbered steps + SLA) · **FP Memory** · Settings

**v16.4.6 UI:** Detection detail modal with VirusTotal/NVD/Shodan/crt.sh links · Remediation detail with numbered steps · Onboard success animation · Dark web clickable mentions · No login screen (AUTH_DISABLED default)

---

## 📋 API Reference

```
POST /api/customers/onboard          # One-call customer onboarding
POST /api/match-intel-all            # Match all detections (fast)
POST /api/ai-triage?limit=5          # AI triage batch
POST /api/collect-all                # Trigger all collectors
GET  /api/findings                   # List findings
GET  /api/findings/{id}              # Finding detail + proof chain
GET  /api/detections/{id}            # Detection detail + raw evidence
GET  /api/finding-remediations/      # All remediation actions
POST /api/finding-remediations/create # Create manual remediation
GET  /api/fp-patterns                # FP patterns
POST /api/settings/active-provider   # Switch AI provider
POST /api/pipeline-fixup             # Backfill proofs + remediations
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
# 110 tests across 6 test files
docker exec arguswatch-backend python -m pytest tests/ -v

# Matching: 35 tests (8 strategies × TP + FP)
# CSS fix: 16 tests (rejection + sanitizer)
# Onboard: 16 tests (domain-name mismatch)
# crt.sh: 22 tests (parsing + email exclusion)
# Pattern: 12 tests (core regex)
# Self-ref: 9 tests (exclusion logic)
```

---

## 📊 Exposure Scoring (5 Dimensions)

D1 Direct Exposure (45%) · D2 Active Exploitation (20%) · D3 Threat Actor Intent (15%) · D4 Attack Surface (10%) · D5 Asset Criticality (10%)

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

VulnPilot AI (US 63/983,055) · Ghost Risks (US 63/983,059) · VCTS (US 63/983,697) · IAMPilot (US 63/987,743)

---

<div align="center">

**[Solvent CyberSecurity LLC](https://solventcyber.com)** — *ArgusWatch: See Everything. Miss Nothing.*

</div>
