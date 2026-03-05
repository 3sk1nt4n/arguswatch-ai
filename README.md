<div align="center">

# ArgusWatch AI - Agentic Threat Intelligence Platform

### Multi-Tenant MSSP Platform with 39 Collectors, 7 AI Agents, and 3-Link Proof Chain

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED.svg)](https://docker.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com)
[![Lines](https://img.shields.io/badge/codebase-30%2C000%2B_lines-orange.svg)]()
[![Collectors](https://img.shields.io/badge/collectors-39_real_feeds-green.svg)]()
[![Patents](https://img.shields.io/badge/patents-4_USPTO_filed-purple.svg)]()

**Built by [Solvent CyberSecurity LLC](https://solventcyber.com) | Created by Adil Eskintan ([@3sk1nt4n](https://github.com/3sk1nt4n))**

*Zero fake data. Real threat intelligence from 39 sources. Every finding has a provable evidence trail.*

---

[Quick Start](#-quick-start) | [Your First Customer](#-your-first-customer) | [Architecture](#-architecture) | [Collectors](#-39-real-collectors) | [AI Agents](#-7-autonomous-ai-agents) | [Proof Chain](#-3-link-proof-chain) | [Dashboard](#-dashboard-pages) | [API](#-api) | [Configuration](#-configuration)

</div>

---

## What is ArgusWatch?

ArgusWatch is a full-stack, multi-tenant threat intelligence platform built for MSSPs (Managed Security Service Providers). It collects real IOCs (Indicators of Compromise) from 39 threat feeds, correlates them against customer assets using 8 strategies, and presents every finding with a 3-link proof chain showing exactly where the data came from and why it matters.

The platform runs 7 autonomous AI agents that handle dark web triage, campaign detection, false positive learning, severity assessment, and more. All AI runs locally on Qwen 2.5 14B via Ollama (free, air-gapped), with optional support for Claude, GPT-4o, and Gemini.

There is no fake demo data anywhere. Every detection comes from real threat feeds. Every finding is backed by provable evidence.

---

## Quick Start

```bash
git clone https://github.com/3sk1nt4n/arguswatch-ai.git
cd arguswatch-ai

# Add your API keys (optional, 21 free collectors work with zero keys)
cp .env.example .env && nano .env

# Launch all 10 services
docker compose up -d --build

# Open the dashboard
# Default login: admin / arguswatch-admin-changeme (change in .env)
open http://localhost:7777
```

**First run takes about 3 minutes** because it downloads the Qwen 2.5 14B AI model. After that, startup takes about 30 seconds.

**What happens automatically on startup:**

1. PostgreSQL initializes with the full schema
2. Ollama downloads Qwen 2.5 14B (first run only)
3. Intel-Proxy starts collecting from all 39 threat feeds
4. IOCs are extracted, normalized, and stored
5. The correlation engine matches IOCs against customer assets
6. Findings are created with severity scores and remediation steps
7. Exposure scores are calculated using the D1-D5 formula
8. The dashboard loads at `http://localhost:7777`

---

## Your First Customer

ArgusWatch starts clean with no fake demo data. Here is how to see real threat intelligence in about 5 minutes.

### Step 1: Onboard a Customer

Click **+ Onboard** (top right corner) and fill in the details:

```
Company Name:  Your Company
Primary Domain: yourcompany.com
Contact Email:  security@yourcompany.com
Industry:       technology
```

Click **Onboard and Start Monitoring**.

The platform runs a full 12-step pipeline automatically:

| Step | What happens | Time |
|------|-------------|------|
| 1 | Creates customer record, registers domain, email domain, and brand name | Instant |
| 2 | Populates industry-default tech stack (nginx, java, python, etc.) | Instant |
| 3 | Triggers passive recon via subfinder and CT logs | 10-30 sec |
| 4 | Matches ALL existing IOCs against customer assets | 5-15 sec |
| 5 | Correlates unrouted detections to this customer | 5-10 sec |
| 6 | Promotes detections into deduplicated Findings | 5-10 sec |
| 7 | Generates remediation steps for CRITICAL and HIGH findings | 5 sec |
| 8 | Runs threat actor attribution | 5 sec |
| 9 | Detects attack campaigns from grouped findings | 5 sec |
| 10 | Calculates D1-D5 exposure score | 2 sec |
| 11 | Seeds exposure history for the trend chart | Instant |
| 12 | Runs a background re-match 90 seconds later to catch late-arriving IOCs | Auto |

### Step 2: Wait About 2 Minutes, Then Refresh

The platform runs a background re-match 90 seconds after onboarding to catch IOCs that arrived while the initial pipeline was running. Refresh the customer modal after 2 minutes to see the full picture.

Watch the **Recent Activity** feed in the left sidebar to see collectors running in real time.

### Step 3: Explore Your Customer

Click the customer card to see:
- **Findings** - CVEs matched to your tech stack, domains in phishing feeds, dark web mentions
- **Coverage** - 17 IOC categories showing which threats are being monitored
- **Exposure** - D1-D5 dimensional risk score with breakdown
- **Proof Chain** - click any finding to see exactly WHERE the data came from and WHY it matches

### Step 4: Add More Assets (Optional)

Click **Tech Stack** to select technologies the customer uses (AWS, Oracle, Docker, Kubernetes, etc.). Click **Assets** to bulk-add IPs, subdomains, GitHub orgs, and more. Each new asset triggers re-correlation and new findings appear within seconds.

### Recommended Demo Customers

These companies have public HackerOne bug bounty programs, so monitoring them is expected:

| Company | Domain | Industry | Tier |
|---------|--------|----------|------|
| Yahoo | yahoo.com | technology | Enterprise |
| GitHub | github.com | technology | Enterprise |
| Uber | uber.com | transportation | Enterprise |
| Starbucks | starbucks.com | retail | Premium |
| Shopify | shopify.com | technology | Premium |

---

## Architecture

```
                    +---------------------+
                    |   Dashboard (7777)   |
                    |   Single-page UI     |
                    +----------+----------+
                               |
              +----------------+----------------+
              |                |                |
    +---------v--+   +--------v-------+   +---v-----------+
    |  Backend   |   | Intel-Proxy    |   | Recon Engine  |
    |  FastAPI   |   | 39 Collectors  |   | subfinder     |
    |  90+ APIs  |   | Gateway        |   | Censys CT     |
    +-----+------+   +--------+-------+   +---------------+
          |                    |
    +-----v--------------------v---------+
    |   PostgreSQL + Redis               |
    |   Celery Worker + Beat             |
    +-----+------------------------------+
          |
    +-----v------------------------------+
    |  Ollama (Qwen 2.5 14B)            |
    |  + Claude / GPT-4o / Gemini       |
    +------------------------------------+
```

**10 Docker services with healthchecks:**

| Service | Role | Port |
|---------|------|------|
| Backend | FastAPI API + Dashboard | 7777 |
| Intel-Proxy | Threat feed collector gateway | 9010 |
| Recon-Engine | Passive subdomain enumeration | 9011 |
| PostgreSQL | Primary database | 5433 |
| Redis | Cache and pub/sub | 6380 |
| Celery Worker | Background task processing | - |
| Celery Beat | Scheduled collection cycles | - |
| Ollama | Local AI model (Qwen 2.5 14B) | 11435 |
| Nginx | HTTPS reverse proxy | 9443 |
| Prometheus | Metrics collection | 9091 |

---

## 39 Real Collectors

### 21 Free Collectors (no API key needed)

These work out of the box with zero configuration:

CISA KEV, NVD, MITRE ATT&CK, ThreatFox, Feodo Tracker, OpenPhish, URLhaus, PhishTank, MalwareBazaar, CIRCL MISP, Abuse.ch, RansomFeed, Pulsedive, DarkSearch/Ahmia, Paste Sites, VX-Underground, HudsonRock, Grep.app, GitHub Gist Scanner, Sourcegraph, Telegram Channels

### 18 Premium Collectors (API key required)

Most of these offer free tiers. Sign up links are in the `.env.example` file:

AlienVault OTX (free), Shodan ($59 lifetime), VirusTotal (free tier), Censys (free tier), HIBP ($3.50/month), GitHub Secrets (free), IntelX (free tier), URLScan.io (free tier), GreyNoise (free community), LeakIX (free tier), GrayHatWarfare (free tier), BinaryEdge (free tier), LeakCheck, SocRadar, SpyCloud, CrowdStrike, Mandiant, Recorded Future

---

## 7 Autonomous AI Agents

These agents run on scheduled intervals without human interaction:

| Agent | Schedule | What it does |
|-------|----------|-------------|
| Dark Web Triage | Every 30 min | Classifies ransomware claims, paste dumps, and leak mentions |
| Sector Campaign Detection | Every 6 hours | Correlates threats across customers in the same industry |
| False Positive Memory | On each FP mark | Learns from analyst dismiss decisions and auto-closes similar items |
| Exposure Narrative | After each rescore | Generates CISO-readable risk reports explaining the score |
| Severity Assessment | On each finding | AI-driven IOC prioritization based on context and customer profile |
| Attribution Reasoning | On attribution | Explains why a threat actor is targeting a specific customer |
| Campaign Correlation | On new findings | Groups related findings into attack campaigns |

**4 AI providers available (switch from Settings):**
- Ollama/Qwen 2.5 14B - default, free, runs locally, air-gapped
- Anthropic Claude
- OpenAI GPT-4o
- Google Gemini

---

## 3-Link Proof Chain

Every finding in ArgusWatch includes a verifiable evidence trail. Nothing is a black box.

**LINK 1: What does this IOC affect?**

Shows NVD CPE data including the vendor, product, version, CVSS score, and CISA KEV exploitation status. Links directly to NVD, MITRE CVE, and CISA KEV databases.

**LINK 2: How do we know the customer uses this asset?**

Shows the discovery source (Customer Onboarding, Industry Template, Censys Scan, CT Log Discovery, Analyst Registered, etc.) with a confidence score from 0-100%. Includes external verification links to Wappalyzer, BuiltWith, Shodan, crt.sh, SecurityTrails, and NVD CPE Dictionary so you can verify independently.

**LINK 3: How the correlation engine matched them**

Shows the correlation strategy name (S1-S8), confidence percentage, and the number of corroborating sources.

### 8 Correlation Strategies

| Strategy | How it works |
|----------|-------------|
| S1: Exact Domain | Finds `uber.com` in a phishing URL, matches it to customer Uber |
| S2: Subdomain | Finds `api.uber.com` in a paste dump, matches it to customer Uber |
| S3: IP/CIDR | Finds a malicious IP in the customer's registered network range |
| S4: Email Pattern | Finds `*@uber.com` in a credential dump |
| S5: Tech Stack/CPE | CVE affects Oracle, customer uses Oracle in their tech stack |
| S6: Context Proximity | Customer name found near IOCs in paste content |
| S7: Typosquat | Detects `ub3r.com` as a typosquat of `uber.com` |
| S8: Token Decode | JWT token body contains the customer's domain |

---

## D1-D5 Exposure Scoring

The exposure score is not a single opaque number. It is decomposed into five dimensions so CISOs can see exactly where the risk comes from:

```
Overall = 0.35 x D1 + 0.25 x D2 + 0.20 x D3 + 0.10 x D4 + 0.10 x D5
```

| Dimension | Weight | What it measures |
|-----------|--------|-----------------|
| D1: Actor Intent | 35% | Threat actors actively targeting the customer's industry |
| D2: Target Profile | 25% | The customer's exposed attack surface |
| D3: Sector Risk | 20% | Industry-wide threat landscape |
| D4: Dark Web | 10% | Underground forum and dark web mentions |
| D5: Surface Exposure | 10% | Internet-facing vulnerabilities |

---

## Dashboard Pages

| Page | What you see |
|------|-------------|
| Command Center | Threat Pressure Index, severity distribution, live detection timeline, IOC breakdown, AI chat |
| Findings | Clickable cards opening rich detail modals with proof chain, AI analysis, and remediation steps |
| Campaigns | Correlated attack campaigns with kill chain mapping, actor attribution, and customer impact |
| Detections | Raw IOC matches from all 39 collectors with severity badges and source tracking |
| Actors | 183 MITRE ATT&CK groups with clickable detail modals, techniques, IOCs, and external intel links |
| Dark Web | Ransomware claims, paste dumps, dark web mentions with clickable detail modals and AI triage |
| Exposure | D1-D5 dimensional risk scores per customer with trend charts |
| Threat Universe | 3D force-directed graph visualization of threats, actors, and customers |
| Customers | Multi-tenant management, onboarding pipeline, 17-category coverage heatmap |
| Settings | Collector status (active/locked), API key management, AI provider configuration |

---

## API

**90+ REST endpoints** documented at `http://localhost:7777/docs`

Here are the most commonly used ones:

```
GET  /api/stats                       Platform-wide metrics
GET  /api/findings                    All intelligence records with proof chain
GET  /api/findings/{id}               Full finding detail with asset proof and affected products
GET  /api/campaigns                   Attack campaigns
GET  /api/exposure/leaderboard        D1-D5 scores ranked by customer
GET  /api/darkweb                     Dark web intelligence
GET  /api/actors                      183 MITRE ATT&CK threat actors
GET  /api/customers                   Customer list with scores
GET  /api/customers/{id}/coverage     17-category IOC coverage heatmap
POST /api/customers/onboard           One-call customer onboarding (runs full 12-step pipeline)
POST /api/collect-all                 Trigger all 39 collectors
POST /api/ai/query                    AI-powered threat analysis
GET  /api/collectors/status           Collector health and IOC counts
GET  /api/enterprise/status           API key configuration status
GET  /api/debug/env-check             Verify API keys are loaded in the container
```

---

## Configuration

### Adding API Keys

1. Copy the example file: `cp .env.example .env`
2. Open `.env` in any text editor
3. Paste your API keys next to the appropriate variable names
4. Restart the platform:

```bash
docker compose down
docker compose up --build -d
```

5. Verify keys loaded: open `http://localhost:7777/api/debug/env-check`

Free tier API keys are available for most collectors. Signup links are included in `.env.example` as comments.

### Changing the Admin Password

Edit `.env` and set:
```
ADMIN_USER=your-username
ADMIN_PASSWORD=your-strong-password
```

### Fresh Start (Wipe Everything)

```bash
docker compose down -v    # The -v flag removes the database volume
docker compose up --build -d
```

### Switching AI Providers

Go to Settings in the dashboard. The AI Provider Configuration section lets you:
- Enter API keys for Claude, GPT-4o, or Gemini
- Click Activate to switch providers instantly
- Qwen 2.5 14B via Ollama is the default and runs locally for free

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend API | Python 3.11, FastAPI, SQLAlchemy, Pydantic |
| Database | PostgreSQL 16 with Row-Level Security |
| Cache/Queue | Redis 7, Celery |
| AI (Local) | Ollama, Qwen 2.5 14B |
| AI (Cloud) | Claude, GPT-4o, Gemini (optional) |
| Containers | Docker Compose, 10 services with healthchecks |
| Frontend | Single-page HTML, vanilla JS, CSS3 |
| 3D Visualization | Three.js |
| Metrics | Prometheus |

---

## Patents Filed

| Application | Title |
|------------|-------|
| US 63/983,055 | VulnPilot - AI vulnerability prioritization |
| US 63/983,059 | Ghost Risks - undetected threat identification |
| US 63/983,697 | VCTS - vulnerability scenario engine |
| US 63/987,743 | IAMPilot - governance-modulated identity threat assessment |

---

## Built By

**Adil Eskintan** - Principal Cybersecurity Technical Programs Manager, SANS Ambassador (Silver)

Certifications: GCFA, GCIH, GMON, GCTD, GDSA, GCIA

**Solvent CyberSecurity LLC** | [solventcyber.com](https://solventcyber.com) | GitHub: [@3sk1nt4n](https://github.com/3sk1nt4n)

---

## License

This project is proprietary software owned by Solvent CyberSecurity LLC. See LICENSE file for details.
