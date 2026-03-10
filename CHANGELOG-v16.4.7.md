# CHANGELOG -  ArgusWatch v16.4.7

**Release Date:** March 7, 2026  
**Session:** Full pipeline audit + 20 bug fixes + 110 test cases

---

## 🔧 Bug Fixes (20)

### Pattern Matcher (3 regex fixes + 4 removals)
- **github_fine_grained_pat** -  regex used `ghp_` prefix, real tokens use `github_pat_`
- **sendgrid_api_key** -  required 40+ char second segment, real keys have ~25
- **azure_bearer** -  required token to START with "Azure", real secrets use env var pattern
- **REMOVED:** crypto_seed_phrase, stripe_test_key, twilio_auth_token, bearer_token_header

### Matching Engine (5 fixes)
- **brand/typosquat** -  DOMAIN_ONLY guard blocked brand_name assets. Typosquat detection was dead.
- **tech_stack** -  `"redis" in "redistribution"` = true. Fixed to word boundary regex.
- **CSS false positive** -  CSS `property:value;` patterns matched as username_password_combo
- **Self-referential** -  GitHub gist URLs routed back to GitHub-the-customer (328 false findings)
- **IP in CIDR** -  TypeError: string vs IPv4Network comparison. Fixed with proper conversion.

### Onboard Safety (3 fixes)
- **import crash** -  `re` and `socket` not imported in main.py -> 500 on onboard
- **Domain mismatch** -  PayPal with apple.com was accepted. Now blocked with confirm override.
- **Severity enum** -  String comparison instead of SeverityLevel enum in remediation query

### AI Pipeline (3 fixes)
- **Disconnected hooks** -  AI triage hooks existed but were never called by correlation engine
- **Ollama excluded** -  Orchestrator only accepted cloud APIs. Now Ollama is default.
- **Model name** -  `claude-sonnet-4-5-20250929` -> `claude-sonnet-4-6`

### Dashboard (6 fixes)
- **Regex crash** -  `replace(/https?:\\/\\//,...)` double-escaped -> SyntaxError killed entire page
- **Wrong API table** -  Remediations page read empty `remediation_actions` instead of `finding_remediations`
- **Login stuck** -  Auth overlay blocked page load even with AUTH_DISABLED=true
- **Claude chat error** -  API error response not parsed, crashed on `data["content"][0]`
- **Old stats endpoint** -  Finding detail called `/api/remediations/stats` (405 Method Not Allowed)
- **Create remediation** -  Browser `prompt()` replaced with inline form; saves to correct table

## ✨ New Features

### Collectors
- **crt.sh Certificate Transparency** -  periodic subdomain discovery with email filter + interesting keyword detection (admin, vpn, staging, jenkins, etc.)
- **Shodan InternetDB** -  added to onboard targeted collectors. Port 9200=Elasticsearch, 5601=Kibana, 3000=Grafana.
- **2 new grep.app queries** -  `AIza filename:.env` (google_api_key), `bitcoin address filename:.txt`

### AI Pipeline
- **Ollama as default orchestrator** -  4-iteration cap, all 4 providers supported
- **`/api/ai-triage` endpoint** -  batch AI triage (5 at a time) separate from bulk matching
- **Provider switching** -  header buttons + Settings page control all AI components together
- **Google Gemini** -  full orchestrator support added

### Dashboard
- **Detection detail modal** -  raw evidence, metadata, external verification links (VirusTotal, NVD, Shodan, AbuseIPDB, crt.sh, grep.app, URLhaus)
- **Remediation detail modal** -  numbered technical steps, governance steps, evidence required, SLA, status buttons
- **Finding proof chain** -  clickable source detection buttons under "How was this matched?"
- **Onboard success animation** -  ✅ with stats, auto-closes after 2.5s
- **Dark web clickable cards** -  every mention in drilldown opens full detail modal
- **Remediations sidebar page** -  stats, filters, clickable cards
- **FP Memory sidebar page** -  now accessible from navigation
- **AbuseIPDB** -  added to Settings collector cards
- **Create remediation form** -  inline styled form instead of browser prompt

### Matching
- **Hostname extraction** -  `postgresql://user:pass@db.customer.com` now extracts hostname for domain matching
- **Connection string routing** -  db_connection_string, remote_credential, dev_tunnel_exposed types now correlate via hostname

## 📊 Statistics

| Metric | Count |
|--------|-------|
| Files changed | 15 |
| Bugs fixed | 20 |
| Tests added | 110 (35 matching + 22 crt.sh + 16 CSS + 16 onboard + 12 pattern + 9 self-ref) |
| IOC types | 86 active (15 PROVEN + 64 WORKING + 7 THEORETICAL) |
| Collectors | 47 registered |
| grep.app queries | 109 |
| Python files | 129 (all compile) |
| Total codebase | ~37,000 lines |

---

## Session B -  March 9, 2026

### 🔧 Bug Fixes (7)

**chat_tools.py -  6 column-mismatch crashes (Chat Agent would fail on first use)**
- `tool_search_findings`: `f.customer_name` -> Finding model has no `customer_name`. Fixed to resolve via Customer query.
- `tool_search_darkweb`: `DarkWebMention.customer_name` -> doesn't exist, only `customer_id`. Fixed to join through Customer table.
- `tool_search_darkweb`: `DarkWebMention.created_at` -> model uses `discovered_at`. Fixed.
- `tool_search_darkweb`: `m.content` -> model uses `content_snippet`. Fixed.
- `tool_search_darkweb`: `m.customer_name` -> doesn't exist. Changed to `m.customer_id`.
- `tool_search_darkweb`: `m.ai_summary` -> model uses `triage_narrative`. Fixed.

**main.py -  1 type error (AI Match Confidence would crash)**
- `(f.match_proof or "")[:300]` -> `match_proof` is JSON dict, can't slice. Fixed to `str()` first.

### ✨ New Features

**Reliable Two-Phase Chat Agent (`/api/ai/chat`)**
- New endpoint that does NOT depend on Ollama tool-calling
- Phase 1: LLM classifies intent + extracts parameters (small models reliable at this)
- Phase 2: Python executes DB queries deterministically (never fails, never hallucinates)
- Phase 3: LLM summarizes real data into natural language
- Triple fallback: keyword classifier -> raw SQL -> formatted text. Always returns real data.
- Dashboard chat bar now routes to `/api/ai/chat` by default
- Old `/api/ai/agent-query` kept for cloud providers where tool-calling works

**Agentic AI Bar Investigation (`/api/ai/investigate`)**
- After compromise check returns results, LLM automatically investigates further
- Phase 1: LLM decides what to investigate (check findings? actors? exposure? related emails?)
- Phase 2: Python executes chosen follow-up queries deterministically
- Phase 3: LLM writes analyst investigation brief from all gathered data
- 3-phase progress bar with honest timing (🤖 for LLM steps, ⚡ for instant steps)
- Only triggers when compromised -  clean results don't waste LLM time
- Response shows "✅ Genuinely Agentic" badge with per-phase timing breakdown

**Qwen 3.5 9B Model Upgrade**
- Default local model upgraded from `qwen2.5:14b` to `qwen3.5:9b`
- 36% fewer parameters, 22% smaller on disk (6.6GB vs 8.5GB)
- GPQA Diamond: ~55 -> 81.7 (beats GPT-OSS-120B at 13x smaller)
- IFEval (instruction following): ~80 -> 91.5 = better JSON compliance
- RL-trained specifically for tool calling and structured output
- 256K native context (was 32K-128K)
- Native multimodal: text + image + video
- Updated: docker-compose.yml, config.py, ollama-entrypoint.sh, .env.example

### 📊 Honest AI Assessment

| Component | Docs Label | Honest Label | Adds Real Value? |
|-----------|-----------|-------------|-----------------|
| 9-Tool Orchestrator | Agentic AI | Agentic but redundant | No -  linear pipeline is faster |
| Severity Triage | AI-Decided | Single LLM call | No -  IOC v10 lookup table is better |
| FP Check | AI-Decided | Single LLM call | No -  12 HIGH-FP types already known |
| FP Memory | Machine Learning | Hit counter + CIDR | Not ML, but useful automation |
| RAG Context | RAG | SQL relevance queries | Not RAG, but useful context |
| Investigation Narrative | AI-Generated | AI-Generated | **YES** -  can't do this with if-else |
| Chat Agent (reliable) | AI-Powered | Classify->Query->Summarize | **YES** -  NL queries against live DB |
