# CHANGELOG — ArgusWatch v16.4.6

**Release Date:** March 7, 2026  
**Session:** Full pipeline audit + 20 bug fixes + 110 test cases

---

## 🔧 Bug Fixes (20)

### Pattern Matcher (3 regex fixes + 4 removals)
- **github_fine_grained_pat** — regex used `ghp_` prefix, real tokens use `github_pat_`
- **sendgrid_api_key** — required 40+ char second segment, real keys have ~25
- **azure_bearer** — required token to START with "Azure", real secrets use env var pattern
- **REMOVED:** crypto_seed_phrase, stripe_test_key, twilio_auth_token, bearer_token_header

### Matching Engine (5 fixes)
- **brand/typosquat** — DOMAIN_ONLY guard blocked brand_name assets. Typosquat detection was dead.
- **tech_stack** — `"redis" in "redistribution"` = true. Fixed to word boundary regex.
- **CSS false positive** — CSS `property:value;` patterns matched as username_password_combo
- **Self-referential** — GitHub gist URLs routed back to GitHub-the-customer (328 false findings)
- **IP in CIDR** — TypeError: string vs IPv4Network comparison. Fixed with proper conversion.

### Onboard Safety (3 fixes)
- **import crash** — `re` and `socket` not imported in main.py → 500 on onboard
- **Domain mismatch** — PayPal with apple.com was accepted. Now blocked with confirm override.
- **Severity enum** — String comparison instead of SeverityLevel enum in remediation query

### AI Pipeline (3 fixes)
- **Disconnected hooks** — AI triage hooks existed but were never called by correlation engine
- **Ollama excluded** — Orchestrator only accepted cloud APIs. Now Ollama is default.
- **Model name** — `claude-sonnet-4-5-20250929` → `claude-sonnet-4-6`

### Dashboard (6 fixes)
- **Regex crash** — `replace(/https?:\\/\\//,...)` double-escaped → SyntaxError killed entire page
- **Wrong API table** — Remediations page read empty `remediation_actions` instead of `finding_remediations`
- **Login stuck** — Auth overlay blocked page load even with AUTH_DISABLED=true
- **Claude chat error** — API error response not parsed, crashed on `data["content"][0]`
- **Old stats endpoint** — Finding detail called `/api/remediations/stats` (405 Method Not Allowed)
- **Create remediation** — Browser `prompt()` replaced with inline form; saves to correct table

## ✨ New Features

### Collectors
- **crt.sh Certificate Transparency** — periodic subdomain discovery with email filter + interesting keyword detection (admin, vpn, staging, jenkins, etc.)
- **Shodan InternetDB** — added to onboard targeted collectors. Port 9200=Elasticsearch, 5601=Kibana, 3000=Grafana.
- **2 new grep.app queries** — `AIza filename:.env` (google_api_key), `bitcoin address filename:.txt`

### AI Pipeline
- **Ollama as default orchestrator** — 4-iteration cap, all 4 providers supported
- **`/api/ai-triage` endpoint** — batch AI triage (5 at a time) separate from bulk matching
- **Provider switching** — header buttons + Settings page control all AI components together
- **Google Gemini** — full orchestrator support added

### Dashboard
- **Detection detail modal** — raw evidence, metadata, external verification links (VirusTotal, NVD, Shodan, AbuseIPDB, crt.sh, grep.app, URLhaus)
- **Remediation detail modal** — numbered technical steps, governance steps, evidence required, SLA, status buttons
- **Finding proof chain** — clickable source detection buttons under "How was this matched?"
- **Onboard success animation** — ✅ with stats, auto-closes after 2.5s
- **Dark web clickable cards** — every mention in drilldown opens full detail modal
- **Remediations sidebar page** — stats, filters, clickable cards
- **FP Memory sidebar page** — now accessible from navigation
- **AbuseIPDB** — added to Settings collector cards
- **Create remediation form** — inline styled form instead of browser prompt

### Matching
- **Hostname extraction** — `postgresql://user:pass@db.customer.com` now extracts hostname for domain matching
- **Connection string routing** — db_connection_string, remote_credential, dev_tunnel_exposed types now correlate via hostname

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
