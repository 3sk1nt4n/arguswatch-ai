# ArgusWatch v16.4.1  -  Runtime Testing Battle Plan

The pipeline: Collection ➜ Matching ➜ Scoring ➜ AI Triage ➜ Remediation ➜ Dashboard

Every stage is code-complete but zero-tested. This is the order to make it real.

---

## PHASE 1: Does it even start? (30 min)

```bash
./fresh-start.sh
```

Watch for:
- [ ] PostgreSQL healthy (5433)
- [ ] Redis healthy (6380)
- [ ] Backend starts without import errors
- [ ] Migrations run without SQL errors
- [ ] Customer seed completes (6 customers from CSV)
- [ ] Intel Proxy starts and begins collecting

**First failure will likely be:**
- Missing Python package in requirements.txt (feedparser? telethon?)
- Import error from pattern_matcher.py COPY missing in Dockerfile
- Database column mismatch between models.py and migration scripts

**Fix approach:** `docker compose logs backend`  -  read the first error, fix it, rebuild.

---

## PHASE 2: Does Collection produce data? (15 min)

After backend is running, check:

```bash
# Hit the stats endpoint
curl http://localhost:7777/api/stats

# Check detection count directly
curl http://localhost:7777/api/detections?limit=5

# Check intel proxy health
curl http://localhost:9010/health

# Check collector run history
curl http://localhost:9010/collectors/status
```

**Expected:** 200-2000+ detections from free feeds (CISA KEV, Feodo, ThreatFox, etc.)

**If zero detections:**
- Check intel-proxy logs: `docker compose logs intel-proxy`
- Intel proxy writes directly to DB with raw SQL  -  if DB tables don't match, inserts fail silently
- The insert_detection() function catches ALL exceptions and logs warnings  -  check for those

---

## PHASE 3: Does Matching link threats to customers? (15 min)

```bash
# Check if any detections got customer_id assigned
curl http://localhost:7777/api/findings?limit=5

# Check customer-specific detections
curl http://localhost:7777/api/customers

# For each customer, check their findings
curl http://localhost:7777/api/customers/1/findings
```

**Expected:** Some findings linked to seed customers (especially VulnWeb Demo which has broad matching)

**If zero matches:**
- The customer_intel_matcher checks detection IOC values against customer asset domains/IPs
- If all detections are CVE IDs or hashes (from KEV/NVD), they won't match customer domains
- Need detections with domain/IP/URL types to match  -  those come from Shodan, HudsonRock, Pulsedive
- Check: `curl http://localhost:7777/api/detections?ioc_type=domain`  -  if empty, matching has nothing to work with

**Fix:** The VulnWeb Demo customer should match against broad patterns. If not, the matching logic needs debugging.

---

## PHASE 4: Does Scoring calculate exposure? (10 min)

```bash
# Check exposure scores per customer
curl http://localhost:7777/api/exposure/all

# Trigger recalculation
curl -X POST http://localhost:7777/api/exposure/recalculate

# Check individual customer
curl http://localhost:7777/api/customers/1/exposure
```

**Expected:** Each customer has a 0-100 exposure score with D1-D5 breakdown

**If all zeros:**
- Scoring depends on findings existing with severity levels
- If Phase 3 produced zero findings, scoring has nothing to calculate
- Check the formula: it reads finding counts, severity distribution, SLA status

---

## PHASE 5: Does AI Triage work? (20 min)

```bash
# Check if Ollama downloaded the model
curl http://localhost:11435/api/tags

# If model not ready, it's still downloading (check):
docker compose logs ollama

# Test AI directly
curl http://localhost:7777/api/agent/ask -X POST \
  -H "Content-Type: application/json" \
  -d '{"question": "What are the top threats for our customers?"}'
```

**Expected:** AI response with analysis based on collected data

**If AI fails:**
- Ollama model download takes 10-30 min first time (9GB)
- If ANTHROPIC_API_KEY or OPENAI_API_KEY are set, those providers are tried first
- The Gemini tool-call format bug will crash if GOOGLE_AI_API_KEY is set  -  leave it empty for now
- Check: `docker compose logs ollama` for download progress

**Alternative:** Skip local Ollama, set ANTHROPIC_API_KEY in .env for instant Claude-powered triage

---

## PHASE 6: Does the Dashboard render? (10 min)

Open http://localhost:7777 in browser. Check:

- [ ] Overview page loads with stats cards
- [ ] SVG gauge renders (exposure score)
- [ ] Detection feed shows real detections
- [ ] Customer list shows 6 seed customers
- [ ] Click a customer → detail modal opens
- [ ] Threat Universe 3D globe renders (Three.js)
- [ ] Mobile hamburger menu works (resize browser to 768px)

**If blank page:**
- Check browser console (F12) for JS errors
- Most likely: API endpoint returns unexpected JSON shape
- The dashboard is static HTML/JS calling fetch() against /api/* endpoints
- If any endpoint 500s, that card/chart breaks

**If data shows but looks wrong:**
- The dashboard was designed for specific JSON response shapes
- If models changed but API serialization didn't update, fields may be missing/null

---

## PHASE 7: Remediation + Actions (10 min)

```bash
# Check if any actions were generated
curl http://localhost:7777/api/actions?limit=5

# Check SLA status
curl http://localhost:7777/api/sla/status
```

**Expected:** Auto-generated remediation actions for high/critical findings

**If empty:** Action generation runs at end of pipeline. If findings exist but actions don't, check action_engine.py logic.

---

## KNOWN BUGS TO FIX BEFORE RUNNING

Priority order (fix these first to avoid wasted debugging time):

1. **Dockerfile pattern_matcher.py**  -  verify COPY includes engine/pattern_matcher.py
2. **requirements.txt**  -  verify feedparser, telethon are listed
3. **github_collector.py line 44**  -  change VIRUSTOTAL_API_KEY → GITHUB_TOKEN
4. **Delete phishtank_urlhaus.py** (keep phishtank_urlhaus_collector.py)
5. **abuse_collector.py**  -  rename or rewrite to avoid feodo duplicate

---

## THE HONEST PREDICTION

After ./fresh-start.sh and fixing the first 2-3 import/migration errors:

| Stage | Prediction |
|-------|-----------|
| Collection | 12-15 of 19 free collectors produce data |
| Matching | Some matches for VulnWeb Demo, fewer for real companies |
| Scoring | Works IF findings exist (mathematical, no external deps) |
| AI Triage | Works IF Ollama model downloaded OR cloud API key set |
| Remediation | Partially works  -  depends on full pipeline completing |
| Dashboard | Renders but expect 3-5 broken cards/charts needing JSON fixes |

**Total time to go from zip to working dashboard with real data: 2-4 hours of debugging.**

That's not a criticism of the code  -  it's the reality of any 34K-line application that's never been executed. The architecture is sound. The code is real. It just needs its first run.

---

## IDEAS FOR AFTER FIRST SUCCESSFUL RUN

Once the basic pipeline works end-to-end:

### Quick Wins (1-2 hours each)
- **Collector health dashboard**  -  /collectors/status already exists in intel-proxy, wire it to a dashboard card
- **Real-time collection counter**  -  WebSocket or polling that shows detections ticking up live
- **One-click recollect**  -  Button in dashboard that hits POST /collect/all
- **Export findings to CSV**  -  /api/export/findings endpoint → download button

### Medium Effort (4-8 hours each)
- **Slack/Teams alerts**  -  SLACK_WEBHOOK_URL is already in docker-compose, just need the dispatch code
- **Email PDF reports**  -  report generation code exists, need SMTP config + scheduling
- **Customer onboarding wizard**  -  the 30-gap UX fix from v16.4, needs frontend wiring
- **API key management UI**  -  /collectors/status shows which need keys, add input fields

### Big Impact (1-2 days each)
- **Multi-tenant auth**  -  JWT is wired but AUTH_DISABLED=true, flip to false + test login flow
- **Celery task monitoring**  -  Flower dashboard (celery monitoring) as additional Docker service
- **Historical trending**  -  exposure_history table exists, build sparkline charts
- **MITRE ATT&CK heatmap**  -  threat actors have techniques[], visualize coverage gaps
