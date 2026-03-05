# ArgusWatch Collector Status  -  Honest Audit

Every collector was read line-by-line. This is what actually exists.

---

## TIER 1: NO KEY NEEDED  -  Public Feeds (10 collectors)

These hit public URLs with zero authentication. Highest chance of working on first run.

| # | Collector | What It Fetches | Real URL | Lines | Confidence |
|---|-----------|----------------|----------|-------|------------|
| 1 | **cisa_kev** | CISA Known Exploited Vulns (JSON) | cisa.gov/.../known_exploited_vulnerabilities.json | 142 | **HIGH**  -  Real URL, solid JSON parsing, dedup by cve_id, both async+sync paths, records CollectorRun. Best-written collector in the repo. |
| 2 | **feodo_collector** | Feodo Tracker botnet C2 IPs (JSON) | feodotracker.abuse.ch/downloads/ipblocklist.json | 53 | **HIGH**  -  Real URL, simple JSON list, handles both list and dict formats. |
| 3 | **openphish_collector** | Phishing URLs (plaintext) | openphish.com/feed.txt | 45 | **HIGH**  -  Real URL, plain text one-URL-per-line, dead simple parsing. |
| 4 | **malwarebazaar_collector** | Malware samples (JSON API) | mb-api.abuse.ch/api/v1/ | 54 | **MEDIUM**  -  Real URL, POST request, but response field parsing needs runtime check. |
| 5 | **threatfox_collector** | IOCs from abuse.ch ThreatFox (JSON) | threatfox-api.abuse.ch/api/v1/ | 62 | **MEDIUM**  -  Real URL, POST API. Response structure assumed but not verified. |
| 6 | **phishtank_urlhaus** | PhishTank + URLhaus combined feed | data.phishtank.com + urlhaus.abuse.ch | 168 | **MEDIUM**  -  Two real URLs, CSV parsing for URLhaus, JSON for PhishTank. PhishTank sometimes requires key for rate limits. |
| 7 | **phishtank_urlhaus_collector** | Same as above (duplicate file) | Same URLs | 149 | **MEDIUM**  -  ⚠️ DUPLICATE of #6. Both exist. Unclear which gets loaded. One should be deleted. |
| 8 | **ransomfeed_collector** | Ransomware victim postings (JSON) | ransomfeed.it or ransomwatch API | 61 | **MEDIUM**  -  URL in code, but ransomfeed.it has changed its API structure multiple times. May 404. |
| 9 | **rss_collector** | Security RSS feeds (XML) | Multiple hardcoded RSS URLs | 73 | **MEDIUM**  -  Uses feedparser library. Will work IF feedparser is installed and RSS feeds haven't moved. |
| 10 | **mitre_collector** | MITRE ATT&CK threat actor data | raw.githubusercontent.com/mitre/cti | 266 | **MEDIUM**  -  Real GitHub raw URL for STIX bundles. Longest free collector. Complex STIX parsing  -  likely has field path issues at runtime. |

**Known bug in this tier:**
- `phishtank_urlhaus.py` and `phishtank_urlhaus_collector.py` are duplicates. Both define collector logic. Depending on import order, one may shadow the other or both may run (double-counting detections).
- `rss_collector` needs `feedparser` pip package  -  may not be in Dockerfile requirements.

---

## TIER 2: FREE KEY REQUIRED  -  Needs API Key to Function (11 collectors)

These require a free-tier API key. Without it they either return empty or skip silently.

| # | Collector | Key Setting | Free Tier? | Lines | Confidence |
|---|-----------|------------|------------|-------|------------|
| 11 | **shodan_collector** | `SHODAN_API_KEY` | Free tier exists (100 queries/month) | 75 | **HIGH**  -  Real API URL, correct query format (`hostname:` / `ip:`), ties to customer assets, proper dedup. Well-written. |
| 12 | **urlscan_collector** | `URLSCAN_API_KEY` | Free tier exists | 61 | **MEDIUM**  -  Real URL, but API response parsing untested. |
| 13 | **otx_collector** | `OTX_API_KEY` | Free (AlienVault OTX) | 173 | **MEDIUM**  -  Real URL, paginated pulse fetching, but complex response parsing (nested IOC extraction). |
| 14 | **pulsedive (circl_pulsedive)** | `PULSEDIVE_API_KEY` | Free tier exists | 207 | **MEDIUM**  -  Real URLs, multi-query approach. Longest key-required collector. Complex enough that field mismatches are likely. |
| 15 | **breach_collector** | `HIBP_API_KEY` | **PAID only ($3.50/month)** | 192 | **MEDIUM**  -  Real HIBP v3 API format. Requires paid API key. Checks per-domain, per-email. Well-structured with rate limiting. |
| 16 | **github_collector** | `GITHUB_TOKEN` | Free (PAT) | 64 | **LOW**  -  ⚠️ BUG: Code checks `settings.VIRUSTOTAL_API_KEY` instead of `settings.GITHUB_TOKEN`. Auth header never set even with valid token. Will only work for unauthenticated GitHub search (very low rate limit, 10 req/min). |
| 17 | **darksearch_collector** | `DARKSEARCH_API_KEY` | Was free, **may be dead** | 127 | **LOW**  -  DarkSearch.io has gone offline/paywalled multiple times. URL may 404. |
| 18 | **hudsonrock_collector** | None (free public API) | Free | 80 | **MEDIUM**  -  Real Cavalier API URLs, per-domain and per-email lookup. Free tier may have undocumented rate limits. Response field names (`employees` vs `stealers`) handled with fallback. |
| 19 | **grep_collector** | None (free) | Free | 100 | **MEDIUM**  -  grep.app code search API. Real URL but API may require auth now. |
| 20 | **paste_collector** | None (scraping) | Free | 85 | **LOW**  -  Scrapes multiple paste sites. URLs may be stale or blocked. Regex-based IOC extraction from pastes. |
| 21 | **vxunderground_collector** | None (scraping) | Free | 69 | **LOW**  -  Scrapes VX-Underground GitHub/site. URLs change frequently. |

**Known bugs in this tier:**
- `github_collector.py` line 44: checks `settings.VIRUSTOTAL_API_KEY`  -  should be `settings.GITHUB_TOKEN`. Auth header is never actually set.
- `darksearch_collector.py`  -  DarkSearch.io availability is unreliable.

---

## TIER 3: MISNAMED / DUPLICATE  -  Needs Attention (2 collectors)

| # | Collector | Problem |
|---|-----------|---------|
| 22 | **abuse_collector** | ⚠️ **MISNAMED.** File says "AbuseIPDB Collector" but the URL is `feodotracker.abuse.ch/downloads/ipblocklist.txt`  -  identical feed to `feodo_collector`. This is NOT an AbuseIPDB integration. Real AbuseIPDB (api.abuseipdb.com) requires `ABUSEIPDB_API_KEY` and uses a completely different endpoint. Source tag is `abuse_ch`, same as what feodo produces. **This collector is a duplicate of feodo, mislabeled.** |
| 23 | **circl_misp_collector** | References `PULSEDIVE_API_KEY`  -  naming suggests CIRCL MISP integration but code appears to be Pulsedive-related. Needs review of whether this actually talks to CIRCL or is a copy of circl_pulsedive. |

---

## TIER 4: NVD + SPECIALIZED (3 collectors)

| # | Collector | Key Setting | Lines | Confidence |
|---|-----------|------------|-------|------------|
| 24 | **nvd_collector** | None (free, rate-limited) | 292 | **MEDIUM**  -  Real NVD API URL + FIRST.org EPSS. Longest standard collector. Complex CVE + CPE parsing. NVD recently changed to API 2.0  -  URL format may be stale. |
| 25 | **vxug_darkfeed** | None | 191 | **LOW**  -  Multiple dark web feed sources combined. Uses feedparser. URLs may be stale. |
| 26 | **telegram_collector** | `TELEGRAM_API_ID` + `TELEGRAM_API_HASH` | 90 | **MEDIUM**  -  Uses Telethon (MTProto). Real implementation with channel scanning, IOC extraction via pattern_matcher. Requires Telegram developer credentials. Needs `telethon` pip package. |

---

## TIER 5: ENTERPRISE  -  Stub Only (7 collectors)

These are **7-line stubs** that return `{"status": "inactive"}`. No API integration code exists. They exist as architectural placeholders.

| # | Collector | Key Setting | Lines | Reality |
|---|-----------|------------|-------|---------|
| 27 | **crowdstrike** | `CROWDSTRIKE_CLIENT_ID` + `CROWDSTRIKE_SECRET` | 7 | **STUB.** Returns inactive message. Zero API code. |
| 28 | **crowdstrike_collector** | Same | 23 | **STUB with Celery wrapper.** Key check, returns "key_present" but does nothing. |
| 29 | **cyberint** | `CYBERINT_API_KEY` | 7 | **STUB.** |
| 30 | **cyberint_collector** | Same | 23 | **STUB with Celery wrapper.** |
| 31 | **flare** | `FLARE_API_KEY` | 7 | **STUB.** |
| 32 | **flare_collector** | Same | 23 | **STUB with Celery wrapper.** |
| 33 | **recordedfuture** | `RECORDED_FUTURE_KEY` | 7 | **STUB.** |
| 34 | **recordedfuture_collector** | Same | 23 | **STUB with Celery wrapper.** |
| 35 | **cyware_taxii** | (unknown) | 7 | **STUB.** |
| 36 | **socradar_collector** | `SOCRADAR_API_KEY` | 81 | Has some real code (URL, httpx call) but minimal parsing. Borderline stub. |
| 37 | **cybersixgill** | `CYBERSIXGILL_CLIENT_ID` + `CYBERSIXGILL_SECRET` | 44 | Has OAuth token exchange code + one search call. Most complete enterprise collector. |
| 38 | **spycloud** | `SPYCLOUD_API_KEY` | 45 | Has real URL and basic API call. Minimal but functional structure. |

---

## REAL COUNT  -  Honest Numbers

| Category | Count |
|----------|-------|
| **Real collectors with API integration code** | 21 |
| **Duplicates / misnamed** | 3 (abuse=feodo dup, phishtank dup, circl_misp unclear) |
| **Enterprise stubs (no API code, just return inactive)** | 9 |
| **Enterprise with partial code** | 3 (cybersixgill, spycloud, socradar) |
| **Total .py files in collectors/ + enterprise/** | 38 (minus __init__.py, _pipeline_hook) |

**So when I said "33 collectors"  -  the honest number is:**
- **21 real collectors** with actual HTTP calls to real APIs
- **3 enterprise with partial code** (cybersixgill, spycloud, socradar)
- **9 enterprise stubs** that do nothing
- **3 duplicates/misnamed** that need cleanup
- Minus duplicates, that's roughly **18 unique, functional collectors**

---

## KEYS YOU'D NEED (.env file)

### High Priority (enables the best collectors)
```bash
SHODAN_API_KEY=           # shodan.io  -  free tier, 100 queries/month
HIBP_API_KEY=             # haveibeenpwned.com  -  $3.50/month, essential for breach monitoring
GITHUB_TOKEN=             # github.com/settings/tokens  -  free PAT (BUT code has bug, won't use it)
OTX_API_KEY=              # otx.alienvault.com  -  free registration
URLSCAN_API_KEY=          # urlscan.io  -  free tier
PULSEDIVE_API_KEY=        # pulsedive.com  -  free tier
```

### Medium Priority (nice to have)
```bash
VIRUSTOTAL_API_KEY=       # virustotal.com  -  free tier (used in enrichment, not collection)
ABUSEIPDB_API_KEY=        # abuseipdb.com  -  free tier (BUT no collector actually uses it! See bug above)
CENSYS_API_ID=            # censys.io  -  free tier
CENSYS_API_SECRET=        # censys.io
DARKSEARCH_API_KEY=       # darksearch.io  -  may be offline
```

### Telegram (requires developer account)
```bash
TELEGRAM_API_ID=          # my.telegram.org  -  developer app
TELEGRAM_API_HASH=        # my.telegram.org
```

### AI Providers (for agent, not collection)
```bash
ANTHROPIC_API_KEY=        # Claude
OPENAI_API_KEY=           # GPT-4
GOOGLE_AI_API_KEY=        # Gemini
```

### Enterprise (paid platforms  -  stubs only, won't do anything yet)
```bash
CROWDSTRIKE_CLIENT_ID=
CROWDSTRIKE_SECRET=
RECORDED_FUTURE_KEY=
CYBERINT_API_KEY=
FLARE_API_KEY=
SPYCLOUD_API_KEY=
CYBERSIXGILL_CLIENT_ID=
CYBERSIXGILL_SECRET=
SOCRADAR_API_KEY=
```

---

## BUGS TO FIX BEFORE FIRST RUN

1. **abuse_collector.py**  -  Rename to `feodo_abuse_collector.py` or rewrite to actually hit `api.abuseipdb.com/api/v2/blacklist` with `ABUSEIPDB_API_KEY`
2. **github_collector.py line 44**  -  Change `settings.VIRUSTOTAL_API_KEY` to `settings.GITHUB_TOKEN` and add auth header
3. **Delete one of** `phishtank_urlhaus.py` / `phishtank_urlhaus_collector.py`  -  they're duplicates
4. **circl_misp_collector.py**  -  Verify whether this is CIRCL MISP or mislabeled Pulsedive
5. **Dockerfile**  -  Confirm `feedparser` and `telethon` are in requirements.txt
