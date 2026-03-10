"""
ArgusWatch Intel Proxy Gateway
================================
Separate microservice with FULL internet access.
Fetches REAL threat intel from public feeds, writes directly to PostgreSQL.

Architecture:
  [Backend container]  ->  http://intel-proxy:9000/collect/all
  [Intel Proxy]        ->  CISA, MITRE, abuse.ch, NVD, OpenPhish, RSS...
  [Intel Proxy]        ->  writes detections + actors + darkweb directly to DB

This is the enterprise pattern used by CrowdStrike, Splunk SOAR, Cortex XSOAR.
"""

import os, asyncio, logging, time, json, hashlib, re
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
log = logging.getLogger("intel-proxy")

# ── DB connection (same postgres as backend) ──
PG_USER = os.getenv("POSTGRES_USER", "arguswatch")
PG_PASS = os.environ["POSTGRES_PASSWORD"]  # Required -  no default
PG_HOST = os.getenv("POSTGRES_HOST", "postgres")
PG_PORT = os.getenv("POSTGRES_PORT", "5432")
PG_DB   = os.getenv("POSTGRES_DB", "arguswatch")
DB_URL  = f"postgresql+asyncpg://{PG_USER}:{PG_PASS}@{PG_HOST}:{PG_PORT}/{PG_DB}"

engine = create_async_engine(DB_URL, pool_size=5, max_overflow=5)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# ── API Keys (optional - enhances collection) ──
VT_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "")
OTX_KEY     = os.getenv("OTX_API_KEY", "")
SHODAN_KEY  = os.getenv("SHODAN_API_KEY", "")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
CENSYS_ID   = os.getenv("CENSYS_API_ID", "")
CENSYS_SECRET = os.getenv("CENSYS_API_SECRET", "")
INTELX_KEY  = os.getenv("INTELX_API_KEY", "")
PULSEDIVE_KEY = os.getenv("PULSEDIVE_API_KEY", "")

HTTP_TIMEOUT = 30.0

# ════════════════════════════════════════════════════════════
# DB HELPERS - direct SQL inserts (no ORM dependency)
# ════════════════════════════════════════════════════════════

async def insert_detection(db_ignored, source, ioc_type, ioc_value, severity, sla_hours, raw_text, confidence=0.7, customer_id=None, metadata=None):
    """Insert a detection if it doesn't already exist (dedup by source+ioc_value). Uses own session."""
    try:
        async with AsyncSessionLocal() as db:
            check = await db.execute(text(
                "SELECT id FROM detections WHERE source=:s AND ioc_value=:v LIMIT 1"
            ), {"s": source, "v": ioc_value})
            if check.scalar():
                return None  # already exists
            r = await db.execute(text("""
                INSERT INTO detections (source, ioc_type, ioc_value, severity, sla_hours, raw_text,
                    confidence, customer_id, status, source_count, metadata, first_seen, last_seen, created_at)
                VALUES (:source, :ioc_type, :ioc_value, :severity, :sla_hours, :raw_text,
                    :confidence, :customer_id, 'NEW', 1, :metadata, NOW(), NOW(), NOW())
                RETURNING id
            """), {
                "source": source, "ioc_type": ioc_type, "ioc_value": ioc_value,
                "severity": severity, "sla_hours": sla_hours, "raw_text": raw_text,
                "confidence": confidence, "customer_id": customer_id,
                "metadata": json.dumps(metadata) if metadata else None,
            })
            det_id = r.scalar()
            await db.commit()
            return det_id
    except Exception as e:
        log.warning(f"insert_detection failed [{source}:{ioc_value[:30]}]: {str(e)[:80]}")
        return None

async def insert_collector_run(db_ignored, name, status, stats, started, completed, error=None):
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("""
                INSERT INTO collector_runs (collector_name, status, started_at, completed_at, stats, error_msg)
                VALUES (:n, :s, :st, :co, :stats, :err)
            """), {"n": name, "s": status, "st": started, "co": completed,
                   "stats": json.dumps(stats), "err": error})
            await db.commit()
    except Exception as e:
        log.warning(f"insert_collector_run failed [{name}]: {str(e)[:80]}")

async def insert_actor(db_ignored, name, mitre_id=None, aliases=None, origin=None, motivation=None,
                       sophistication=None, active_since=None, sectors=None, techniques=None,
                       description=None, countries=None):
    try:
        async with AsyncSessionLocal() as db:
            check = await db.execute(text("SELECT id FROM threat_actors WHERE name=:n LIMIT 1"), {"n": name})
            existing = check.scalar()
            if existing:
                return existing
            r = await db.execute(text("""
                INSERT INTO threat_actors (name, mitre_id, aliases, origin_country, motivation,
                    sophistication, active_since, target_sectors, techniques, description,
                    target_countries, source, created_at, updated_at)
                VALUES (:name, :mitre_id, :aliases, :origin, :motivation,
                    :sophistication, :active_since, :sectors, :techniques, :description,
                    :countries, 'intel-proxy', NOW(), NOW())
                RETURNING id
            """), {
                "name": name, "mitre_id": mitre_id, "aliases": json.dumps(aliases or []),
                "origin": origin, "motivation": motivation, "sophistication": sophistication,
                "active_since": active_since, "sectors": json.dumps(sectors or []),
                "techniques": json.dumps(techniques or []), "description": description,
                "countries": json.dumps(countries or []),
            })
            aid = r.scalar()
            await db.commit()
            return aid
    except Exception as e:
        log.warning(f"insert_actor failed [{name}]: {str(e)[:80]}")
        return None

async def insert_darkweb(db_ignored, source, mention_type, title, actor=None, severity="HIGH", customer_id=None, url=None, metadata=None):
    try:
        async with AsyncSessionLocal() as db:
            # Dedup: skip if same title already exists (catches ransomfeed/ransomwatch overlap)
            check = await db.execute(text(
                "SELECT id FROM darkweb_mentions WHERE title=:t LIMIT 1"
            ), {"t": title})
            if check.scalar():
                return None  # already exists
            await db.execute(text("""
                INSERT INTO darkweb_mentions (source, mention_type, title, threat_actor, severity,
                    customer_id, discovered_at, published_at, url, metadata)
                VALUES (:source, :mtype, :title, :actor, :severity,
                    :cid, NOW(), NOW(), :url, :meta)
            """), {
                "source": source, "mtype": mention_type, "title": title, "actor": actor,
                "severity": severity, "cid": customer_id, "url": url,
                "meta": json.dumps(metadata or {}),
            })
            await db.commit()
    except Exception as e:
        log.warning(f"insert_darkweb failed: {str(e)[:80]}")



# ═══════════════════════════════════════════════════════════════
# Import extracted collectors + inject helpers
# ═══════════════════════════════════════════════════════════════
import collectors_registry
from collectors_registry import *  # noqa: F401,F403

# ════════════════════════════════════════════════════════════
# REAL COLLECTORS - each fetches from actual internet sources
# ════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════
# Collectors extracted to collectors_registry.py
# ══════════════════════════════════════════════════════════════

ALL_COLLECTORS = {
    # ── FREE - no key needed ──
    "kev": collect_cisa_kev,
    "feodo": collect_feodo,
    "threatfox": collect_threatfox,
    "malwarebazaar": collect_malwarebazaar,
    "openphish": collect_openphish,
    "abuse": collect_abuse_feodo_txt,
    "nvd": collect_nvd,
    "mitre": collect_mitre,
    "ransomfeed": collect_ransomfeed,
    "rss": collect_rss,
    "paste": collect_paste,
    "hudsonrock": collect_hudsonrock,
    "phishtank_urlhaus": collect_phishtank_urlhaus,
    "circl_misp": collect_circl_misp,
    "pulsedive": collect_pulsedive,
    "vxunderground": collect_vxunderground,
    "ransomwatch": collect_ransomwatch,
    "darksearch": collect_darksearch,
    "grep_app": collect_grep_app,
    # ── v16.4.3: RAW TEXT -> PATTERN_MATCHER collectors ──
    "github_gist": collect_github_gists,
    "sourcegraph": collect_sourcegraph,
    "alt_paste": collect_alt_paste,
    "grayhatwarfare": collect_grayhatwarfare,
    "leakix": collect_leakix,
    "telegram": collect_telegram,
    # ── v16.4.4: NEW free collectors ──
    "crtsh": collect_crtsh,
    "hibp_breaches": collect_hibp_breaches,
    "github_code": collect_github_code_search,
    "urlscan_community": collect_urlscan_community,
    # ── v16.4.5: HIGH-VALUE free collectors ──
    "shodan_internetdb": collect_shodan_internetdb,
    "typosquat": collect_typosquat,
    "epss_top": collect_epss_top,
    # ── KEY-OPTIONAL - skip gracefully if no key ──
    "otx": collect_otx,
    "urlscan": collect_urlscan,
    "github": collect_github_secrets,
    "shodan": collect_shodan_customer,
    "censys": collect_censys,
    "intelx": collect_intelx,
    "breach": collect_breach,
    "socradar": collect_socradar,
    # ── ENTERPRISE - require paid keys ──
    "spycloud": collect_spycloud,
    "crowdstrike": collect_crowdstrike,
    "cybersixgill": collect_cybersixgill,
    "recordedfuture": collect_recordedfuture,
    "cyberint": collect_cyberint,
    "flare": collect_flare,
}

# Categorize collectors for the settings UI
COLLECTOR_INFO = {
    "kev":              {"tier": "free",       "name": "CISA KEV",              "key_env": None,                    "description": "US gov known exploited vulnerabilities"},
    "feodo":            {"tier": "free",       "name": "Feodo Tracker",         "key_env": None,                    "description": "Botnet C2 IP blocklist (abuse.ch)"},
    "threatfox":        {"tier": "free",       "name": "ThreatFox",             "key_env": None,                    "description": "IOC database - IPs, domains, hashes (abuse.ch)"},
    "malwarebazaar":    {"tier": "free",       "name": "MalwareBazaar",         "key_env": None,                    "description": "Recent malware hashes (abuse.ch)"},
    "openphish":        {"tier": "free",       "name": "OpenPhish",             "key_env": None,                    "description": "Phishing URL feed"},
    "abuse":            {"tier": "free",       "name": "AbuseIPDB Feed",        "key_env": None,                    "description": "IP blocklist (abuse.ch feodo txt)"},
    "nvd":              {"tier": "free",       "name": "NVD",                   "key_env": None,                    "description": "NIST CVE database with CVSS + EPSS"},
    "mitre":            {"tier": "free",       "name": "MITRE ATT&CK",         "key_env": None,                    "description": "138+ threat actor groups and techniques"},
    "ransomfeed":       {"tier": "free",       "name": "RansomFeed",            "key_env": None,                    "description": "Ransomware victim leak announcements"},
    "rss":              {"tier": "free",       "name": "RSS Feeds",             "key_env": None,                    "description": "Krebs, CISA alerts, BleepingComputer"},
    "paste":            {"tier": "free",       "name": "Paste Sites",           "key_env": None,                    "description": "Pastebin credential/data dumps"},
    "hudsonrock":       {"tier": "free",       "name": "Hudson Rock",           "key_env": None,                    "description": "Stealer log victims per domain"},
    "phishtank_urlhaus":{"tier": "free",       "name": "PhishTank + URLhaus",   "key_env": "PHISHTANK_API_KEY",     "description": "Verified phishing + malicious URLs (key optional)"},
    "circl_misp":       {"tier": "free",       "name": "CIRCL MISP",            "key_env": None,                    "description": "Luxembourg CERT OSINT threat intel"},
    "vxunderground":    {"tier": "free",       "name": "VX-Underground",        "key_env": None,                    "description": "Malware samples and APT tracking"},
    "darksearch":       {"tier": "free",       "name": "Ahmia/DarkSearch",      "key_env": None,                    "description": "Clearnet Tor search - dark web index"},
    "grep_app":         {"tier": "free",       "name": "Grep.app",              "key_env": None,                    "description": "Public GitHub exposed secrets search"},
    "github_gist":      {"tier": "free",       "name": "GitHub Gist Scanner",   "key_env": None,                    "description": "Scan public gists for secrets via pattern_matcher (Cat 1,2,7,10,11)"},
    "sourcegraph":      {"tier": "free",       "name": "Sourcegraph Search",    "key_env": None,                    "description": "Search 2M+ public repos for leaked secrets (Cat 2,7,12)"},
    "alt_paste":        {"tier": "free",       "name": "Alt Paste Sites",       "key_env": None,                    "description": "dpaste, paste.ee, centos, ubuntu paste scanning (Cat 1,2,8,15)"},
    "grayhatwarfare":   {"tier": "key_optional","name": "GrayHatWarfare",       "key_env": "GRAYHATWARFARE_API_KEY","description": "Open S3/Azure/GCS bucket search per customer (Cat 12)"},
    "leakix":           {"tier": "key_optional","name": "LeakIX",               "key_env": "LEAKIX_API_KEY",        "description": "Exposed services + leaked data per customer domain (Cat 1,7,12)"},
    "telegram":         {"tier": "free",       "name": "Telegram Channels",     "key_env": None,                    "description": "Public threat intel channels -  IOC + breach mention scanning (Cat 1,9,15)"},
    "crtsh":            {"tier": "free",       "name": "crt.sh CT Logs",        "key_env": None,                    "description": "Certificate Transparency subdomain discovery per customer domain"},
    "hibp_breaches":    {"tier": "free",       "name": "HIBP Breach List",      "key_env": None,                    "description": "Cross-reference customer domains against 700+ known data breaches"},
    "github_code":      {"tier": "key_optional","name": "GitHub Code Search",   "key_env": "GITHUB_TOKEN",          "description": "Search public repos for leaked secrets (AKIA, sk_live_, xoxb-, etc.)"},
    "urlscan_community":{"tier": "free",       "name": "URLScan Community",     "key_env": None,                    "description": "Detect phishing pages and suspicious scans targeting customer domains"},
    "shodan_internetdb": {"tier": "free",      "name": "Shodan InternetDB",     "key_env": None,                    "description": "FREE exposed service + CVE scan per customer IP (no key)"},
    "typosquat":         {"tier": "free",      "name": "Typosquat Detector",    "key_env": None,                    "description": "DNS permutation phishing domain discovery per customer (no key)"},
    "epss_top":          {"tier": "free",      "name": "EPSS Top Exploited",    "key_env": None,                    "description": "FIRST.org top-100 most exploited CVEs by probability (no key)"},
    "otx":              {"tier": "key_optional","name": "AlienVault OTX",       "key_env": "OTX_API_KEY",           "description": "Community threat pulses and IOCs"},
    "urlscan":          {"tier": "key_optional","name": "URLScan.io",           "key_env": "URLSCAN_API_KEY",       "description": "Phishing/malware URL scans (1000/day free)"},
    "github":           {"tier": "key_optional","name": "GitHub Secrets",       "key_env": "GITHUB_TOKEN",          "description": "Exposed credentials in public repos"},
    "shodan":           {"tier": "key_optional","name": "Shodan",               "key_env": "SHODAN_API_KEY",        "description": "Exposed services on customer IPs"},
    "censys":           {"tier": "key_optional","name": "Censys",               "key_env": "CENSYS_API_ID",         "description": "Exposed certificates and services per customer domain"},
    "intelx":           {"tier": "key_optional","name": "IntelX",               "key_env": "INTELX_API_KEY",        "description": "Dark web + paste + leak search per customer domain"},
    "hibp":             {"tier": "key_optional","name": "HIBP + BreachDir",     "key_env": "HIBP_API_KEY",          "description": "Breached accounts per domain ($3.50/mo HIBP)"},
    "socradar":         {"tier": "key_optional","name": "SocRadar",             "key_env": "SOCRADAR_API_KEY",      "description": "Brand monitoring, leak alerts"},
    "virustotal":       {"tier": "key_optional","name": "VirusTotal",           "key_env": "VIRUSTOTAL_API_KEY",    "description": "Multi-engine malware scanning & URL analysis"},
    "greynoise":        {"tier": "key_optional","name": "GreyNoise",            "key_env": "GREYNOISE_API_KEY",     "description": "Internet background noise classification"},
    "binaryedge":       {"tier": "key_optional","name": "BinaryEdge",           "key_env": "BINARYEDGE_API_KEY",    "description": "Internet scanning and data analytics"},
    "leakcheck":        {"tier": "key_optional","name": "LeakCheck",            "key_env": "LEAKCHECK_API_KEY",     "description": "Credential breach monitoring"},
    "mandiant":         {"tier": "enterprise", "name": "Mandiant",              "key_env": "MANDIANT_API_KEY",      "description": "Google Mandiant threat intelligence"},
    "spycloud":         {"tier": "enterprise", "name": "SpyCloud",              "key_env": "SPYCLOUD_API_KEY",      "description": "Live stealer logs with session confirmation"},
    "crowdstrike":      {"tier": "enterprise", "name": "CrowdStrike Falcon",   "key_env": "CROWDSTRIKE_CLIENT_ID", "description": "Threat actor profiles, campaign attribution"},
    "cybersixgill":     {"tier": "enterprise", "name": "Cybersixgill",         "key_env": "CYBERSIXGILL_CLIENT_ID","description": "Invite-only dark web forums (pending)"},
    "recordedfuture":   {"tier": "enterprise", "name": "Recorded Future",      "key_env": "RECORDED_FUTURE_KEY",   "description": "Credential exposure alerts (pending)"},
    "cyberint":         {"tier": "enterprise", "name": "Cyberint",             "key_env": "CYBERINT_API_KEY",      "description": "ATO confirmation alerts (pending)"},
    "flare":            {"tier": "enterprise", "name": "Flare",                "key_env": "FLARE_API_KEY",         "description": "Aggregated dark web credentials (pending)"},
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database connection on startup, auto-collect from all sources."""
    print("=" * 55, flush=True)
    print("  Intel Proxy Gateway - Starting", flush=True)
    print("=" * 55, flush=True)

    # Wait for DB to be ready
    for attempt in range(10):
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            log.info("  DB connected OK")
            break
        except Exception as e:
            log.warning(f"  DB not ready (attempt {attempt+1}): {e}")
            await asyncio.sleep(3)

    # Auto-run all collectors on startup
    _bg_task = None  # prevent garbage collection

    async def auto_collect():
        print(flush=True)
        print("=" * 55, flush=True)
        print("  AUTO-COLLECT STARTING (5s delay)...", flush=True)
        print("=" * 55, flush=True)
        try:
            await asyncio.sleep(5)
            print(f"  Running {len(ALL_COLLECTORS)} collectors...", flush=True)
            results = {}
            for name, func in ALL_COLLECTORS.items():
                try:
                    r = await asyncio.wait_for(func(), timeout=60)
                    results[name] = r
                    new = r.get("new", 0) if isinstance(r, dict) else 0
                    err = r.get("error") if isinstance(r, dict) else None
                    symbol = "✓" if not err else "✗"
                    print(f"  {symbol} {name}: {new} new", flush=True)
                except asyncio.TimeoutError:
                    print(f"  ✗ {name}: TIMEOUT (60s)", flush=True)
                    results[name] = {"error": "timeout"}
                except Exception as e:
                    print(f"  ✗ {name}: {type(e).__name__}: {e}", flush=True)
                    results[name] = {"error": str(e)}
            total_new = sum((r.get("new", 0) if isinstance(r, dict) else 0) for r in results.values())
            total_err = sum(1 for r in results.values() if isinstance(r, dict) and r.get("error"))
            print("=" * 55, flush=True)
            print(f"  Intel Proxy - Collection complete", flush=True)
            print(f"  {total_new} new IOCs from {len(results)-total_err}/{len(results)} sources", flush=True)
            print("=" * 55, flush=True)
        except Exception as e:
            import traceback
            print(f"  !!! AUTO-COLLECT CRASHED: {e}", flush=True)
            traceback.print_exc()

    _bg_task = asyncio.create_task(auto_collect())
    yield
    await engine.dispose()


async def collect_all():
    """Trigger all collectors."""
    print(f"[COLLECT_ALL] Starting {len(ALL_COLLECTORS)} collectors...", flush=True)
    results = {}
    for name, func in ALL_COLLECTORS.items():
        try:
            results[name] = await asyncio.wait_for(func(), timeout=60)
            new = results[name].get("new", 0) if isinstance(results[name], dict) else 0
            print(f"  {name}: {new} new", flush=True)
        except asyncio.TimeoutError:
            results[name] = {"error": "timeout (60s)"}
            print(f"  {name}: TIMEOUT", flush=True)
        except Exception as e:
            results[name] = {"error": str(e)}
            print(f"  {name}: ERROR {e}", flush=True)
    total = sum((r.get("new", 0) if isinstance(r, dict) else 0) for r in results.values())
    print(f"[COLLECT_ALL] Done: {total} new IOCs", flush=True)
    return {"status": "ok", "results": results}



async def collect_one(collector_name: str):
    """Trigger a specific collector."""
    func = ALL_COLLECTORS.get(collector_name)
    if not func:
        return {"error": f"Unknown collector: {collector_name}", "available": list(ALL_COLLECTORS.keys())}
    try:
        return await func()
    except Exception as e:
        return {"error": str(e)}




async def _enrich_epss_batch(cve_ids: list) -> int:
    """Fetch EPSS scores from FIRST.org API and store in detection metadata.
    
    EPSS = Exploit Prediction Scoring System
    Free API, no auth, returns probability of exploitation within 30 days.
    """
    enriched = 0
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i:i+100]
        cve_list = ",".join(batch)
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as c:
                resp = await c.get(f"https://api.first.org/data/v1/epss?cve={cve_list}")
                if resp.status_code != 200:
                    continue
                epss_data = resp.json().get("data", [])
                epss_map = {e["cve"]: e for e in epss_data}
                
                async with AsyncSessionLocal() as db:
                    for cve_id in batch:
                        entry = epss_map.get(cve_id)
                        if not entry:
                            continue
                        epss_score = float(entry.get("epss", 0))
                        epss_pct = float(entry.get("percentile", 0))
                        # Update detection metadata with EPSS
                        try:
                            await db.execute(text("""
                                UPDATE detections SET metadata = 
                                    COALESCE(metadata, '{}'::jsonb) || :epss_data
                                WHERE ioc_value = :cve_id AND source = 'nvd'
                            """), {
                                "cve_id": cve_id,
                                "epss_data": json.dumps({"epss_score": epss_score, "epss_percentile": epss_pct}),
                            })
                            enriched += 1
                        except Exception:
                            pass
                    await db.commit()
        except Exception as e:
            log.warning(f"EPSS batch failed: {e}")
    return enriched

# collect_mitre -> collectors_registry.py
# collect_ransomfeed -> collectors_registry.py
# collect_rss -> collectors_registry.py
# collect_paste -> collectors_registry.py
# collect_hudsonrock -> collectors_registry.py

# collect_otx -> collectors_registry.py

# collect_urlscan -> collectors_registry.py

# collect_phishtank_urlhaus -> collectors_registry.py

# collect_shodan_customer -> collectors_registry.py

# collect_censys -> collectors_registry.py

# collect_intelx -> collectors_registry.py

# collect_darksearch -> collectors_registry.py

# collect_circl_misp -> collectors_registry.py

# collect_pulsedive -> collectors_registry.py

# collect_vxunderground -> collectors_registry.py

# collect_ransomwatch -> collectors_registry.py

# collect_grep_app -> collectors_registry.py

# collect_github_secrets -> collectors_registry.py

# collect_breach -> collectors_registry.py

# collect_socradar -> collectors_registry.py
# collect_spycloud -> collectors_registry.py

# collect_crowdstrike -> collectors_registry.py
def _load_pm():
    global _pm_scan_v2, _sev_score_v2, _pm_loaded_v2
    if _pm_loaded_v2:
        return
    _pm_loaded_v2 = True
    try:
        from arguswatch.engine.pattern_matcher import scan_text
        _pm_scan_v2 = scan_text
    except ImportError:
        log.warning("pattern_matcher not available -  raw text collectors disabled")
    try:
        from arguswatch.engine.severity_scorer import score
        _sev_score_v2 = score
    except ImportError:
        pass


async def _store_ioc_matches(db_ignored, raw_text, source_name, source_url,
                              customer_id=None, metadata_extra=None):
    """Run pattern_matcher on raw text, store each IOC as a Detection."""
    _load_pm()
    if not _pm_scan_v2 or not raw_text or len(raw_text) < 10:
        return 0
    try:
        matches = _pm_scan_v2(raw_text)
    except Exception as e:
        log.debug(f"pattern_matcher error: {e}")
        return 0

    # V16.4.5: IOC types where collector-level customer_id is WRONG.
    # A gist search for "github.com" finds gists with random URLs inside.
    # Those URLs belong to whoever owns the domain, NOT to GitHub.
    # Only hash/CVE/advisory types make sense with context-based customer routing.
    CONTEXT_SAFE_TYPES = {
        "cve_id", "advisory", "sha256", "sha1", "md5", "sha512",
        "malware_hash", "apt_group", "ransomware_group", "campaign",
        "breach_record", "email_password_combo", "username_password_combo",
        "breachdirectory_combo", "privileged_credential", "config_file",
        "sql_schema_dump", "crypto_seed_phrase", "bitcoin_address",
        "monero_address", "data_auction", "ransom_note",
    }

    new_count = 0
    # Skip IOC types that are public data, not leaked secrets (swift_bic = 53% of all Gist output)
    SKIP_JUNK_TYPES = {"swift_bic", "ach_routing"}
    # V16.4.5: False positive patterns that should NEVER be stored
    FP_PATTERNS = {
        "privileged_credential": [
            r"^system:\\n",      # Mermaid diagrams starting with system:
            r"^system:\*\*",     # Markdown bold system headers
            r"^System:\*\*",
            r"```mermaid",       # Mermaid code blocks
            r"^admin$",          # Generic words, not actual credentials
            r"^root$",
            r"^administrator$",
        ],
        "malicious_url_path": [
            r"^aff\.php\?",      # Affiliate tracking links, not malicious
            r"^ref\.php\?",
            r"^click\.php\?",
            r"^track\.php\?",
        ],
    }
    import re as _re_fp
    def _is_false_positive(ioc_type, value):
        patterns = FP_PATTERNS.get(ioc_type)
        if not patterns:
            return False
        for pat in patterns:
            if _re_fp.search(pat, value, _re_fp.IGNORECASE):
                return True
        return False

    for m in matches[:100]:
        if m.ioc_type in SKIP_JUNK_TYPES:
            continue
        if _is_false_positive(m.ioc_type, m.value):
            continue
        severity = "MEDIUM"
        sla = 48
        if _sev_score_v2:
            try:
                scored = _sev_score_v2(m.category, m.ioc_type, confidence=m.confidence)
                severity = scored.severity
                sla = scored.sla_hours
            except Exception:
                pass
        pos = raw_text.find(m.value)
        if pos >= 0:
            context = raw_text[max(0, pos - 200):min(len(raw_text), pos + len(m.value) + 200)]
        else:
            context = raw_text[:400]
        raw_desc = f"{source_name}: {m.ioc_type} in {source_url[:100]} -  {context[:200]}"
        meta = {"category": m.category, "ioc_type": m.ioc_type,
                "confidence": m.confidence, "source_url": source_url,
                "line_number": m.line_number}
        if metadata_extra:
            meta.update(metadata_extra)
        det_id = await insert_detection(
            db_ignored, source_name, m.ioc_type, m.value,
            severity, sla, raw_desc[:2000],
            confidence=m.confidence,
            # V16.4.5: Only pass customer_id for IOC types where context makes sense.
            # URL/domain/email IOCs get customer_id=None -> correlation engine routes them.
            customer_id=customer_id if m.ioc_type in CONTEXT_SAFE_TYPES else None,
            metadata=meta)
        if det_id:
            new_count += 1
    return new_count


# ═══════════════════════════════════════════════════════════════
# Inject helpers into collectors_registry (must be AFTER _store_ioc_matches is defined)
# ═══════════════════════════════════════════════════════════════
# get_pool and settings are legacy params - not used by any collector but required by init_helpers signature
get_pool = None
settings = type('Settings', (), {'OLLAMA_MODEL': 'qwen3:8b', 'OLLAMA_URL': 'http://ollama:11434'})()
collectors_registry.init_helpers(
    insert_detection, insert_collector_run, insert_actor, insert_darkweb,
    get_pool, settings, _store_ioc_matches_fn=_store_ioc_matches,
    _async_session_local=AsyncSessionLocal,
)
print(f"[STARTUP] init_helpers injected. AsyncSessionLocal={collectors_registry.AsyncSessionLocal is not None}", flush=True)
print(f"[STARTUP] ALL_COLLECTORS: {len(ALL_COLLECTORS)} collectors registered", flush=True)


# collect_github_gists -> collectors_registry.py

# collect_sourcegraph -> collectors_registry.py

# collect_alt_paste -> collectors_registry.py

# collect_grayhatwarfare -> collectors_registry.py

# collect_leakix -> collectors_registry.py

# collect_telegram -> collectors_registry.py
# collect_crtsh -> collectors_registry.py

# collect_hibp_breaches -> collectors_registry.py

# collect_github_code_search -> collectors_registry.py

# collect_urlscan_community -> collectors_registry.py
# collect_recordedfuture -> collectors_registry.py
# collect_cyberint -> collectors_registry.py
# collect_flare -> collectors_registry.py
async def enrich_domain(domain: str) -> dict:
    """Real DNS + WHOIS-like enrichment for a domain."""
    result = {"domain": domain, "dns": {}, "whois": {}, "reputation": {}}
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as c:
        # DNS via DNS-over-HTTPS (Cloudflare)
        try:
            resp = await c.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
                              headers={"Accept": "application/dns-json"})
            if resp.status_code == 200:
                data = resp.json()
                result["dns"]["A"] = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
        except Exception: pass
        # MX records
        try:
            resp = await c.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX",
                              headers={"Accept": "application/dns-json"})
            if resp.status_code == 200:
                data = resp.json()
                result["dns"]["MX"] = [a["data"] for a in data.get("Answer", []) if a.get("type") == 15]
        except Exception: pass
        # RDAP (WHOIS replacement)
        try:
            resp = await c.get(f"https://rdap.org/domain/{domain}")
            if resp.status_code == 200:
                data = resp.json()
                result["whois"]["name"] = data.get("name", "")
                result["whois"]["status"] = data.get("status", [])
                for e in data.get("entities", []):
                    if "registrant" in e.get("roles", []):
                        vcards = e.get("vcardArray", [None, []])[1] if e.get("vcardArray") else []
                        for vc in vcards:
                            if isinstance(vc, list) and len(vc) > 3 and vc[0] == "org":
                                result["whois"]["registrant_org"] = vc[3]
        except Exception: pass
        # VirusTotal (if key available)
        if VT_KEY:
            try:
                resp = await c.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                                  headers={"x-apikey": VT_KEY})
                if resp.status_code == 200:
                    vt = resp.json().get("data", {}).get("attributes", {})
                    stats = vt.get("last_analysis_stats", {})
                    result["reputation"]["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "clean": stats.get("harmless", 0),
                        "reputation": vt.get("reputation", 0),
                    }
            except Exception: pass
    return result

async def enrich_ip(ip: str) -> dict:
    """Real IP enrichment."""
    result = {"ip": ip, "geo": {}, "reputation": {}, "rdns": ""}
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as c:
        # Reverse DNS
        try:
            resp = await c.get(f"https://cloudflare-dns.com/dns-query?name={ip}&type=PTR",
                              headers={"Accept": "application/dns-json"})
            if resp.status_code == 200:
                data = resp.json()
                ptrs = [a["data"] for a in data.get("Answer", []) if a.get("type") == 12]
                result["rdns"] = ptrs[0] if ptrs else ""
        except Exception: pass
        # AbuseIPDB (if key)
        if ABUSEIPDB_KEY:
            try:
                resp = await c.get("https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip}, headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"})
                if resp.status_code == 200:
                    d = resp.json().get("data", {})
                    result["reputation"]["abuseipdb"] = {
                        "score": d.get("abuseConfidenceScore", 0),
                        "reports": d.get("totalReports", 0),
                        "country": d.get("countryCode", ""),
                        "isp": d.get("isp", ""),
                    }
            except Exception: pass
        # Shodan (if key)
        if SHODAN_KEY:
            try:
                resp = await c.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}")
                if resp.status_code == 200:
                    d = resp.json()
                    result["reputation"]["shodan"] = {
                        "ports": d.get("ports", []),
                        "org": d.get("org", ""),
                        "os": d.get("os", ""),
                        "vulns": d.get("vulns", []),
                    }
            except Exception: pass
    return result


# ════════════════════════════════════════════════════════════
# ASSET DISCOVERY - real OSINT for customer domains
# ════════════════════════════════════════════════════════════

async def discover_assets(domain: str) -> dict:
    """Real asset discovery using free OSINT sources."""
    result = {"domain": domain, "subdomains": [], "ips": [], "emails": [], "certs": []}
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as c:
        # Certificate Transparency (crt.sh)
        try:
            resp = await c.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if resp.status_code == 200:
                certs = resp.json()
                seen = set()
                for cert in certs[:200]:
                    cn = cert.get("common_name", "")
                    if cn and cn not in seen and domain in cn:
                        seen.add(cn)
                        result["subdomains"].append(cn)
                result["certs"] = len(certs)
        except Exception: pass
        # DNS lookups for found subdomains
        for sub in result["subdomains"][:20]:
            try:
                resp = await c.get(f"https://cloudflare-dns.com/dns-query?name={sub}&type=A",
                    headers={"Accept": "application/dns-json"})
                if resp.status_code == 200:
                    for a in resp.json().get("Answer", []):
                        if a.get("type") == 1:
                            result["ips"].append({"subdomain": sub, "ip": a["data"]})
            except Exception: pass
        # Common email patterns
        result["emails"] = [f"{prefix}@{domain}" for prefix in
            ["security", "admin", "abuse", "info", "support", "hr", "legal", "privacy"]]
    return result


# ════════════════════════════════════════════════════════════
# V16.4.5: NEW HIGH-VALUE FREE COLLECTORS
# ════════════════════════════════════════════════════════════

# collect_shodan_internetdb -> collectors_registry.py

# collect_crtsh -> collectors_registry.py

# collect_typosquat -> collectors_registry.py

# collect_epss_top -> collectors_registry.py

app = FastAPI(title="ArgusWatch Intel Proxy Gateway", lifespan=lifespan)

@app.post("/settings/key")
async def set_runtime_key(request: Request):
    """Accept API key updates at runtime from backend Settings page.
    Sets os.environ so collectors pick it up on next run.
    Keys are IN-MEMORY only -  add to .env for persistence."""
    body = await request.json()
    key_name = body.get("key", "")
    key_value = body.get("value", "")
    if not key_name or not key_value:
        return {"error": "key and value required"}
    
    # Security: only allow known key names
    ALLOWED = {
        "SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "HIBP_API_KEY", "OTX_API_KEY",
        "URLSCAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET", "INTELX_API_KEY",
        "GREYNOISE_API_KEY", "BINARYEDGE_API_KEY", "LEAKCHECK_API_KEY",
        "SPYCLOUD_API_KEY", "RECORDED_FUTURE_KEY", "CROWDSTRIKE_CLIENT_ID",
        "CROWDSTRIKE_SECRET", "FLARE_API_KEY", "CYBERINT_API_KEY",
        "SOCRADAR_API_KEY", "GRAYHATWARFARE_API_KEY", "LEAKIX_API_KEY",
        "GITHUB_TOKEN", "PULSEDIVE_API_KEY", "HUDSON_ROCK_API_KEY",
        "MANDIANT_API_KEY", "PHISHTANK_API_KEY", "PASTE_EE_API_KEY",
        "ABUSEIPDB_API_KEY", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHANNELS",
        "CYBERSIXGILL_CLIENT_ID", "CYBERSIXGILL_SECRET",
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_AI_API_KEY",
    }
    if key_name not in ALLOWED:
        return {"error": f"Unknown key: {key_name}"}
    
    os.environ[key_name] = key_value
    # Update module-level variables that collectors read at import time
    globals_to_update = {
        "SHODAN_API_KEY": "SHODAN_KEY", "GITHUB_TOKEN": "GITHUB_TOKEN",
        "GRAYHATWARFARE_API_KEY": "GRAYHAT_KEY", "LEAKIX_API_KEY": "LEAKIX_KEY",
        "TELEGRAM_BOT_TOKEN": "TELEGRAM_BOT_TOKEN",
    }
    if key_name in globals_to_update:
        gname = globals_to_update[key_name]
        if gname in globals():
            globals()[gname] = key_value
    
    log.info(f"Runtime key set: {key_name} ({'*' * min(4, len(key_value))}...)")
    return {"set": key_name, "active": True, "note": "In-memory only. Add to .env for persistence."}


@app.get("/health")
async def health():
    """Health check + network connectivity test."""
    tests = {}
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as c:
        for name, url in [("cisa", "https://www.cisa.gov"), ("abuse_ch", "https://abuse.ch"), ("github", "https://github.com")]:
            try:
                r = await c.head(url)
                tests[name] = {"ok": True, "status": r.status_code}
            except Exception as e:
                tests[name] = {"ok": False, "error": str(e)[:60]}
    return {"status": "ok", "network": tests, "internet_access": any(t["ok"] for t in tests.values())}

@app.post("/collect/all")
async def api_collect_all():
    """Trigger ALL collectors. Returns per-collector results."""
    return await collect_all()

@app.post("/collect/{collector_name}")
async def api_collect_one(collector_name: str):
    """Trigger a specific collector by name."""
    func = ALL_COLLECTORS.get(collector_name)
    if not func:
        return {"error": f"Unknown collector: {collector_name}", "available": list(ALL_COLLECTORS.keys())}
    try:
        result = await func()
        return result
    except Exception as e:
        log.error(f"Collector {collector_name} failed: {e}")
        return {"error": str(e), "new": 0}

@app.get("/enrich/domain/{domain}")
async def api_enrich_domain(domain: str):
    """Real domain enrichment - DNS, WHOIS, reputation."""
    return await enrich_domain(domain)

@app.get("/enrich/ip/{ip}")
async def api_enrich_ip(ip: str):
    """Real IP enrichment - rDNS, AbuseIPDB, Shodan."""
    return await enrich_ip(ip)

@app.get("/discover/{domain}")
async def api_discover(domain: str):
    """Real asset discovery - crt.sh, DNS, email patterns."""
    return await discover_assets(domain)


@app.get("/search/compromise/{query}")
async def search_compromise(query: str):
    """Search if an email, domain, hash, or keyword has been compromised.
    
    Checks multiple sources simultaneously:
    1. LOCAL DB: Search our detections + findings tables for this IOC
    2. HUDSONROCK: Free stealer log API (if query looks like email/domain)
    3. HIBP: Breach check (if HIBP_API_KEY configured and query is email)
    4. SOURCEGRAPH: Search public code for this value
    5. PATTERN CLASSIFY: Run pattern_matcher on the query itself to identify what type it is
    
    Returns a unified result with all findings.
    """
    import re as _re
    query = query.strip()
    if len(query) < 3 or len(query) > 500:
        return {"error": "Query must be 3-500 characters", "results": []}

    results = {"query": query, "query_type": "unknown", "sources_checked": [],
               "compromised": False, "total_hits": 0, "findings": []}

    # Step 1: Classify the query
    if _re.match(r'^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$', query):
        results["query_type"] = "email"
    elif _re.match(r'^[a-fA-F0-9]{32}$', query):
        results["query_type"] = "md5_hash"
    elif _re.match(r'^[a-fA-F0-9]{40}$', query):
        results["query_type"] = "sha1_hash"
    elif _re.match(r'^[a-fA-F0-9]{64}$', query):
        results["query_type"] = "sha256_hash"
    elif _re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', query):
        results["query_type"] = "ip"
    elif _re.match(r'^CVE-\d{4}-\d{4,7}$', query, _re.IGNORECASE):
        results["query_type"] = "cve"
    elif _re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', query):
        results["query_type"] = "domain"
    elif _re.match(r'^AKIA[0-9A-Z]{16}$', query):
        results["query_type"] = "aws_key"
    elif _re.match(r'^ghp_[A-Za-z0-9]{36}$', query):
        results["query_type"] = "github_token"
    elif _re.match(r'^sk_live_[A-Za-z0-9]{24,}$', query):
        results["query_type"] = "stripe_key"
    elif _re.match(r'^\d{3}-\d{2}-\d{4}$', query):
        results["query_type"] = "ssn"
    else:
        results["query_type"] = "keyword"

    # Step 2: Search our own database
    try:
        async with AsyncSessionLocal() as db:
            # Exact match
            r = await db.execute(text(
                "SELECT id, source, ioc_type, ioc_value, severity, raw_text, created_at "
                "FROM detections WHERE ioc_value = :q ORDER BY created_at DESC LIMIT 20"
            ), {"q": query})
            exact_hits = r.fetchall()
            
            # Partial match (LIKE)
            r2 = await db.execute(text(
                "SELECT id, source, ioc_type, ioc_value, severity, raw_text, created_at "
                "FROM detections WHERE ioc_value LIKE :q AND ioc_value != :exact "
                "ORDER BY created_at DESC LIMIT 20"
            ), {"q": f"%{query}%", "exact": query})
            partial_hits = r2.fetchall()

            # Also search findings
            r3 = await db.execute(text(
                "SELECT id, ioc_type, ioc_value, severity, ai_narrative, created_at "
                "FROM findings WHERE ioc_value = :q OR ioc_value LIKE :like "
                "ORDER BY created_at DESC LIMIT 20"
            ), {"q": query, "like": f"%{query}%"})
            finding_hits = r3.fetchall()

            # Also search dark web mentions
            r4 = await db.execute(text(
                "SELECT id, source, title, threat_actor, severity, discovered_at "
                "FROM darkweb_mentions WHERE title LIKE :q OR content_snippet LIKE :q "
                "ORDER BY discovered_at DESC LIMIT 10"
            ), {"q": f"%{query}%"})
            darkweb_hits = r4.fetchall()

        for hit in exact_hits:
            results["findings"].append({
                "source": "arguswatch_db", "match_type": "exact",
                "detection_id": hit[0], "feed": hit[1], "ioc_type": hit[2],
                "ioc_value": hit[3], "severity": hit[4],
                "context": (hit[5] or "")[:200],
                "found_at": hit[6].isoformat() if hit[6] else None,
            })
        for hit in partial_hits:
            results["findings"].append({
                "source": "arguswatch_db", "match_type": "partial",
                "detection_id": hit[0], "feed": hit[1], "ioc_type": hit[2],
                "ioc_value": hit[3], "severity": hit[4],
                "context": (hit[5] or "")[:200],
                "found_at": hit[6].isoformat() if hit[6] else None,
            })
        for hit in finding_hits:
            results["findings"].append({
                "source": "arguswatch_findings", "match_type": "finding",
                "finding_id": hit[0], "ioc_type": hit[1],
                "ioc_value": hit[2], "severity": hit[3],
                "context": (hit[4] or "")[:200],
                "found_at": hit[5].isoformat() if hit[5] else None,
            })
        for hit in darkweb_hits:
            results["findings"].append({
                "source": "darkweb_mention", "match_type": "darkweb",
                "mention_id": hit[0], "feed": hit[1],
                "title": hit[2], "threat_actor": hit[3],
                "severity": hit[4],
                "found_at": hit[5].isoformat() if hit[5] else None,
            })
        results["sources_checked"].append({"name": "ArgusWatch DB", "status": "ok",
            "hits": len(exact_hits) + len(partial_hits) + len(finding_hits) + len(darkweb_hits)})
    except Exception as e:
        results["sources_checked"].append({"name": "ArgusWatch DB", "status": f"error: {str(e)[:80]}", "hits": 0})

    # Step 3: HudsonRock (email or domain)
    if results["query_type"] in ("email", "domain"):
        search_domain = query.split("@")[1] if "@" in query else query
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as c:
                resp = await c.get(
                    f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={search_domain}",
                    headers={"User-Agent": "ArgusWatch/16.4"})
                if resp.status_code == 200:
                    data = resp.json()
                    stealers = data.get("stealers", [])
                    # If searching for specific email, filter
                    if results["query_type"] == "email":
                        stealers = [s for s in stealers if query.lower() in str(s).lower()]
                    for s in stealers[:10]:
                        results["findings"].append({
                            "source": "hudsonrock", "match_type": "stealer_log",
                            "severity": "HIGH",
                            "context": f"Found in stealer log: {str(s)[:200]}",
                            "raw_data": {k: v for k, v in s.items() if k in (
                                "email", "url", "date_compromised", "computer_name", "operating_system")} if isinstance(s, dict) else str(s)[:200],
                        })
                    results["sources_checked"].append({"name": "HudsonRock", "status": "ok", "hits": len(stealers)})
                elif resp.status_code == 404:
                    results["sources_checked"].append({"name": "HudsonRock", "status": "ok", "hits": 0})
                else:
                    results["sources_checked"].append({"name": "HudsonRock", "status": f"http_{resp.status_code}", "hits": 0})
        except Exception as e:
            results["sources_checked"].append({"name": "HudsonRock", "status": f"error: {str(e)[:80]}", "hits": 0})

    # Step 4: HIBP (email only)
    if results["query_type"] == "email" and HIBP_KEY:
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as c:
                resp = await c.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{query}",
                    headers={"hibp-api-key": HIBP_KEY, "User-Agent": "ArgusWatch/16.4"},
                    params={"truncateResponse": "false"})
                if resp.status_code == 200:
                    breaches = resp.json()
                    for b in breaches[:10]:
                        results["findings"].append({
                            "source": "hibp", "match_type": "breach",
                            "severity": "CRITICAL" if b.get("IsVerified") else "HIGH",
                            "breach_name": b.get("Name", ""),
                            "breach_date": b.get("BreachDate", ""),
                            "data_classes": b.get("DataClasses", []),
                            "context": f"Breached in {b.get('Name', '?')} ({b.get('BreachDate', '?')}): {', '.join(b.get('DataClasses', [])[:5])}",
                        })
                    results["sources_checked"].append({"name": "HIBP", "status": "ok", "hits": len(breaches)})
                elif resp.status_code == 404:
                    results["sources_checked"].append({"name": "HIBP", "status": "ok", "hits": 0})
                else:
                    results["sources_checked"].append({"name": "HIBP", "status": f"http_{resp.status_code}", "hits": 0})
        except Exception as e:
            results["sources_checked"].append({"name": "HIBP", "status": f"error: {str(e)[:80]}", "hits": 0})
    elif results["query_type"] == "email" and not HIBP_KEY:
        results["sources_checked"].append({"name": "HIBP", "status": "skipped_no_key", "hits": 0})

    # Step 5: Sourcegraph (any text -  search public code)
    if results["query_type"] not in ("ssn",):  # Don't search SSNs on public code
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as c:
                sg_query = f'"{query}" type:file count:10'
                resp = await c.post("https://sourcegraph.com/.api/graphql",
                    json={"query": """query($q:String!){search(query:$q,version:V3){
                        results{results{...on FileMatch{repository{name}file{path}
                        lineMatches{preview}}}}}}""",
                        "variables": {"q": sg_query}},
                    headers={"User-Agent": "ArgusWatch/16.4"}, timeout=15.0)
                if resp.status_code == 200:
                    sg_results = (resp.json().get("data", {}).get("search", {})
                                  .get("results", {}).get("results", []))
                    for r in sg_results[:5]:
                        repo = r.get("repository", {}).get("name", "")
                        fpath = r.get("file", {}).get("path", "")
                        preview = "\n".join(lm.get("preview", "") for lm in r.get("lineMatches", [])[:3])
                        results["findings"].append({
                            "source": "sourcegraph", "match_type": "code_leak",
                            "severity": "CRITICAL" if results["query_type"] in ("aws_key", "github_token", "stripe_key") else "HIGH",
                            "repo": repo, "file": fpath,
                            "context": f"Found in {repo}/{fpath}: {preview[:200]}",
                            "url": f"https://sourcegraph.com/{repo}/-/blob/{fpath}",
                        })
                    results["sources_checked"].append({"name": "Sourcegraph", "status": "ok", "hits": len(sg_results)})
                else:
                    results["sources_checked"].append({"name": "Sourcegraph", "status": f"http_{resp.status_code}", "hits": 0})
        except Exception as e:
            results["sources_checked"].append({"name": "Sourcegraph", "status": f"error: {str(e)[:80]}", "hits": 0})

    # Step 6: VirusTotal (hash only)
    if results["query_type"] in ("md5_hash", "sha1_hash", "sha256_hash") and VT_KEY:
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as c:
                resp = await c.get(f"https://www.virustotal.com/api/v3/files/{query}",
                                   headers={"x-apikey": VT_KEY})
                if resp.status_code == 200:
                    vt = resp.json().get("data", {}).get("attributes", {})
                    stats = vt.get("last_analysis_stats", {})
                    results["findings"].append({
                        "source": "virustotal", "match_type": "malware_scan",
                        "severity": "CRITICAL" if stats.get("malicious", 0) > 10 else "HIGH" if stats.get("malicious", 0) > 0 else "LOW",
                        "malicious_engines": stats.get("malicious", 0),
                        "total_engines": sum(stats.values()),
                        "file_type": vt.get("type_description", ""),
                        "context": f"VirusTotal: {stats.get('malicious', 0)}/{sum(stats.values())} engines detect as malicious",
                    })
                    results["sources_checked"].append({"name": "VirusTotal", "status": "ok", "hits": 1 if stats.get("malicious", 0) > 0 else 0})
                elif resp.status_code == 404:
                    results["sources_checked"].append({"name": "VirusTotal", "status": "ok", "hits": 0})
                else:
                    results["sources_checked"].append({"name": "VirusTotal", "status": f"http_{resp.status_code}", "hits": 0})
        except Exception as e:
            results["sources_checked"].append({"name": "VirusTotal", "status": f"error: {str(e)[:80]}", "hits": 0})
    elif results["query_type"] in ("md5_hash", "sha1_hash", "sha256_hash") and not VT_KEY:
        results["sources_checked"].append({"name": "VirusTotal", "status": "skipped_no_key", "hits": 0})

    # Summarize
    results["total_hits"] = len(results["findings"])
    results["compromised"] = results["total_hits"] > 0
    results["severity_summary"] = {
        "critical": sum(1 for f in results["findings"] if f.get("severity") == "CRITICAL"),
        "high": sum(1 for f in results["findings"] if f.get("severity") == "HIGH"),
        "medium": sum(1 for f in results["findings"] if f.get("severity") == "MEDIUM"),
    }

    return results


@app.get("/collectors/status")
async def collector_status():
    """ONE-CLICK SETUP: Shows all 30 collectors, which are active, which need keys.
    
    Frontend renders this as a settings page where operators can:
    1. See which collectors are running (green)
    2. See which need API keys (yellow) 
    3. Enter keys via the /collectors/configure endpoint
    4. Toggle collectors on/off
    
    This is the dynamic setup page for MSSPs.
    """
    status = []
    for cid, info in COLLECTOR_INFO.items():
        key_env = info.get("key_env")
        key_configured = False
        key_value_hint = ""
        
        if key_env:
            key_val = os.getenv(key_env, "")
            key_configured = bool(key_val)
            key_value_hint = f"{key_val[:4]}...{key_val[-4:]}" if len(key_val) > 8 else ("set" if key_val else "")
        
        needs_key = key_env is not None and not key_configured
        active = not needs_key or info["tier"] == "free"
        
        # Check last run from DB
        last_run = None
        last_status = None
        try:
            async with AsyncSessionLocal() as db:
                r = await db.execute(text(
                    "SELECT completed_at, status FROM collector_runs WHERE collector_name=:n ORDER BY completed_at DESC LIMIT 1"
                ), {"n": cid})
                row = r.first()
                if row:
                    last_run = row[0].isoformat() if row[0] else None
                    last_status = row[1]
        except Exception: pass
        
        status.append({
            "id": cid,
            "name": info["name"],
            "tier": info["tier"],
            "description": info["description"],
            "active": active,
            "needs_key": needs_key,
            "key_env_var": key_env,
            "key_configured": key_configured,
            "key_hint": key_value_hint,
            "last_run": last_run,
            "last_status": last_status,
        })
    
    summary = {
        "total": len(status),
        "active": sum(1 for s in status if s["active"]),
        "needs_key": sum(1 for s in status if s["needs_key"]),
        "free": sum(1 for s in status if COLLECTOR_INFO[s["id"]]["tier"] == "free"),
        "key_optional": sum(1 for s in status if COLLECTOR_INFO[s["id"]]["tier"] == "key_optional"),
        "enterprise": sum(1 for s in status if COLLECTOR_INFO[s["id"]]["tier"] == "enterprise"),
    }
    
    return {"summary": summary, "collectors": status}

