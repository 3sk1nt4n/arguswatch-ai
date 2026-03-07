"""
ArgusWatch Intel Proxy Gateway
================================
Separate microservice with FULL internet access.
Fetches REAL threat intel from public feeds, writes directly to PostgreSQL.

Architecture:
  [Backend container]  →  http://intel-proxy:9000/collect/all
  [Intel Proxy]        →  CISA, MITRE, abuse.ch, NVD, OpenPhish, RSS...
  [Intel Proxy]        →  writes detections + actors + darkweb directly to DB

This is the enterprise pattern used by CrowdStrike, Splunk SOAR, Cortex XSOAR.
"""

import os, asyncio, logging, time, json, hashlib, re
from datetime import datetime, timedelta
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
PG_PASS = os.getenv("POSTGRES_PASSWORD", "arguswatch_dev_2026")
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


# ════════════════════════════════════════════════════════════
# REAL COLLECTORS - each fetches from actual internet sources
# ════════════════════════════════════════════════════════════

async def collect_cisa_kev():
    """CISA Known Exploited Vulnerabilities - real CISA.gov feed.
    v14: Also marks cve_product_map entries as actively_exploited and stores CVSS metadata."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0, "kev_marked": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            data = resp.json()
        vulns = data.get("vulnerabilities", [])
        stats["total"] = len(vulns)
        kev_cve_ids = []
        async with AsyncSessionLocal() as db:
            for v in vulns[-200:]:  # Latest 200
                cve = v.get("cveID", "")
                if not cve:
                    continue
                kev_cve_ids.append(cve)
                vendor = v.get("vendorProject", "")
                product = v.get("product", "")
                desc = v.get("shortDescription", "")
                raw = f"CISA KEV: {cve} - {vendor} {product}: {desc}"
                meta = {"cvss_score": 10.0, "cvss_severity": "CRITICAL", "kev": True,
                        "vendor": vendor, "product": product}
                det_id = await insert_detection(db, "cisa_kev", "cve_id", cve,
                    "CRITICAL", 4, raw, confidence=0.95, metadata=meta)
                if det_id:
                    stats["new"] += 1
                else:
                    stats["skipped"] += 1

            # Mark all KEV CVEs as actively_exploited in cve_product_map
            # V16.4.5: ALSO INSERT product mappings from KEV's own vendor/product fields
            # Before this fix: KEV had vendor+product data but NEVER created mappings.
            # This was the ROOT CAUSE of 189 unrouted CVEs.
            if kev_cve_ids:
                try:
                    for cve_id in kev_cve_ids:
                        await db.execute(text(
                            "UPDATE cve_product_map SET actively_exploited = true WHERE cve_id = :cve_id"
                        ), {"cve_id": cve_id})
                    stats["kev_marked"] = len(kev_cve_ids)
                except Exception as e:
                    log.debug(f"KEV mark failed: {e}")

            # V16.4.5: Create product mappings from KEV vendor/product fields
            kev_products_added = 0
            for v in vulns[-200:]:
                cve = v.get("cveID", "")
                vendor = v.get("vendorProject", "")
                product = v.get("product", "")
                if not cve or not product:
                    continue
                # Normalize product name to match tech_stack format
                product_clean = product.strip().title()
                try:
                    check = await db.execute(text(
                        "SELECT id FROM cve_product_map WHERE cve_id=:c AND product_name=:p LIMIT 1"
                    ), {"c": cve, "p": product_clean})
                    if not check.scalar():
                        await db.execute(text("""
                            INSERT INTO cve_product_map (cve_id, product_name, vendor, version_range, cvss_score, severity, actively_exploited, source, created_at)
                            VALUES (:cve_id, :product, :vendor, '', 10.0, 'CRITICAL', true, 'cisa_kev', NOW())
                        """), {"cve_id": cve, "product": product_clean, "vendor": vendor.strip().title()})
                        kev_products_added += 1
                except Exception as e:
                    pass  # Duplicate or constraint - skip silently
            stats["kev_products_added"] = kev_products_added
            log.info(f"KEV: {kev_products_added} new product mappings added")

            await insert_collector_run(db, "kev", "completed", stats, started, datetime.utcnow())
            await db.commit()
        log.info(f"CISA KEV: {stats['new']} new / {stats['total']} total, {stats['kev_marked']} marked actively_exploited")
    except Exception as e:
        log.error(f"CISA KEV failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "kev", "failed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    return stats

async def collect_feodo():
    """Feodo Tracker - real C2 server IP blocklist from abuse.ch."""
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            entries = resp.json()
        stats["total"] = len(entries) if isinstance(entries, list) else 0
        async with AsyncSessionLocal() as db:
            items = entries if isinstance(entries, list) else []
            for e in items[:500]:
                ip = e.get("ip_address") or e.get("ip") or ""
                if not ip: continue
                malware = e.get("malware", "unknown")
                port = e.get("port", "")
                raw = f"Feodo C2: {ip}:{port} - {malware} botnet infrastructure"
                det_id = await insert_detection(db, "feodo", "ipv4", ip,
                    "CRITICAL", 4, raw, confidence=0.9)
                if det_id: stats["new"] += 1
                else: stats["skipped"] += 1
            await insert_collector_run(db, "feodo", "completed", stats, started, datetime.utcnow())
            await db.commit()
        log.info(f"Feodo: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"Feodo failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "feodo", "failed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    return stats

async def collect_threatfox():
    """ThreatFox - real IOC database from abuse.ch."""
    url = "https://threatfox-api.abuse.ch/api/v1/"
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            resp = await c.post(url, json={"query": "get_iocs", "days": 3})
            resp.raise_for_status()
            data = resp.json()
        iocs = data.get("data", [])
        if not isinstance(iocs, list): iocs = []
        stats["total"] = len(iocs)
        async with AsyncSessionLocal() as db:
            for ioc in iocs[:300]:
                ioc_val = ioc.get("ioc", "")
                if not ioc_val: continue
                ioc_type = ioc.get("ioc_type", "unknown")
                malware = ioc.get("malware_printable", "unknown")
                threat = ioc.get("threat_type_desc", "")
                confidence = int(ioc.get("confidence_level", 50))
                sev = "CRITICAL" if confidence > 80 else "HIGH" if confidence > 50 else "MEDIUM"
                sla = 4 if sev == "CRITICAL" else 12 if sev == "HIGH" else 72
                raw = f"ThreatFox: {ioc_type} - {malware} ({threat}) confidence:{confidence}%"
                # Map ThreatFox types to our types
                det_type = "domain" if "domain" in ioc_type.lower() else \
                           "url" if "url" in ioc_type.lower() else \
                           "ipv4" if "ip:" in ioc_type.lower() else \
                           "hash_md5" if "md5" in ioc_type.lower() else \
                           "hash_sha256" if "sha256" in ioc_type.lower() else ioc_type
                det_id = await insert_detection(db, "threatfox", det_type, ioc_val,
                    sev, sla, raw, confidence=confidence/100)
                if det_id: stats["new"] += 1
                else: stats["skipped"] += 1
            await insert_collector_run(db, "threatfox", "completed", stats, started, datetime.utcnow())
            await db.commit()
        log.info(f"ThreatFox: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"ThreatFox failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "threatfox", "failed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    return stats

async def collect_malwarebazaar():
    """MalwareBazaar - real malware sample hashes from abuse.ch."""
    url = "https://mb-api.abuse.ch/api/v1/"
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            resp = await c.post(url, data={"query": "get_recent", "selector": "time"})
            resp.raise_for_status()
            data = resp.json()
        samples = data.get("data", [])
        if not isinstance(samples, list): samples = []
        stats["total"] = len(samples)
        async with AsyncSessionLocal() as db:
            for s in samples[:200]:
                sha = s.get("sha256_hash", "")
                if not sha: continue
                sig = s.get("signature", "unknown")
                ftype = s.get("file_type", "")
                tags = ", ".join(s.get("tags", []) or [])
                raw = f"MalwareBazaar: {sig} ({ftype}) tags:[{tags}]"
                sev = "HIGH" if sig and sig != "null" else "MEDIUM"
                det_id = await insert_detection(db, "malwarebazaar", "hash_sha256", sha,
                    sev, 12 if sev=="HIGH" else 72, raw, confidence=0.8)
                if det_id: stats["new"] += 1
                else: stats["skipped"] += 1
            await insert_collector_run(db, "malwarebazaar", "completed", stats, started, datetime.utcnow())
            await db.commit()
        log.info(f"MalwareBazaar: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"MalwareBazaar failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "malwarebazaar", "failed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    return stats

async def collect_openphish():
    """OpenPhish - real phishing URL feed."""
    url = "https://openphish.com/feed.txt"
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            resp = await c.get(url)
            resp.raise_for_status()
        lines = [l.strip() for l in resp.text.strip().split("\n") if l.strip().startswith("http")]
        stats["total"] = len(lines)
        async with AsyncSessionLocal() as db:
            for u in lines[:200]:
                raw = f"OpenPhish: Active phishing URL"
                det_id = await insert_detection(db, "openphish", "url", u,
                    "HIGH", 12, raw, confidence=0.85)
                if det_id: stats["new"] += 1
                else: stats["skipped"] += 1
            await insert_collector_run(db, "openphish", "completed", stats, started, datetime.utcnow())
            await db.commit()
        log.info(f"OpenPhish: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"OpenPhish failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "openphish", "failed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    return stats

async def collect_abuse_feodo_txt():
    """AbuseIPDB Feodo blocklist (text format) - real botnet IPs."""
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            resp = await c.get(url)
            resp.raise_for_status()
        lines = [l.strip() for l in resp.text.split("\n") if l.strip() and not l.startswith("#")]
        stats["total"] = len(lines)
        async with AsyncSessionLocal() as db:
            for ip in lines[:300]:
                raw = f"Abuse.ch Feodo blocklist: suspected botnet C2 IP"
                det_id = await insert_detection(db, "abuse_ch", "ipv4", ip,
                    "HIGH", 12, raw, confidence=0.85)
                if det_id: stats["new"] += 1
                else: stats["skipped"] += 1
            await insert_collector_run(db, "abuse", "completed", stats, started, datetime.utcnow())
            await db.commit()
        log.info(f"Abuse blocklist: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"Abuse blocklist failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "abuse", "failed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    return stats

async def collect_nvd():
    """NVD - real CVE data from NIST with CVSS metadata + CPE product map + EPSS scores."""
    # V16.4.5: Filter for recent CVEs (last 7 days) instead of random 50 from all time
    from datetime import timedelta
    end = datetime.utcnow()
    start = end - timedelta(days=7)
    date_filter = f"&pubStartDate={start.strftime('%Y-%m-%dT00:00:00.000')}&pubEndDate={end.strftime('%Y-%m-%dT23:59:59.999')}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50{date_filter}"
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0, "cpe_products": 0, "epss_enriched": 0}
    new_cve_ids = []
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            data = resp.json()
        vulns = data.get("vulnerabilities", [])
        stats["total"] = len(vulns)
        async with AsyncSessionLocal() as db:
            for v in vulns:
                cve_data = v.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id: continue
                desc_list = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")[:500]
                # Get CVSS score
                metrics = cve_data.get("metrics", {})
                cvss31 = metrics.get("cvssMetricV31", [{}])
                score = cvss31[0].get("cvssData", {}).get("baseScore", 0) if cvss31 else 0
                severity_str = cvss31[0].get("cvssData", {}).get("baseSeverity", "HIGH") if cvss31 else "HIGH"
                sev = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
                sla = 4 if sev == "CRITICAL" else 12 if sev == "HIGH" else 72
                raw = f"NVD: {cve_id} (CVSS {score}) - {desc[:200]}"
                # Store CVSS in metadata for exposure scorer
                meta = {"cvss_score": score, "cvss_severity": severity_str, "published": cve_data.get("published", "")}
                det_id = await insert_detection(db, "nvd", "cve_id", cve_id,
                    sev, sla, raw, confidence=0.9, metadata=meta)
                if det_id:
                    stats["new"] += 1
                    new_cve_ids.append(cve_id)
                else:
                    stats["skipped"] += 1

                # ── Populate cve_product_map from CPE data ──
                configurations = cve_data.get("configurations", [])
                seen_products = set()
                for config in configurations:
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            cpe_uri = match.get("criteria", "")
                            if not cpe_uri or not match.get("vulnerable", False):
                                continue
                            parts = cpe_uri.split(":")
                            if len(parts) < 5: continue
                            vendor = parts[3].replace("_", " ").title()
                            product = parts[4].replace("_", " ").title()
                            if product in ("*", "-"): continue
                            key = f"{vendor}:{product}"
                            if key in seen_products: continue
                            seen_products.add(key)
                            # Extract version range
                            ve = match.get("versionEndExcluding", "")
                            vei = match.get("versionEndIncluding", "")
                            vr = f"< {ve}" if ve else f"<= {vei}" if vei else ""
                            try:
                                check = await db.execute(text(
                                    "SELECT id FROM cve_product_map WHERE cve_id=:c AND product_name=:p LIMIT 1"
                                ), {"c": cve_id, "p": product})
                                if not check.scalar():
                                    await db.execute(text("""
                                        INSERT INTO cve_product_map (cve_id, product_name, vendor, version_range, cvss_score, severity, actively_exploited, source, created_at)
                                        VALUES (:cve_id, :product, :vendor, :vr, :cvss, :sev, false, 'nvd', NOW())
                                    """), {"cve_id": cve_id, "product": product, "vendor": vendor,
                                           "vr": vr, "cvss": score, "sev": severity_str})
                                    stats["cpe_products"] += 1
                            except Exception as cpe_err:
                                log.debug(f"CPE insert skip: {cpe_err}")

            await insert_collector_run(db, "nvd", "completed", stats, started, datetime.utcnow())
            await db.commit()

        # ── EPSS enrichment for new CVEs ──
        if new_cve_ids:
            try:
                epss_enriched = await _enrich_epss_batch(new_cve_ids)
                stats["epss_enriched"] = epss_enriched
            except Exception as e:
                log.warning(f"EPSS enrichment failed: {e}")

            # ── EPSS HARD RULE: Re-score after EPSS arrives ──
            # severity_scorer runs at INSERT time BEFORE EPSS exists.
            # This step catches any CVE where EPSS > 0.7 but severity was set
            # to MEDIUM or LOW based on CVSS alone. Triple-Lock Rule.
            try:
                async with AsyncSessionLocal() as db:
                    # EPSS > 0.9 → must be CRITICAL
                    upgraded_crit = await db.execute(text("""
                        UPDATE detections SET severity = 'CRITICAL', sla_hours = 12,
                            raw_text = raw_text || ' [EPSS>90% → CRITICAL by Triple-Lock]'
                        WHERE source = 'nvd' AND ioc_type = 'cve_id'
                        AND severity NOT IN ('CRITICAL')
                        AND (metadata->>'epss_score')::float > 0.9
                    """))
                    # EPSS > 0.7 → must be at least HIGH
                    upgraded_high = await db.execute(text("""
                        UPDATE detections SET severity = 'HIGH', sla_hours = LEAST(sla_hours, 24),
                            raw_text = raw_text || ' [EPSS>70% → HIGH by Triple-Lock]'
                        WHERE source = 'nvd' AND ioc_type = 'cve_id'
                        AND severity IN ('MEDIUM', 'LOW', 'INFO')
                        AND (metadata->>'epss_score')::float > 0.7
                        AND (metadata->>'epss_score')::float <= 0.9
                    """))
                    await db.commit()
                    crit_count = upgraded_crit.rowcount or 0
                    high_count = upgraded_high.rowcount or 0
                    if crit_count or high_count:
                        stats["epss_upgrades"] = {"to_critical": crit_count, "to_high": high_count}
                        log.info(f"NVD EPSS Triple-Lock: {crit_count} → CRITICAL, {high_count} → HIGH")
            except Exception as e:
                log.debug(f"EPSS re-score failed: {e}")

        log.info(f"NVD: {stats['new']} new / {stats['total']} total, {stats['cpe_products']} CPE products, {stats['epss_enriched']} EPSS")
    except Exception as e:
        log.error(f"NVD failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "nvd", "failed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    return stats


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
            async with httpx.AsyncClient(timeout=15.0) as c:
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

async def collect_mitre():
    """MITRE ATT&CK - real threat actor data from MITRE GitHub."""
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=60.0) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            data = resp.json()
        objects = data.get("objects", [])
        groups = [o for o in objects if o.get("type") == "intrusion-set" and not o.get("revoked")]
        stats["total"] = len(groups)
        async with AsyncSessionLocal() as db:
            for g in groups:
                name = g.get("name", "")
                if not name: continue
                mitre_id = ""
                for ref in g.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        mitre_id = ref.get("external_id", "")
                        break
                aliases = g.get("aliases", [])[1:] if len(g.get("aliases", [])) > 1 else []
                desc = (g.get("description", "") or "")[:1000]
                # Extract origin from description heuristics
                origin = ""
                for country in ["China", "Russia", "Iran", "North Korea", "Palestine", "Vietnam", "India", "Pakistan"]:
                    if country.lower() in desc.lower():
                        origin = country
                        break
                motivation = ""
                if any(w in desc.lower() for w in ["espionage", "intelligence", "surveillance"]):
                    motivation = "Espionage"
                elif any(w in desc.lower() for w in ["financial", "ransom", "profit", "money"]):
                    motivation = "Financial"
                elif any(w in desc.lower() for w in ["destruct", "disrupt", "sabotage"]):
                    motivation = "Destruction"
                actor_id = await insert_actor(db, name, mitre_id=mitre_id, aliases=aliases,
                    origin=origin, motivation=motivation, description=desc,
                    active_since=g.get("first_seen", ""),
                    sectors=[], techniques=[], countries=[])
                if actor_id: stats["new"] += 1
                else: stats["skipped"] += 1
            await insert_collector_run(db, "mitre", "completed", stats, started, datetime.utcnow())
            await db.commit()
        log.info(f"MITRE: {stats['new']} new actors / {stats['total']} total groups")
    except Exception as e:
        log.error(f"MITRE failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "mitre", "failed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    return stats

async def collect_ransomfeed():
    """RansomFeed - real ransomware victim posts."""
    url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            posts = resp.json()
        if not isinstance(posts, list): posts = []
        stats["total"] = len(posts)
        async with AsyncSessionLocal() as db:
            for p in posts[-100:]:  # Latest 100
                title = p.get("post_title", "")
                group = p.get("group_name", "unknown")
                discovered = p.get("discovered", "")
                if not title: continue
                await insert_darkweb(db, "ransomfeed", "ransomware_leak",
                    f"{group}: {title[:200]}", actor=group, severity="CRITICAL",
                    metadata={"group": group, "discovered": discovered,
                              "exfiltration_confirmed": bool(re.search(
                                  r'(?:\d+\s*(?:GB|TB|MB|files?|records?))|(?:exfiltrat|stolen|leaked?\s+data|data\s+(?:dump|leak|breach))',
                                  title, re.IGNORECASE))})
                stats["new"] += 1
            await insert_collector_run(db, "ransomfeed", "completed", stats, started, datetime.utcnow())
            await db.commit()
        log.info(f"RansomFeed: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"RansomFeed failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "ransomfeed", "failed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    return stats

async def collect_rss():
    """RSS Feeds - real security news from Krebs, CISA, Threatpost, BleepingComputer."""
    import xml.etree.ElementTree as ET
    feeds = [
        ("krebs", "https://krebsonsecurity.com/feed/"),
        ("cisa_alerts", "https://www.cisa.gov/uscert/ncas/alerts.xml"),
        ("bleeping", "https://www.bleepingcomputer.com/feed/"),
    ]
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    async with AsyncSessionLocal() as db:
        for feed_name, url in feeds:
            try:
                async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
                    resp = await c.get(url)
                    resp.raise_for_status()
                root = ET.fromstring(resp.text)
                items = root.findall(".//item")[:20]
                stats["total"] += len(items)
                for item in items:
                    title = (item.findtext("title") or "")[:500]
                    link = item.findtext("link") or ""
                    desc = (item.findtext("description") or "")[:500]
                    if not title: continue
                    # Extract IOCs from title/description
                    ioc_val = f"rss:{feed_name}:{hashlib.md5(title.encode()).hexdigest()[:16]}"
                    raw = f"RSS [{feed_name}]: {title}"
                    det_id = await insert_detection(db, "rss", "advisory", ioc_val,
                        "MEDIUM", 72, raw, confidence=0.5)
                    if det_id: stats["new"] += 1
                    else: stats["skipped"] += 1
            except Exception as e:
                log.warning(f"RSS {feed_name} failed: {e}")
        await insert_collector_run(db, "rss", "completed", stats, started, datetime.utcnow())
        await db.commit()
    log.info(f"RSS: {stats['new']} new / {stats['total']} total")
    return stats

async def collect_paste():
    """Paste sites - download paste content, scan with pattern_matcher, store individual IOCs.
    
    BEFORE: Stored paste URLs only ("paste_url" type, 50-char raw_text).
            pattern_matcher never ran. No IOCs extracted. S6 couldn't find siblings.
    
    AFTER:  Downloads paste content via scrape API, runs pattern_matcher on full text,
            stores EACH IOC as separate detection with:
            - Specific ioc_type (aws_access_key, email_password_combo, etc)
            - paste_key in metadata (for S6 Phase B context matching)
            - raw_text = surrounding context (up to 500 chars around the IOC)
    """
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0, "pastes_scanned": 0, "iocs_found": 0}

    # Import pattern_matcher for IOC extraction
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
    try:
        from arguswatch.engine.pattern_matcher import scan_text as pm_scan
        from arguswatch.engine.severity_scorer import score as sev_score
    except ImportError:
        # Fallback: pattern_matcher not available in intel-proxy container
        pm_scan = None
        sev_score = None

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            # Step 1: Get recent paste list
            resp = await c.get("https://scrape.pastebin.com/api_scraping.php?limit=50")
            if resp.status_code != 200:
                log.warning(f"Paste scraping API returned {resp.status_code}")
                return stats
            
            pastes = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else []
            stats["total"] = len(pastes)

            async with AsyncSessionLocal() as db:
                for p in pastes[:30]:  # Limit to 30 to avoid rate limiting
                    key = p.get("key", "")
                    title = p.get("title", "untitled")
                    paste_url = f"https://pastebin.com/{key}"
                    scrape_url = p.get("scrape_url", f"https://scrape.pastebin.com/api_scrape_item.php?i={key}")
                    
                    if not key:
                        continue

                    # Step 2: Download paste content
                    try:
                        content_resp = await c.get(scrape_url)
                        if content_resp.status_code != 200:
                            # Store URL only as fallback
                            det_id = await insert_detection(db, "paste", "paste_url",
                                paste_url, "LOW", 168,
                                f"Paste: {title} (key:{key}) - content unavailable",
                                confidence=0.3, metadata={"paste_key": key, "title": title})
                            if det_id: stats["new"] += 1
                            continue
                        
                        paste_content = content_resp.text[:10000]  # Cap at 10KB
                        stats["pastes_scanned"] += 1
                    except Exception as e:
                        log.debug(f"Paste content download failed for {key}: {e}")
                        continue

                    # Step 3: Run pattern_matcher on paste content
                    if pm_scan and len(paste_content) > 20:
                        try:
                            matches = pm_scan(paste_content)
                        except Exception:
                            matches = []
                        
                        if matches:
                            stats["iocs_found"] += len(matches)
                            
                            for m in matches[:50]:  # Cap IOCs per paste
                                # Build context: ±250 chars around the IOC
                                ioc_pos = paste_content.find(m.value)
                                if ioc_pos >= 0:
                                    ctx_start = max(0, ioc_pos - 250)
                                    ctx_end = min(len(paste_content), ioc_pos + len(m.value) + 250)
                                    context_text = paste_content[ctx_start:ctx_end]
                                else:
                                    context_text = paste_content[:500]
                                
                                # Get severity from severity_scorer
                                if sev_score:
                                    try:
                                        sev = sev_score(m.category, m.ioc_type, confidence=m.confidence)
                                        severity = sev.severity
                                        sla = sev.sla_hours
                                    except Exception:
                                        severity = "MEDIUM"
                                        sla = 48
                                else:
                                    severity = "MEDIUM"
                                    sla = 48
                                
                                raw = f"Paste [{title}] ({paste_url}): {context_text}"
                                det_id = await insert_detection(db, "paste", m.ioc_type,
                                    m.value, severity, sla, raw[:2000],
                                    confidence=m.confidence,
                                    metadata={
                                        "paste_key": key,
                                        "paste_url": paste_url,
                                        "title": title,
                                        "category": m.category,
                                        "line": m.line_number,
                                    })
                                if det_id:
                                    stats["new"] += 1
                        else:
                            # No IOCs found - still store paste URL for reference
                            det_id = await insert_detection(db, "paste", "paste_url",
                                paste_url, "LOW", 168,
                                f"Paste: {title} (key:{key}) - no IOCs detected",
                                confidence=0.2, metadata={"paste_key": key, "title": title})
                            if det_id: stats["new"] += 1
                    else:
                        # No pattern_matcher - store paste URL only
                        det_id = await insert_detection(db, "paste", "paste_url",
                            paste_url, "LOW", 168,
                            f"Paste: {title} (key:{key})",
                            confidence=0.3, metadata={"paste_key": key, "title": title})
                        if det_id: stats["new"] += 1

                    await asyncio.sleep(1)  # Rate limiting between paste downloads

                # NOTE: Rentry.co and ControlC.com were removed in v16.4
                # Rentry: /raw endpoint requires auth token from support@rentry.co, no public /recent page
                # ControlC: all pastes hidden from search engines by default, no public listing endpoint
                # Keep Pastebin as the sole paste source until a verified alternative is found

                await insert_collector_run(db, "paste", "completed", stats, started, datetime.utcnow())
                await db.commit()
    except Exception as e:
        log.warning(f"Paste failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "paste", "completed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    log.info(f"Paste: {stats['new']} new / {stats['total']} pastes / {stats['pastes_scanned']} scanned / {stats['iocs_found']} IOCs")
    return stats

async def collect_hudsonrock():
    """Hudson Rock - free OSINT stealer log search."""
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    # Need customer domains to search - get from DB
    try:
        async with AsyncSessionLocal() as db:
            r = await db.execute(text("SELECT DISTINCT asset_value FROM customer_assets WHERE asset_type='domain' LIMIT 10"))
            domains = [row[0] for row in r.fetchall()]
        if not domains:
            log.info("HudsonRock: no customer domains to search")
            async with AsyncSessionLocal() as db:
                await insert_collector_run(db, "hudsonrock", "completed", {"new":0,"note":"no domains"}, started, datetime.utcnow())
                await db.commit()
            return stats
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            for domain in domains[:5]:
                try:
                    resp = await c.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}")
                    if resp.status_code == 200:
                        data = resp.json()
                        stealers = data.get("stealers", [])
                        stats["total"] += len(stealers)
                        async with AsyncSessionLocal() as db:
                            for s in stealers[:20]:
                                email = s.get("email", "") or s.get("url", "")
                                if not email: continue
                                raw = f"HudsonRock: Stealer log for {domain} - {email}"
                                det_id = await insert_detection(db, "hudsonrock", "email", email,
                                    "HIGH", 12, raw, confidence=0.75)
                                if det_id: stats["new"] += 1
                                else: stats["skipped"] += 1
                            await db.commit()
                except Exception as e:
                    log.warning(f"HudsonRock {domain}: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "hudsonrock", "completed", stats, started, datetime.utcnow())
            await db.commit()
    except Exception as e:
        log.error(f"HudsonRock failed: {e}")
        stats["error"] = str(e)
    log.info(f"HudsonRock: {stats['new']} new / {stats['total']} total")
    return stats


# ════════════════════════════════════════════════════════════
# KEY-OPTIONAL COLLECTORS - degrade gracefully without keys
# ════════════════════════════════════════════════════════════

# Load all optional keys at module level
HIBP_KEY        = os.getenv("HIBP_API_KEY", "")
BREACH_DIR_KEY  = os.getenv("BREACHDIRECTORY_API_KEY", "") or os.getenv("BREACH_DIRECTORY_API_KEY", "")
SOCRADAR_KEY    = os.getenv("SOCRADAR_API_KEY", "")
GITHUB_TOKEN    = os.getenv("GITHUB_TOKEN", "")
PHISHTANK_KEY   = os.getenv("PHISHTANK_API_KEY", "")
SPYCLOUD_KEY    = os.getenv("SPYCLOUD_API_KEY", "")
SIXGILL_ID      = os.getenv("CYBERSIXGILL_CLIENT_ID", "")
SIXGILL_SECRET  = os.getenv("CYBERSIXGILL_SECRET", "")
RF_KEY          = os.getenv("RECORDED_FUTURE_KEY", "")
CYBERINT_KEY    = os.getenv("CYBERINT_API_KEY", "")
FLARE_KEY       = os.getenv("FLARE_API_KEY", "")
CS_CLIENT_ID    = os.getenv("CROWDSTRIKE_CLIENT_ID", "")
CS_SECRET       = os.getenv("CROWDSTRIKE_SECRET", "")


async def collect_otx():
    """AlienVault OTX - community threat pulses. Free key from otx.alienvault.com."""
    if not OTX_KEY:
        log.info("OTX: skipped (no OTX_API_KEY)")
        return {"skipped": True, "reason": "no OTX_API_KEY", "new": 0}
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
            resp = await c.get("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20&modified_since=2024-01-01",
                               headers={"X-OTX-API-KEY": OTX_KEY})
            resp.raise_for_status()
            pulses = resp.json().get("results", [])
            stats["total"] = len(pulses)
            async with AsyncSessionLocal() as db:
                for pulse in pulses[:20]:
                    name = pulse.get("name", "")
                    for indicator in pulse.get("indicators", [])[:50]:
                        ioc_val = indicator.get("indicator", "")
                        ioc_type = indicator.get("type", "").lower()
                        if not ioc_val: continue
                        # Map OTX types to our types
                        det_type = "ipv4" if "ipv4" in ioc_type else \
                                   "domain" if "domain" in ioc_type or "hostname" in ioc_type else \
                                   "url" if "url" in ioc_type else \
                                   "hash_md5" if "md5" in ioc_type else \
                                   "hash_sha256" if "sha256" in ioc_type else \
                                   "email" if "email" in ioc_type else ioc_type
                        raw = f"OTX Pulse: {name[:100]} - {ioc_type}: {ioc_val[:80]}"
                        det_id = await insert_detection(db, "otx", det_type, ioc_val,
                            "MEDIUM", 72, raw, confidence=0.6)
                        if det_id: stats["new"] += 1
                        else: stats["skipped"] += 1
                await insert_collector_run(db, "otx", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"OTX: {stats['new']} new / {stats['total']} pulses")
    except Exception as e:
        log.error(f"OTX failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_urlscan():
    """URLScan.io - recent phishing/malware scans. Free key (1000/day)."""
    if not URLSCAN_KEY:
        log.info("URLScan: skipped (no URLSCAN_API_KEY)")
        return {"skipped": True, "reason": "no URLSCAN_API_KEY", "new": 0}
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
            resp = await c.get("https://urlscan.io/api/v1/search/?q=task.tags:phishing%20AND%20page.status:200&size=50",
                               headers={"API-Key": URLSCAN_KEY})
            resp.raise_for_status()
            results = resp.json().get("results", [])
            stats["total"] = len(results)
            async with AsyncSessionLocal() as db:
                for r in results[:50]:
                    page = r.get("page", {})
                    url = page.get("url", "")
                    domain = page.get("domain", "")
                    if not url: continue
                    raw = f"URLScan phishing: {domain} - {url[:200]}"
                    det_id = await insert_detection(db, "urlscan", "url", url,
                        "HIGH", 24, raw, confidence=0.7)
                    if det_id: stats["new"] += 1
                    else: stats["skipped"] += 1
                await insert_collector_run(db, "urlscan", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"URLScan: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"URLScan failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_phishtank_urlhaus():
    """PhishTank verified phishing URLs + URLhaus malicious URLs. Both FREE, no key."""
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0, "phishtank": 0, "urlhaus": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            # URLhaus - always free
            try:
                resp = await c.get("https://urlhaus.abuse.ch/downloads/text_online/")
                if resp.status_code == 200:
                    lines = [l.strip() for l in resp.text.split("\n") 
                             if l.strip().startswith("http") and not l.startswith("#")]
                    stats["total"] += len(lines)
                    async with AsyncSessionLocal() as db:
                        for url in lines[:200]:
                            det_id = await insert_detection(db, "urlhaus", "url", url,
                                "HIGH", 24, f"URLhaus malicious: {url[:200]}", confidence=0.85)
                            if det_id:
                                stats["new"] += 1
                                stats["urlhaus"] += 1
                            else: stats["skipped"] += 1
                        await db.commit()
            except Exception as e:
                log.warning(f"URLhaus part failed: {e}")

            # PhishTank - free, optional key for higher rate
            try:
                pt_url = "http://data.phishtank.com/data/online-valid.csv"
                if PHISHTANK_KEY:
                    pt_url = f"http://data.phishtank.com/data/{PHISHTANK_KEY}/online-valid.csv"
                resp = await c.get(pt_url, timeout=30.0)
                if resp.status_code == 200:
                    lines = resp.text.strip().split("\n")[1:]  # skip header
                    stats["total"] += len(lines)
                    async with AsyncSessionLocal() as db:
                        for line in lines[:200]:
                            parts = line.split(",")
                            if len(parts) < 2: continue
                            url = parts[1].strip().strip('"')
                            if not url.startswith("http"): continue
                            det_id = await insert_detection(db, "phishtank", "url", url,
                                "HIGH", 24, f"PhishTank verified: {url[:200]}", confidence=0.9)
                            if det_id:
                                stats["new"] += 1
                                stats["phishtank"] += 1
                            else: stats["skipped"] += 1
                        await db.commit()
            except Exception as e:
                log.warning(f"PhishTank part failed: {e}")

        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "phishtank_urlhaus", "completed", stats, started, datetime.utcnow())
            await db.commit()
        log.info(f"PhishTank+URLhaus: {stats['new']} new (PT:{stats['phishtank']}, UH:{stats['urlhaus']})")
    except Exception as e:
        log.error(f"PhishTank+URLhaus failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_shodan_customer():
    """Shodan - exposed services on customer IPs/domains. Requires key."""
    if not SHODAN_KEY:
        log.info("Shodan: skipped (no SHODAN_API_KEY)")
        return {"skipped": True, "reason": "no SHODAN_API_KEY", "new": 0}
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0}
    try:
        # Query Shodan for recently seen vulnerable hosts
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
            resp = await c.get(f"https://api.shodan.io/shodan/host/search?key={SHODAN_KEY}&query=vuln:*&facets=port")
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                stats["total"] = len(matches)
                async with AsyncSessionLocal() as db:
                    for match in matches[:100]:
                        ip = match.get("ip_str", "")
                        if not ip: continue
                        vulns = match.get("vulns", {})
                        ports = match.get("port", "")
                        org = match.get("org", "")
                        raw = f"Shodan: {ip}:{ports} org:{org} vulns:{list(vulns.keys())[:5]}"
                        det_id = await insert_detection(db, "shodan", "ipv4", ip,
                            "MEDIUM", 72, raw, confidence=0.7,
                            metadata={"ports": [ports], "org": org, "vulns": list(vulns.keys())[:10]})
                        if det_id: stats["new"] += 1
                    await insert_collector_run(db, "shodan", "completed", stats, started, datetime.utcnow())
                    await db.commit()
        log.info(f"Shodan: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"Shodan failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_censys():
    """Censys - exposed services via Censys Search 2.0. Requires CENSYS_API_ID + CENSYS_API_SECRET."""
    if not CENSYS_ID or not CENSYS_SECRET:
        log.info("Censys: skipped (no CENSYS_API_ID/SECRET)")
        return {"skipped": True, "reason": "no CENSYS_API_ID", "new": 0}
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0}
    try:
        import base64
        auth_token = base64.b64encode(f"{CENSYS_ID}:{CENSYS_SECRET}".encode()).decode()
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
            async with AsyncSessionLocal() as db:
                # Get customer domains/IPs to search
                try:
                    r = await db.execute(text(
                        "SELECT DISTINCT asset_value, asset_type FROM customer_assets "
                        "WHERE asset_type IN ('domain','ip') AND customer_id IS NOT NULL LIMIT 15"
                    ))
                    assets = r.all()
                except Exception:
                    assets = []
                for asset_value, asset_type in assets:
                    query = asset_value if asset_type == "ip" else f"services.tls.certificates.leaf.names: {asset_value}"
                    try:
                        resp = await c.get("https://search.censys.io/api/v2/hosts/search",
                            params={"q": query, "per_page": 25},
                            headers={"Authorization": f"Basic {auth_token}", "Accept": "application/json"})
                        if resp.status_code == 200:
                            hits = resp.json().get("result", {}).get("hits", [])
                            stats["total"] += len(hits)
                            for hit in hits[:25]:
                                ip = hit.get("ip", "")
                                if not ip: continue
                                services = hit.get("services", [])
                                ports = [str(s.get("port", "")) for s in services[:10]]
                                raw = f"Censys: {ip} ports:{','.join(ports)} for {asset_value}"
                                det_id = await insert_detection(db, "censys", "ipv4", ip,
                                    "MEDIUM", 72, raw, confidence=0.7,
                                    metadata={"ports": ports, "query": asset_value,
                                              "autonomous_system": hit.get("autonomous_system", {}).get("name", "")})
                                if det_id: stats["new"] += 1
                        await asyncio.sleep(0.5)
                    except Exception as e:
                        log.debug(f"Censys {asset_value}: {e}")
                await insert_collector_run(db, "censys", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"Censys: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"Censys failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_intelx():
    """IntelX - dark web + paste + leak search. Requires INTELX_API_KEY (free tier)."""
    if not INTELX_KEY:
        log.info("IntelX: skipped (no INTELX_API_KEY)")
        return {"skipped": True, "reason": "no INTELX_API_KEY", "new": 0}
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
            async with AsyncSessionLocal() as db:
                # Get customer domains
                try:
                    r = await db.execute(text(
                        "SELECT DISTINCT asset_value FROM customer_assets WHERE asset_type='domain' LIMIT 10"
                    ))
                    domains = [row[0] for row in r.all()]
                except Exception:
                    domains = []
                for domain in domains:
                    try:
                        # IntelX phonebook search (free tier: limited results)
                        resp = await c.post("https://2.intelx.io/phonebook/search",
                            json={"term": domain, "maxresults": 20, "media": 0,
                                  "target": 1},  # VERIFY LIVE: target 1 is reportedly emails, 2=domains, 3=urls per IntelX docs
                            params={"k": INTELX_KEY},
                            headers={"Content-Type": "application/json"})
                        if resp.status_code == 200:
                            search_id = resp.json().get("id", "")
                            if search_id:
                                await asyncio.sleep(2)  # Wait for search to process
                                r2 = await c.get(f"https://2.intelx.io/phonebook/search/result",
                                    params={"id": search_id, "limit": 20, "k": INTELX_KEY})
                                if r2.status_code == 200:
                                    selectors = r2.json().get("selectors", [])
                                    stats["total"] += len(selectors)
                                    for sel in selectors[:20]:
                                        val = sel.get("selectorvalue", "")
                                        stype = sel.get("selectortypeh", "")
                                        if not val: continue
                                        ioc_type = "email_address" if "@" in val else "domain" if "." in val else "dark_web_mention"
                                        det_id = await insert_detection(db, "intelx", ioc_type, val,
                                            "HIGH" if "@" in val else "MEDIUM", 48,
                                            f"IntelX phonebook: {val} ({stype}) linked to {domain}",
                                            confidence=0.75,
                                            metadata={"search_domain": domain, "selector_type": stype})
                                        if det_id: stats["new"] += 1
                        await asyncio.sleep(1)
                    except Exception as e:
                        log.debug(f"IntelX {domain}: {e}")
                await insert_collector_run(db, "intelx", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"IntelX: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"IntelX failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_darksearch():
    """Ahmia.fi - clearnet Tor search index. FREE, no key needed.
    Customer-aware: searches for customer domains on dark web."""
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0}
    import re
    search_terms = ["ransomware leak 2026", "credential dump 2026", "stealer logs dump", "database leak sale"]
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            async with AsyncSessionLocal() as db:
                # Add customer-specific searches
                try:
                    r = await db.execute(text(
                        "SELECT DISTINCT ca.asset_value FROM customer_assets ca WHERE ca.asset_type = 'domain' LIMIT 5"))
                    for row in r.all():
                        search_terms.append(f'"{row[0]}" leak')
                except Exception:
                    pass

                for term in search_terms[:8]:
                    try:
                        resp = await c.get("https://ahmia.fi/search/",
                            params={"q": term},
                            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                                     "Accept": "text/html"},
                            timeout=20.0)
                        if resp.status_code != 200: continue
                        onion_urls = re.findall(r'(https?://[a-z2-7]{16,56}\.onion[^\s"<]*)', resp.text)
                        # Also extract result titles for context
                        titles = re.findall(r'<h4>\s*<a[^>]*>(.*?)</a>', resp.text)
                        stats["total"] += len(onion_urls)
                        for i, url in enumerate(onion_urls[:15]):
                            title = titles[i] if i < len(titles) else term
                            title = re.sub(r'<[^>]+>', '', title).strip()[:200]
                            raw = f"Dark web mention ({term}): {title} - {url[:200]}"
                            await insert_darkweb(db, "ahmia", "dark_web_url",
                                f"{title}: {url[:100]}", severity="MEDIUM", url=url,
                                metadata={"search_term": term, "title": title})
                            stats["new"] += 1
                        await asyncio.sleep(3)  # Ahmia rate limits aggressively
                    except Exception as e:
                        log.debug(f"Ahmia search '{term}' failed: {e}")
                        continue
                await insert_collector_run(db, "darksearch", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"DarkSearch/Ahmia: {stats['new']} new / {stats['total']} found")
    except Exception as e:
        log.error(f"DarkSearch failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_circl_misp():
    """CIRCL MISP OSINT feed - Luxembourg CERT. FREE, no key needed."""
    started = datetime.utcnow()
    stats = {"new": 0, "skipped": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            # Fetch manifest to get recent events
            resp = await c.get("https://www.circl.lu/doc/misp/feed-osint/manifest.json")
            if resp.status_code != 200:
                return {"error": f"CIRCL manifest returned {resp.status_code}", "new": 0}
            manifest = resp.json()
            # Get most recent 10 events
            recent_ids = sorted(manifest.keys(), reverse=True)[:10]
            stats["total"] = len(recent_ids)
            async with AsyncSessionLocal() as db:
                for event_id in recent_ids:
                    try:
                        resp = await c.get(f"https://www.circl.lu/doc/misp/feed-osint/{event_id}.json")
                        if resp.status_code != 200: continue
                        event = resp.json().get("Event", {})
                        event_info = event.get("info", "")[:200]
                        for attr in event.get("Attribute", [])[:30]:
                            val = attr.get("value", "")
                            atype = attr.get("type", "").lower()
                            if not val: continue
                            # Map MISP types
                            det_type = "ipv4" if "ip-" in atype else \
                                       "domain" if "domain" in atype or "hostname" in atype else \
                                       "url" if "url" in atype or "link" in atype else \
                                       "hash_md5" if "md5" in atype else \
                                       "hash_sha256" if "sha256" in atype else \
                                       "email" if "email" in atype else None
                            if not det_type: continue
                            raw = f"CIRCL MISP: {event_info} - {atype}: {val[:80]}"
                            det_id = await insert_detection(db, "circl_misp", det_type, val,
                                "MEDIUM", 72, raw, confidence=0.65)
                            if det_id: stats["new"] += 1
                            else: stats["skipped"] += 1
                    except Exception as e:
                        log.debug(f"CIRCL event {event_id}: {e}")
                await insert_collector_run(db, "circl_misp", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"CIRCL MISP: {stats['new']} new / {stats['total']} events")
    except Exception as e:
        log.error(f"CIRCL MISP failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_pulsedive():
    """Pulsedive - community threat enrichment with risk scores. Free tier (key optional).
    Customer-aware: queries each customer domain for related malicious indicators.
    Results inserted with customer_id for immediate actionability.
    """
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "customers_queried": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            async with AsyncSessionLocal() as db:
                # Get customer domains
                try:
                    r = await db.execute(text("""
                        SELECT DISTINCT ca.asset_value, ca.customer_id, c.name
                        FROM customer_assets ca JOIN customers c ON c.id = ca.customer_id
                        WHERE ca.asset_type = 'domain' LIMIT 10
                    """))
                    customer_domains = r.all()
                except Exception:
                    customer_domains = []

                # Fallback: use generic threat queries if no customers yet
                if not customer_domains:
                    log.info("Pulsedive: no customers, running generic threat feed")
                    generic_indicators = ["ransomware", "phishing", "malware"]
                    for term in generic_indicators:
                        try:
                            resp = await c.get("https://pulsedive.com/api/explore.php",
                                params={"q": f'threat="{term}"', "limit": 10, "pretty": 1},
                                timeout=15.0, headers={"User-Agent": "ArgusWatch/16.4"})
                            if resp.status_code != 200: continue
                            data = resp.json()
                            for result in (data.get("results", []) or [])[:10]:
                                indicator = result.get("indicator", "")
                                risk = (result.get("risk") or "none").lower()
                                if not indicator or risk in ("none", "unknown", ""): continue
                                sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
                                sla_map = {"critical": 4, "high": 12, "medium": 24, "low": 72}
                                ind_type = result.get("type", "").lower()
                                ioc_type = "ipv4" if ind_type == "ip" else "domain" if ind_type == "domain" else "url" if ind_type == "url" else "indicator"
                                raw = f"Pulsedive [{risk}]: {indicator} (generic threat: {term})"
                                det_id = await insert_detection(db, "pulsedive", ioc_type,
                                    indicator, sev_map.get(risk, "MEDIUM"), sla_map.get(risk, 24), raw,
                                    confidence=0.6, metadata={"risk": risk, "threat_query": term})
                                if det_id: stats["new"] += 1
                                stats["total"] += 1
                            await asyncio.sleep(2)
                        except Exception as e:
                            log.debug(f"Pulsedive generic '{term}': {e}")
                    await insert_collector_run(db, "pulsedive", "completed", stats, started, datetime.utcnow())
                    await db.commit()
                    return stats

                for domain, cust_id, cust_name in customer_domains[:3]:  # Max 3 - free tier is 30 req/day
                    stats["customers_queried"] += 1
                    # Pulsedive explore API: find indicators related to this domain
                    params = {
                        "q": f'indicator="{domain}"',
                        "limit": 10,
                        "pretty": 1,
                    }
                    if PULSEDIVE_KEY:
                        params["key"] = PULSEDIVE_KEY

                    try:
                        resp = await c.get("https://pulsedive.com/api/explore.php",
                            params=params, timeout=15.0,
                            headers={"User-Agent": "ArgusWatch/16.0"})
                        if resp.status_code == 429:
                            log.warning(f"Pulsedive rate limited after {stats['customers_queried']} queries. Stopping.")
                            break
                        if resp.status_code != 200:
                            await asyncio.sleep(15)
                            continue

                        data = resp.json()
                        results = data.get("results", []) or []
                        stats["total"] += len(results)

                        for result in results[:15]:
                            risk = (result.get("risk") or "none").lower()
                            if risk in ("none", "unknown", ""):
                                continue
                            indicator = result.get("indicator", "") or result.get("ioc", "")
                            if not indicator:
                                continue

                            # Map risk to severity and SLA
                            sev_map = {"critical": "CRITICAL", "high": "HIGH",
                                       "medium": "MEDIUM", "low": "LOW"}
                            sla_map = {"critical": 4, "high": 12, "medium": 24, "low": 72}
                            severity = sev_map.get(risk, "MEDIUM")
                            sla = sla_map.get(risk, 24)

                            # Determine IOC type
                            ind_type = result.get("type", "").lower()
                            ioc_type = "ipv4" if ind_type == "ip" else \
                                       "domain" if ind_type == "domain" else \
                                       "url" if ind_type == "url" else "indicator"

                            raw = f"Pulsedive [{risk}]: {indicator} linked to {domain} ({cust_name})"
                            det_id = await insert_detection(db, "pulsedive", ioc_type,
                                indicator, severity, sla, raw,
                                confidence=0.72,
                                customer_id=cust_id,
                                metadata={"indicator": indicator, "risk": risk,
                                          "domain_queried": domain,
                                          "threats": (result.get("threats") or [])[:3],
                                          "feeds": (result.get("feeds") or [])[:3]})
                            if det_id:
                                stats["new"] += 1

                        await asyncio.sleep(15)  # 15s between queries - free tier is 30 req/day
                    except Exception as e:
                        log.debug(f"Pulsedive {domain}: {e}")

                await insert_collector_run(db, "pulsedive", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"Pulsedive: {stats['new']} new / {stats['total']} results / {stats['customers_queried']} customers queried")
    except Exception as e:
        log.error(f"Pulsedive failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_vxunderground():
    """VX-Underground - malware intelligence via Malpedia (FREE, no key).
    NOTE: vx-underground.org RSS + MalwareBazaar API both require auth now. Using Malpedia."""
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            # Source 1: Malpedia malware families (comprehensive free database)
            try:
                resp = await c.get("https://malpedia.caad.fkie.fraunhofer.de/api/list/families",
                    headers={"User-Agent": "ArgusWatch/16.4"}, timeout=20.0)
                if resp.status_code == 200:
                    families = resp.json()
                    stats["total"] += len(families) if isinstance(families, (list, dict)) else 0
                    items = list(families.items())[:50] if isinstance(families, dict) else families[:50]
                    async with AsyncSessionLocal() as db:
                        for item in items:
                            if isinstance(item, tuple):
                                family_id, family_data = item
                                name = family_id
                                desc = family_data.get("description", "")[:200] if isinstance(family_data, dict) else str(family_data)[:200]
                            else:
                                name = str(item)[:100]
                                desc = ""
                            raw = f"Malpedia malware family: {name}. {desc}"
                            det_id = await insert_detection(db, "vxunderground", "malware_hash",
                                name, "MEDIUM", 72, raw, confidence=0.7,
                                metadata={"family": name, "source": "malpedia"})
                            if det_id: stats["new"] += 1
                        await db.commit()
            except Exception as e:
                log.debug(f"VX-UG/Malpedia families: {e}")

            # Source 2: Malpedia threat actors
            try:
                resp = await c.get("https://malpedia.caad.fkie.fraunhofer.de/api/list/actors",
                    headers={"User-Agent": "ArgusWatch/16.4"}, timeout=20.0)
                if resp.status_code == 200:
                    actors = resp.json()
                    async with AsyncSessionLocal() as db:
                        actor_items = list(actors.items())[:30] if isinstance(actors, dict) else actors[:30]
                        for item in actor_items:
                            if isinstance(item, tuple):
                                actor_id, actor_data = item
                            else:
                                actor_id = str(item)
                                actor_data = {}
                            raw = f"Malpedia actor: {actor_id}"
                            det_id = await insert_detection(db, "vxunderground", "apt_group",
                                actor_id, "MEDIUM", 24, raw, confidence=0.8,
                                metadata={"actor": actor_id, "source": "malpedia_actors"})
                            if det_id: stats["new"] += 1
                            stats["total"] += 1
                        await db.commit()
            except Exception as e:
                log.debug(f"VX-UG/Malpedia actors: {e}")

            async with AsyncSessionLocal() as db:
                await insert_collector_run(db, "vxunderground", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"VX-Underground/Malpedia: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"VX-Underground failed: {e}")
        stats["error"] = str(e)
    return stats


RANSOMWARE_GROUPS = [
    "lockbit", "alphv", "blackcat", "clop", "akira", "play", "black basta",
    "ransomhouse", "revil", "conti", "darkside", "hive", "rhysida",
    "medusa", "bianlian", "hunters international", "8base", "qilin",
    "meow", "dragonforce", "noname057", "killnet",
]


async def collect_ransomwatch():
    """Ransomwatch - free open-source ransomware claim tracker. NO key needed.
    JSON API: ransomwhat.telemetry.ltd/posts - returns victim posts by group.
    Customer-aware: checks if any customer domain/brand appears in victim names.
    Also inserts global ransomware intel for S5 brand matching.
    Source: https://github.com/joshhighet/ransomwatch (verified free, updated hourly)
    """
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "customer_hits": 0, "groups_seen": []}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            resp = await c.get("https://ransomwhat.telemetry.ltd/posts",
                headers={"User-Agent": "ArgusWatch/16.0"}, timeout=25.0)
            if resp.status_code != 200:
                log.warning(f"Ransomwatch returned {resp.status_code}")
                return {"error": f"HTTP {resp.status_code}", "new": 0}

            posts = resp.json()
            if not isinstance(posts, list):
                return {"error": "unexpected response format", "new": 0}

            # Only process recent posts (last 7 days)
            from datetime import timedelta
            cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
            recent = [p for p in posts if (p.get("discovered", "") or "") >= cutoff]
            stats["total"] = len(recent)

            # Get customer assets for matching
            async with AsyncSessionLocal() as db:
                try:
                    r = await db.execute(text("""
                        SELECT ca.asset_value, ca.asset_type, c.id, c.name
                        FROM customer_assets ca JOIN customers c ON c.id = ca.customer_id
                        WHERE ca.asset_type IN ('domain','brand_name','keyword')
                        AND c.active = true LIMIT 100
                    """))
                    customer_assets = r.all()
                except Exception:
                    customer_assets = []

                for post in recent[:50]:
                    group = (post.get("group_name") or "").strip()
                    title = (post.get("post_title") or "").strip()[:300]
                    discovered = post.get("discovered", "")
                    if not title: continue

                    full_text = f"{group} {title}".lower()
                    if group and group not in stats["groups_seen"]:
                        stats["groups_seen"].append(group)

                    # Check each customer asset against this victim post
                    matched_customer = None
                    matched_asset_val = ""
                    for asset_val, asset_type, cid, cname in customer_assets:
                        if asset_val.lower() in full_text:
                            matched_customer = cid
                            matched_asset_val = asset_val
                            break

                    sev = "CRITICAL" if matched_customer else "MEDIUM"
                    sla = 4 if matched_customer else 72
                    raw = f"Ransomwatch [{group}]: {title}"

                    # Detect exfiltration evidence in post text
                    exfil_keywords = re.compile(
                        r'(?:\d+\s*(?:GB|TB|MB|files?|records?|rows?))|'
                        r'(?:exfiltrat|stolen\s+data|leaked?\s+data|data\s+(?:dump|leak|breach|stolen))|'
                        r'(?:download\s+(?:link|available))|(?:published|releasing)',
                        re.IGNORECASE
                    )
                    exfil_evidence = bool(exfil_keywords.search(f"{title} {group}"))

                    det_id = await insert_detection(db, "ransomwatch", "threat_actor_intel",
                        f"ransomwatch:{hashlib.sha256(f'{group}:{title}'.encode()).hexdigest()[:16]}", sev, sla, raw,
                        confidence=0.80 if matched_customer else 0.5,
                        customer_id=matched_customer,
                        metadata={"group": group, "post_title": title,
                                  "discovered": discovered,
                                  "matched_asset": matched_asset_val,
                                  "exfiltration_confirmed": exfil_evidence})

                    # If exfiltration evidence + customer match → insert Cat 15 detection
                    if det_id and exfil_evidence and matched_customer:
                        await insert_detection(db, "ransomwatch", "data_exfiltration_evidence",
                            f"exfil:ransomwatch:{hashlib.sha256(f'{group}:{title}'.encode()).hexdigest()[:16]}",
                            "CRITICAL", 4, f"EXFILTRATION EVIDENCE: {group} claims data from {matched_asset_val}: {title}",
                            confidence=0.85, customer_id=matched_customer,
                            metadata={"group": group, "original_post": title,
                                      "category": "cat15_data_exfiltration",
                                      "evidence_type": "ransomware_claim"})
                        stats["exfil_detections"] = stats.get("exfil_detections", 0) + 1
                    if det_id:
                        stats["new"] += 1

                    # Also insert dark web mention if customer matched
                    if matched_customer:
                        stats["customer_hits"] += 1
                        await insert_darkweb(db, "ransomwatch", "ransomware_leak",
                            f"{group}: {title}"[:499], actor=group, severity="CRITICAL",
                            customer_id=matched_customer,
                            metadata={"matched_asset": matched_asset_val,
                                      "discovered": discovered})

                await insert_collector_run(db, "ransomwatch", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"Ransomwatch: {stats['new']} new / {stats['total']} recent / {stats['customer_hits']} customer hits / groups: {stats['groups_seen'][:10]}")
    except Exception as e:
        log.error(f"Ransomwatch failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_grep_app():
    """Grep.app - real-time public GitHub search for exposed secrets. FREE.
    
    TWO MODES:
    1. CUSTOMER-AWARE: Search for each customer's domain/org on GitHub
       → Finds API keys, .env files, config leaks WITH customer attribution
       → Results stored with customer_id already set
    2. GENERIC: Search for high-signal patterns (AWS keys, private keys)
       → Finds unattributed secrets, matched later via context attribution
    
    FIX B: Runs pattern_matcher on snippet to store SPECIFIC ioc_types
    (aws_access_key, stripe_live_key, etc) instead of generic "exposed_secret"
    """
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "customer_targeted": 0, "generic": 0}
    import re as _re
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
    try:
        from arguswatch.engine.pattern_matcher import scan_text as pm_scan
        from arguswatch.engine.severity_scorer import score as sev_score
    except ImportError:
        pm_scan = None
        sev_score = None
    
    def _classify_and_store(snippet, repo, file_path, source_meta):
        """Run pattern_matcher on snippet to get specific IOC types.
        Returns list of (ioc_type, ioc_value, severity, sla, raw_text) tuples.
        Falls back to 'exposed_secret' if no patterns match."""
        results = []
        if pm_scan and snippet:
            try:
                matches = pm_scan(snippet)
                for m in matches[:10]:
                    if sev_score:
                        try:
                            s = sev_score(m.category, m.ioc_type, confidence=m.confidence)
                            sev, sla = s.severity, s.sla_hours
                        except Exception:
                            sev, sla = "HIGH", 24
                    else:
                        sev, sla = "HIGH", 24
                    results.append((m.ioc_type, m.value, sev, sla, m.confidence))
            except Exception:
                pass
        if not results:
            # Fallback: store as exposed_secret
            results.append(("exposed_secret", f"{repo}/{file_path}", "HIGH", 24, 0.6))
        return results
    
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            async with AsyncSessionLocal() as db:
                # ── MODE 1: Customer-targeted searches ──
                try:
                    r = await db.execute(text("""
                        SELECT DISTINCT ca.asset_value, ca.asset_type, c.id as customer_id, c.name
                        FROM customer_assets ca JOIN customers c ON c.id = ca.customer_id
                        WHERE ca.asset_type IN ('domain', 'github_org', 'org_name')
                        AND c.active = true LIMIT 20
                    """))
                    customer_assets = r.all()
                except Exception:
                    customer_assets = []
                
                for asset_value, asset_type, cust_id, cust_name in customer_assets:
                    # Search GitHub for this customer's domain/org
                    search_queries = [
                        f"{asset_value} filename:.env",
                        f"{asset_value} password",
                        f"{asset_value} api_key",
                    ]
                    if asset_type == "github_org":
                        search_queries.append(f"org:{asset_value} filename:.env")
                        search_queries.append(f"org:{asset_value} password")
                    
                    for query in search_queries[:3]:
                        try:
                            resp = await c.get("https://grep.app/api/search",
                                params={"q": query, "page": "1"},
                                headers={"User-Agent": "ArgusWatch/16.0"})
                            if resp.status_code != 200: continue
                            data = resp.json()
                            hits = data.get("hits", {}).get("hits", [])
                            stats["total"] += len(hits)
                            for hit in hits[:5]:
                                repo = hit.get("repo", "") if isinstance(hit.get("repo"), str) else hit.get("repo", {}).get("raw", "")
                                file_path = hit.get("path", "") if isinstance(hit.get("path"), str) else hit.get("file", {}).get("raw", "")
                                raw_snippet = hit.get("content", {}).get("snippet", "") if isinstance(hit.get("content"), dict) else str(hit.get("content", ""))
                                snippet = _re.sub(r'<[^>]+>', '', raw_snippet)[:300]
                                if not repo: continue
                                raw = f"Customer-targeted GitHub leak [{cust_name}]: {repo}/{file_path} - {snippet}"
                                # Classify snippet with pattern_matcher
                                classified = _classify_and_store(snippet, repo, file_path, {})
                                for ioc_type, ioc_value, sev, sla, conf in classified:
                                    det_id = await insert_detection(db, "grep_app", ioc_type,
                                        ioc_value, sev, sla, raw[:2000], confidence=conf,
                                        customer_id=cust_id,
                                        metadata={"repo": repo, "file": file_path, "query": query,
                                                  "customer_targeted": True, "customer_name": cust_name})
                                    if det_id:
                                        stats["new"] += 1
                                        stats["customer_targeted"] += 1
                        except Exception as e:
                            log.debug(f"Grep.app customer '{query}': {e}")
                    await asyncio.sleep(1)  # Rate limiting
                
                # ── MODE 2: Generic high-signal searches ──
                generic_queries = [
                    # ── ORIGINAL (already working) ──
                    "AWS_SECRET_ACCESS_KEY",
                    "PRIVATE KEY filename:.pem",
                    "sk_live_ filename:.env",
                    "ghp_ filename:.env",
                    # ── SLACK (CRITICAL, 0 in database) ──
                    "xoxb- filename:.env",
                    "xoxp- filename:.env",
                    # ── GITLAB (CRITICAL, 0 in database) ──
                    "glpat- filename:.env",
                    # ── AI KEYS (CRITICAL — pattern was broken, now fixed) ──
                    "sk-ant-api filename:.env",
                    "OPENAI_API_KEY filename:.env",
                    # ── GOOGLE OAUTH (ya29.* expire but EVIDENCE of leak) ──
                    "ya29. filename:.env",
                    "ya29. filename:.properties",
                    # ── JWT TOKENS (now merged into single type) ──
                    "eyJhbGciOi",
                    # ── SENDGRID (pattern fixed) ──
                    "SG. filename:.env",
                    "SENDGRID_API_KEY filename:.env",
                    # ── CLOUD BUCKETS (replaces broken Sourcegraph) ──
                    ".blob.core.windows.net",
                    "storage.googleapis.com filename:.env",
                    "blob.core.windows.net sig=",
                    "s3:// filename:.env",
                    # ── DEV TUNNELS (replaces broken Sourcegraph) ──
                    "ngrok.io filename:.env",
                    "serveo.net filename:.env",
                    # ── AZURE (replaces broken Sourcegraph) ──
                    "AZURE_TOKEN filename:.env",
                    "AZURE_CLIENT_SECRET filename:.env",
                    # ── REMOTE CREDENTIALS ──
                    "rdp:// filename:.env",
                    "DATABASE_URL= filename:.env",
                    # ── SESSION TOKENS (expired but evidence of leak) ──
                    "JSESSIONID filename:.env",
                    "PHPSESSID filename:.properties",
                    # ── GITHUB OAuth (auto-revoked but in git history) ──
                    "gho_ filename:.env",
                    "ghs_ filename:.env",
                    "github_pat_ filename:.env",
                    # ── v16.4.5: NEW — 35 missing IOC type searches ──
                    # CSV data dumps (people commit sample/test CSVs)
                    "username,password,email filename:.csv",
                    "ssn,name,dob filename:.csv",
                    "card_number,cvv filename:.csv",
                    # SQL exfiltration (CTF/red team repos)
                    "INTO OUTFILE filename:.sql",
                    "INTO DUMPFILE filename:.sql",
                    # Exfiltration commands (red team tools)
                    "base64 /etc/shadow",
                    "transfer.sh filename:.sh",
                    # Archive staging
                    "7z a -p filename:.sh",
                    # Financial data (test numbers in committed code)
                    "5425233430109903",
                    "4111111111111111",
                    "378282246310005",
                    # NTLM/Kerberos (pentest dumps in repos)
                    "krbtgt filename:.txt",
                    "mimikatz filename:.log",
                    "NTLM filename:.txt",
                    # Breakglass (emergency procedures committed)
                    "break glass password",
                    "emergency access credential",
                    # LDAP configs (infrastructure repos)
                    "CN= DC= filename:.conf",
                    # Backup files (database dumps committed)
                    "mysqldump filename:.sh",
                    ".sql.gz filename:.env",
                    # Cloud shares (links committed in code)
                    "dropbox.com/s/ filename:.md",
                    "drive.google.com/file filename:.md",
                    # Ransom notes (research/sample repos)
                    "your files have been encrypted",
                    # V16.4.6: Two types had NO query — adding now
                    "AIza filename:.env",
                    "bitcoin address filename:.txt",
                    # SSN format (test data in repos)
                    "social_security filename:.csv",
                    # IBAN format (banking app test configs)
                    "IBAN filename:.env",
                ]
                for query in generic_queries:
                    try:
                        resp = await c.get("https://grep.app/api/search",
                            params={"q": query, "page": "1"},
                            headers={"User-Agent": "ArgusWatch/16.0"})
                        if resp.status_code != 200: continue
                        data = resp.json()
                        hits = data.get("hits", {}).get("hits", [])
                        stats["total"] += len(hits)
                        for hit in hits[:10]:
                            repo = hit.get("repo", "") if isinstance(hit.get("repo"), str) else hit.get("repo", {}).get("raw", "")
                            file_path = hit.get("path", "") if isinstance(hit.get("path"), str) else hit.get("file", {}).get("raw", "")
                            raw_snippet = hit.get("content", {}).get("snippet", "") if isinstance(hit.get("content"), dict) else str(hit.get("content", ""))
                            snippet = _re.sub(r'<[^>]+>', '', raw_snippet)[:200]
                            if not repo: continue
                            raw = f"Grep.app exposed secret: {repo}/{file_path} - {snippet}"
                            # Classify snippet with pattern_matcher
                            classified = _classify_and_store(snippet, repo, file_path, {})
                            for ioc_type, ioc_value, sev, sla, conf in classified:
                                det_id = await insert_detection(db, "grep_app", ioc_type,
                                    ioc_value, sev, sla, raw[:2000], confidence=conf,
                                    metadata={"repo": repo, "file": file_path, "query": query,
                                              "customer_targeted": False})
                                if det_id:
                                    stats["new"] += 1
                                    stats["generic"] += 1
                    except Exception as e:
                        log.debug(f"Grep.app generic '{query}': {e}")
                    await asyncio.sleep(1.5)  # V16.4.5: Rate limit - 52 queries needs spacing
                
                await insert_collector_run(db, "grep_app", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"Grep.app: {stats['new']} new ({stats['customer_targeted']} customer-targeted, {stats['generic']} generic)")
    except Exception as e:
        log.error(f"Grep.app failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_github_secrets():
    """GitHub API - exposed credentials in public repos. Optional GITHUB_TOKEN.
    
    Customer-aware: searches each customer's GitHub org for exposed secrets.
    Results stored with customer_id for immediate actionability.
    """
    if not GITHUB_TOKEN:
        log.info("GitHub secrets: skipped (no GITHUB_TOKEN)")
        return {"skipped": True, "reason": "no GITHUB_TOKEN", "new": 0}
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "customer_targeted": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
            async with AsyncSessionLocal() as db:
                # Get customer GitHub orgs and domains
                try:
                    r = await db.execute(text("""
                        SELECT DISTINCT ca.asset_value, ca.asset_type, c.id as customer_id, c.name
                        FROM customer_assets ca JOIN customers c ON c.id = ca.customer_id
                        WHERE ca.asset_type IN ('domain', 'github_org')
                        AND c.active = true LIMIT 15
                    """))
                    customer_assets = r.all()
                except Exception:
                    customer_assets = []
                
                for asset_value, asset_type, cust_id, cust_name in customer_assets:
                    queries = []
                    if asset_type == "github_org":
                        queries = [
                            f"org:{asset_value} filename:.env password",
                            f"org:{asset_value} filename:.env api_key",
                            f"org:{asset_value} AWS_SECRET",
                        ]
                    else:
                        queries = [
                            f"{asset_value} filename:.env",
                            f"{asset_value} password",
                        ]
                    
                    for q in queries[:2]:
                        try:
                            resp = await c.get("https://api.github.com/search/code",
                                params={"q": q, "per_page": 10},
                                headers={"Authorization": f"token {GITHUB_TOKEN}",
                                         "Accept": "application/vnd.github.v3+json"})
                            if resp.status_code != 200: continue
                            items = resp.json().get("items", [])
                            stats["total"] += len(items)
                            for item in items[:10]:
                                repo = item.get("repository", {}).get("full_name", "")
                                path = item.get("path", "")
                                raw = f"GitHub exposed [{cust_name}]: {repo}/{path}"
                                det_id = await insert_detection(db, "github", "exposed_secret",
                                    f"{repo}/{path}", "CRITICAL", 4, raw, confidence=0.8,
                                    customer_id=cust_id,
                                    metadata={"repo": repo, "file": path,
                                              "customer_targeted": True, "customer_name": cust_name})
                                if det_id:
                                    stats["new"] += 1
                                    stats["customer_targeted"] += 1
                        except Exception as e:
                            log.debug(f"GitHub '{q}': {e}")
                        await asyncio.sleep(2)  # GitHub rate limiting
                
                await insert_collector_run(db, "github", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"GitHub: {stats['new']} new ({stats['customer_targeted']} customer-targeted)")
    except Exception as e:
        log.error(f"GitHub failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_breach():
    """Breach detection - HIBP + BreachDirectory. Both require paid keys."""
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "hibp": 0, "breachdir": 0}
    
    if not HIBP_KEY and not BREACH_DIR_KEY:
        log.info("Breach: skipped (no HIBP_API_KEY or BREACHDIRECTORY_API_KEY)")
        return {"skipped": True, "reason": "no breach API keys", "new": 0}
    
    # Get customer domains to check
    try:
        async with AsyncSessionLocal() as db:
            r = await db.execute(text(
                "SELECT DISTINCT asset_value FROM customer_assets WHERE asset_type='domain' LIMIT 20"
            ))
            domains = [row[0] for row in r.all()]
    except Exception:
        domains = []
    
    if not domains:
        return {"skipped": True, "reason": "no customer domains", "new": 0}
    
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
            async with AsyncSessionLocal() as db:
                # Also fetch customer email assets for per-email HIBP lookups
                try:
                    r2 = await db.execute(text(
                        "SELECT DISTINCT asset_value FROM customer_assets WHERE asset_type='email_domain' LIMIT 10"
                    ))
                    email_domains = [row[0] for row in r2.all()]
                except Exception:
                    email_domains = []

                hibp_headers = {"hibp-api-key": HIBP_KEY, "User-Agent": "ArgusWatch-v16"}

                for domain in domains[:10]:
                    # ── Endpoint 1: /breacheddomain/{domain} ──
                    if HIBP_KEY:
                        try:
                            resp = await c.get(
                                f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                                headers=hibp_headers)
                            if resp.status_code == 200:
                                domain_breaches = resp.json()  # {email: [breach_names]}
                                for email, breach_list in domain_breaches.items():
                                    for bname in breach_list[:5]:
                                        det_id = await insert_detection(db, "hibp_domain", "breach_record",
                                            f"{email}:{bname}", "HIGH", 24,
                                            f"HIBP breacheddomain: {email} exposed in {bname}",
                                            confidence=0.85)
                                        if det_id:
                                            stats["new"] += 1; stats["hibp"] += 1
                            await asyncio.sleep(1.6)  # HIBP rate limit: ~10/min
                        except Exception as e:
                            log.debug(f"HIBP breacheddomain {domain}: {e}")

                    # ── Endpoint 2: /breachedaccount/{email} (sample emails from domain breaches) ──
                    if HIBP_KEY and domain in [d for d in email_domains]:
                        for prefix in ["admin", "info", "support", "security"]:
                            email_addr = f"{prefix}@{domain}"
                            try:
                                resp = await c.get(
                                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_addr}",
                                    headers=hibp_headers, params={"truncateResponse": "false"})
                                if resp.status_code == 200:
                                    for b in resp.json()[:10]:
                                        det_id = await insert_detection(db, "hibp_account", "email_breach",
                                            f"{email_addr}:{b.get('Name','')}",
                                            "HIGH", 24,
                                            f"HIBP account: {email_addr} in {b.get('Name','')} - {b.get('BreachDate','')}",
                                            confidence=0.9)
                                        if det_id:
                                            stats["new"] += 1; stats["hibp"] += 1
                                await asyncio.sleep(1.6)
                            except Exception as e:
                                log.debug(f"HIBP account {email_addr}: {e}")

                    # ── Endpoint 3: /pasteaccount/{email} ──
                    if HIBP_KEY and domain in [d for d in email_domains]:
                        for prefix in ["admin", "info", "support"]:
                            email_addr = f"{prefix}@{domain}"
                            try:
                                resp = await c.get(
                                    f"https://haveibeenpwned.com/api/v3/pasteaccount/{email_addr}",
                                    headers=hibp_headers)
                                if resp.status_code == 200 and resp.json():
                                    for paste in resp.json()[:10]:
                                        det_id = await insert_detection(db, "hibp_paste", "paste_exposure",
                                            f"{email_addr}:{paste.get('Id','')}",
                                            "MEDIUM", 72,
                                            f"HIBP paste: {email_addr} found in {paste.get('Source','unknown')} paste ({paste.get('Date','')})",
                                            confidence=0.8)
                                        if det_id:
                                            stats["new"] += 1; stats["hibp"] += 1
                                await asyncio.sleep(1.6)
                            except Exception as e:
                                log.debug(f"HIBP paste {email_addr}: {e}")
                    
                    # BreachDirectory
                    if BREACH_DIR_KEY:
                        try:
                            resp = await c.get(f"https://breachdirectory.org/api/search/{domain}",
                                headers={"Authorization": f"Bearer {BREACH_DIR_KEY}"})
                            if resp.status_code == 200:
                                data = resp.json()
                                results = data.get("result", [])
                                for r_item in results[:20]:
                                    email = r_item.get("email", "")
                                    if not email: continue
                                    det_id = await insert_detection(db, "breachdirectory", "email_password_combo",
                                        email, "HIGH", 24,
                                        f"BreachDirectory: {email} found in credential dump",
                                        confidence=0.75)
                                    if det_id:
                                        stats["new"] += 1
                                        stats["breachdir"] += 1
                        except Exception as e:
                            log.debug(f"BreachDir {domain}: {e}")
                    
                    await asyncio.sleep(1.5)  # Rate limiting
                await insert_collector_run(db, "breach", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"Breach: {stats['new']} new (HIBP:{stats['hibp']}, BD:{stats['breachdir']})")
    except Exception as e:
        log.error(f"Breach failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_socradar():
    """SocRadar - brand monitoring, leak alerts. Requires key."""
    if not SOCRADAR_KEY:
        log.info("SocRadar: skipped (no SOCRADAR_API_KEY)")
        return {"skipped": True, "reason": "no SOCRADAR_API_KEY", "new": 0}
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
            resp = await c.get("https://platform.socradar.com/api/threat/alerts",
                headers={"Authorization": f"Bearer {SOCRADAR_KEY}"})
            if resp.status_code == 200:
                alerts = resp.json().get("data", [])
                stats["total"] = len(alerts)
                async with AsyncSessionLocal() as db:
                    for alert in alerts[:50]:
                        title = alert.get("title", "")
                        sev = alert.get("severity", "MEDIUM")
                        raw = f"SocRadar: {title[:200]}"
                        await insert_darkweb(db, "socradar", "brand_alert",
                            title[:200], severity=sev, metadata=alert)
                        stats["new"] += 1
                    await insert_collector_run(db, "socradar", "completed", stats, started, datetime.utcnow())
                    await db.commit()
        log.info(f"SocRadar: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"SocRadar failed: {e}")
        stats["error"] = str(e)
    return stats


# ════════════════════════════════════════════════════════════
# ENTERPRISE COLLECTORS - require paid API keys
# ════════════════════════════════════════════════════════════

async def collect_spycloud():
    """SpyCloud - live stealer logs with session confirmation. Enterprise key required."""
    if not SPYCLOUD_KEY:
        return {"skipped": True, "reason": "no SPYCLOUD_API_KEY", "new": 0}
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0}
    try:
        async with AsyncSessionLocal() as db:
            domains = [r[0] for r in (await db.execute(text(
                "SELECT DISTINCT asset_value FROM customer_assets WHERE asset_type='domain' LIMIT 10"
            ))).all()]
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
            async with AsyncSessionLocal() as db:
                for domain in domains:
                    resp = await c.get(f"https://api.spycloud.io/enterprise-v2/breach/data/emails/{domain}",
                        headers={"Authorization": f"Bearer {SPYCLOUD_KEY}"})
                    if resp.status_code == 200:
                        records = resp.json().get("results", [])
                        stats["total"] += len(records)
                        for rec in records[:30]:
                            email = rec.get("email", "")
                            det_id = await insert_detection(db, "spycloud", "email_password_combo",
                                email, "CRITICAL", 4,
                                f"SpyCloud stealer log: {email} (active_session: {rec.get('active_session', False)})",
                                confidence=0.95,
                                metadata={"active_session": rec.get("active_session"), "source_id": rec.get("source_id")})
                            if det_id: stats["new"] += 1
                    await asyncio.sleep(1)
                await insert_collector_run(db, "spycloud", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"SpyCloud: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"SpyCloud failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_crowdstrike():
    """CrowdStrike Falcon Intel - threat actor profiles, campaign attribution. Enterprise."""
    if not CS_CLIENT_ID or not CS_SECRET:
        return {"skipped": True, "reason": "no CROWDSTRIKE credentials", "new": 0}
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
            # Get OAuth2 token
            token_resp = await c.post("https://api.crowdstrike.com/oauth2/token",
                data={"client_id": CS_CLIENT_ID, "client_secret": CS_SECRET})
            if token_resp.status_code != 201:
                return {"error": "CrowdStrike auth failed", "new": 0}
            token = token_resp.json().get("access_token", "")
            headers = {"Authorization": f"Bearer {token}"}
            
            # Fetch recent actors
            resp = await c.get("https://api.crowdstrike.com/intel/combined/actors/v1?limit=20",
                headers=headers)
            if resp.status_code == 200:
                actors = resp.json().get("resources", [])
                stats["total"] = len(actors)
                async with AsyncSessionLocal() as db:
                    for actor in actors:
                        name = actor.get("name", "")
                        if not name: continue
                        await insert_actor(db, name,
                            aliases=actor.get("known_as", ""),
                            origin=actor.get("origins", [{}])[0].get("value", "") if actor.get("origins") else "",
                            motivation=actor.get("motivations", [{}])[0].get("value", "") if actor.get("motivations") else "",
                            sectors=[s.get("value", "") for s in actor.get("target_industries", [])],
                            countries=[c.get("value", "") for c in actor.get("target_countries", [])],
                            description=actor.get("short_description", "")[:500])
                        stats["new"] += 1
                    await insert_collector_run(db, "crowdstrike", "completed", stats, started, datetime.utcnow())
                    await db.commit()
        log.info(f"CrowdStrike: {stats['new']} new / {stats['total']} total")
    except Exception as e:
        log.error(f"CrowdStrike failed: {e}")
        stats["error"] = str(e)
    return stats


# ════════════════════════════════════════════════════════════
# NEW v16.4.3: RAW TEXT → PATTERN_MATCHER PIPELINE
# These 3 collectors unlock ~47 IOC types with ZERO coverage today.
# They fetch RAW TEXT and run pattern_matcher on it.
# ════════════════════════════════════════════════════════════

_pm_scan_v2 = None
_sev_score_v2 = None
_pm_loaded_v2 = False

def _load_pm():
    global _pm_scan_v2, _sev_score_v2, _pm_loaded_v2
    if _pm_loaded_v2:
        return
    _pm_loaded_v2 = True
    try:
        from arguswatch.engine.pattern_matcher import scan_text
        _pm_scan_v2 = scan_text
    except ImportError:
        log.warning("pattern_matcher not available  -  raw text collectors disabled")
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
        raw_desc = f"{source_name}: {m.ioc_type} in {source_url[:100]}  -  {context[:200]}"
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
            # URL/domain/email IOCs get customer_id=None → correlation engine routes them.
            customer_id=customer_id if m.ioc_type in CONTEXT_SAFE_TYPES else None,
            metadata=meta)
        if det_id:
            new_count += 1
    return new_count


async def collect_github_gists():
    """GitHub Public Gists  -  scan recent public gists for secrets via pattern_matcher.
    API: GET https://api.github.com/gists/public?per_page=100
    VERIFIED: documented at docs.github.com, free, 60 req/hr without token.
    NOT TESTED: actual IOC yield from real gists (needs runtime).
    """
    started = datetime.utcnow()
    stats = {"new": 0, "gists_scanned": 0, "gists_with_iocs": 0,
             "total_gists": 0, "skipped": 0}
    github_token = os.getenv("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "ArgusWatch/16.4"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            all_gists = []
            for page in range(1, 4):
                try:
                    resp = await c.get("https://api.github.com/gists/public",
                                       params={"per_page": 100, "page": page}, headers=headers)
                    if resp.status_code == 403:
                        log.warning(f"GitHub Gist API rate limited on page {page}")
                        break
                    if resp.status_code != 200:
                        log.warning(f"GitHub Gist API returned {resp.status_code}")
                        break
                    gists = resp.json()
                    if not isinstance(gists, list) or not gists:
                        break
                    all_gists.extend(gists)
                    await asyncio.sleep(1)
                except Exception as e:
                    log.warning(f"GitHub Gist page {page}: {e}")
                    break
            stats["total_gists"] = len(all_gists)
            async with AsyncSessionLocal() as db:
                for gist in all_gists:
                    gist_id = gist.get("id", "")
                    files = gist.get("files", {})
                    owner = gist.get("owner", {}).get("login", "anon") if gist.get("owner") else "anon"
                    gist_url = gist.get("html_url", f"https://gist.github.com/{gist_id}")
                    if not files:
                        stats["skipped"] += 1
                        continue
                    combined = ""
                    file_names = []
                    for fname, fdata in files.items():
                        file_names.append(fname)
                        if fdata.get("content"):
                            combined += f"\n{fdata['content']}\n"
                        elif fdata.get("raw_url") and fdata.get("size", 0) < 500000:
                            try:
                                fr = await c.get(fdata["raw_url"], headers=headers)
                                if fr.status_code == 200:
                                    combined += f"\n{fr.text[:50000]}\n"
                            except Exception:
                                pass
                        if len(combined) > 200000:
                            break
                    if len(combined) < 20:
                        stats["skipped"] += 1
                        continue
                    stats["gists_scanned"] += 1
                    new = await _store_ioc_matches(db, combined, "github_gist", gist_url,
                        metadata_extra={"gist_id": gist_id, "owner": owner, "files": file_names[:10]})
                    if new > 0:
                        stats["new"] += new
                        stats["gists_with_iocs"] += 1
                    await asyncio.sleep(0.5 if github_token else 1.5)
                await insert_collector_run(db, "github_gist", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"GitHub Gists: {stats['new']} IOCs from {stats['gists_with_iocs']}/{stats['gists_scanned']} gists")
    except Exception as e:
        log.error(f"GitHub Gists failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "github_gist", "failed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    return stats


async def collect_sourcegraph():
    """Sourcegraph Public Code Search  -  search for secret patterns across 2M+ public repos.
    API: GET https://sourcegraph.com/.api/search/stream (stream) or POST /.api/graphql
    VERIFIED: documented at docs.sourcegraph.com, no auth for public repos.
    NOT TESTED: exact response format and rate limits (needs runtime).
    FALLBACK: if stream API fails, tries GraphQL API.
    """
    started = datetime.utcnow()
    stats = {"new": 0, "queries": 0, "results_scanned": 0}
    # High-signal queries ordered by danger (SLA 1h first)
    queries = [
        ("sk_live_ fork:yes count:50", "stripe_live_key"),
        ("xoxb- fork:yes count:50", "slack_bot_token"),
        ("xoxp- fork:yes count:50", "slack_user_token"),
        ("AKIA fork:yes count:100", "aws_access_key"),
        ("AWS_SECRET_ACCESS_KEY fork:yes count:50", "aws_secret_key"),
        ("ghp_ fork:yes count:50", "github_pat"),
        ("glpat- fork:yes count:50", "gitlab_pat"),
        ("sk-ant-api fork:yes count:30", "anthropic_key"),
        ('"-----BEGIN RSA PRIVATE KEY-----" fork:yes count:50', "private_key"),
        ('"-----BEGIN OPENSSH PRIVATE KEY-----" fork:yes count:30', "ssh_key"),
        ("password= file:.env fork:yes count:50", "env_password"),
        ("DATABASE_URL= file:.env fork:yes count:50", "db_connection"),
        ("SENDGRID_API_KEY fork:yes count:30", "sendgrid"),
        ("s3.amazonaws.com fork:yes count:30", "s3_bucket"),
        (".blob.core.windows.net fork:yes count:30", "azure_blob"),
        ("ngrok.io fork:yes count:20", "dev_tunnel"),
    ]
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as c:
            async with AsyncSessionLocal() as db:
                for query, label in queries:
                    stats["queries"] += 1
                    try:
                        # Try stream API first
                        resp = await c.get("https://sourcegraph.com/.api/search/stream",
                            params={"q": f"{query} type:file", "v": "V3", "display": "50"},
                            headers={"Accept": "text/event-stream", "User-Agent": "ArgusWatch/16.4"},
                            timeout=25.0)
                        if resp.status_code == 200 and len(resp.text) > 50:
                            # Parse streaming response (event: matches\ndata: {...}\n\n)
                            for chunk in resp.text.split("\nevent: "):
                                if "matches" not in chunk and "content" not in chunk:
                                    continue
                                data_start = chunk.find("data: ")
                                if data_start == -1:
                                    continue
                                data_line = chunk[data_start + 6:].strip()
                                if not data_line:
                                    continue
                                try:
                                    event_data = json.loads(data_line)
                                except json.JSONDecodeError:
                                    continue
                                items = event_data if isinstance(event_data, list) else [event_data]
                                for match in items:
                                    repo = match.get("repository", "")
                                    fpath = match.get("path", "") or match.get("name", "")
                                    line_matches = match.get("lineMatches", []) or match.get("chunkMatches", [])
                                    snippet = "\n".join(
                                        lm.get("preview", "") or lm.get("content", "")
                                        for lm in line_matches[:20])
                                    if not snippet or len(snippet) < 10:
                                        continue
                                    stats["results_scanned"] += 1
                                    src_url = f"https://sourcegraph.com/{repo}/-/blob/{fpath}"
                                    new = await _store_ioc_matches(db, snippet, "sourcegraph", src_url,
                                        metadata_extra={"repo": repo, "file": fpath, "query": label})
                                    stats["new"] += new
                        else:
                            # Fallback: GraphQL API
                            gql_resp = await c.post("https://sourcegraph.com/.api/graphql",
                                json={"query": """query($q:String!){search(query:$q,version:V3){
                                    results{results{...on FileMatch{repository{name}file{path}
                                    lineMatches{preview}}}}}}""",
                                    "variables": {"q": f"{query} type:file"}},
                                headers={"User-Agent": "ArgusWatch/16.4"}, timeout=25.0)
                            if gql_resp.status_code == 200:
                                results = (gql_resp.json().get("data", {}).get("search", {})
                                           .get("results", {}).get("results", []))
                                for r in results[:30]:
                                    repo = r.get("repository", {}).get("name", "")
                                    fpath = r.get("file", {}).get("path", "")
                                    snippet = "\n".join(lm.get("preview", "") for lm in r.get("lineMatches", [])[:20])
                                    if not snippet or len(snippet) < 10:
                                        continue
                                    stats["results_scanned"] += 1
                                    src_url = f"https://sourcegraph.com/{repo}/-/blob/{fpath}"
                                    new = await _store_ioc_matches(db, snippet, "sourcegraph", src_url,
                                        metadata_extra={"repo": repo, "file": fpath, "query": label})
                                    stats["new"] += new
                        await asyncio.sleep(3)
                    except Exception as e:
                        log.warning(f"Sourcegraph '{label}': {e}")
                        await asyncio.sleep(2)
                await insert_collector_run(db, "sourcegraph", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"Sourcegraph: {stats['new']} IOCs from {stats['results_scanned']} results across {stats['queries']} queries")
    except Exception as e:
        log.error(f"Sourcegraph failed: {e}")
        async with AsyncSessionLocal() as db:
            await insert_collector_run(db, "sourcegraph", "failed", stats, started, datetime.utcnow(), str(e))
            await db.commit()
        stats["error"] = str(e)
    return stats


async def collect_alt_paste():
    """Alternative Paste Sites  -  replace broken Pastebin PRO scraping API.
    Tries multiple free paste sites, downloads content, runs pattern_matcher.
    HONEST: most paste sites DON'T have a 'list recent' API. We try each one
    and log which work and which don't. No fake data.
    """
    started = datetime.utcnow()
    stats = {"new": 0, "pastes_scanned": 0, "total_pastes": 0,
             "sites_tried": 0, "sites_working": 0, "site_results": {}}
    _load_pm()
    paste_ee_key = os.getenv("PASTE_EE_API_KEY", "")
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
        async with AsyncSessionLocal() as db:
            # Site 1: dpaste.org  -  parse homepage for recent paste links
            stats["sites_tried"] += 1
            ss = {"name": "dpaste.org", "pastes": 0, "iocs": 0, "status": "unknown"}
            try:
                resp = await c.get("https://dpaste.org/", headers={"User-Agent": "ArgusWatch/16.4"}, timeout=15.0)
                if resp.status_code == 200:
                    paste_ids = list(dict.fromkeys(re.findall(r'href="/([A-Za-z0-9]{4,12})"', resp.text)))[:30]
                    ss["pastes"] = len(paste_ids)
                    stats["total_pastes"] += len(paste_ids)
                    for pid in paste_ids:
                        try:
                            rr = await c.get(f"https://dpaste.org/{pid}/raw", timeout=10.0)
                            if rr.status_code == 200 and len(rr.text) > 20:
                                stats["pastes_scanned"] += 1
                                new = await _store_ioc_matches(db, rr.text[:50000], "dpaste",
                                    f"https://dpaste.org/{pid}", metadata_extra={"site": "dpaste.org", "paste_id": pid})
                                if new > 0:
                                    stats["new"] += new; ss["iocs"] += new
                        except Exception:
                            pass
                        await asyncio.sleep(1)
                    ss["status"] = "ok"; stats["sites_working"] += 1
                else:
                    ss["status"] = f"http_{resp.status_code}"
            except Exception as e:
                ss["status"] = f"error: {str(e)[:60]}"
            stats["site_results"]["dpaste"] = ss

            # Site 2: paste.ee  -  needs free API key
            stats["sites_tried"] += 1
            ss = {"name": "paste.ee", "pastes": 0, "iocs": 0, "status": "unknown"}
            if paste_ee_key:
                try:
                    resp = await c.get("https://api.paste.ee/v1/pastes",
                                       headers={"X-Auth-Token": paste_ee_key}, timeout=15.0)
                    if resp.status_code == 200:
                        pastes = resp.json().get("data", []) if isinstance(resp.json(), dict) else []
                        ss["pastes"] = len(pastes)
                        stats["total_pastes"] += len(pastes)
                        for paste in pastes[:30]:
                            pid = paste.get("id", "")
                            if not pid:
                                continue
                            try:
                                rr = await c.get(f"https://api.paste.ee/v1/pastes/{pid}",
                                                 headers={"X-Auth-Token": paste_ee_key}, timeout=10.0)
                                if rr.status_code == 200:
                                    sections = rr.json().get("paste", {}).get("sections", [])
                                    content = "\n".join(s.get("contents", "") for s in sections)
                                    if len(content) > 20:
                                        stats["pastes_scanned"] += 1
                                        new = await _store_ioc_matches(db, content[:50000], "paste_ee",
                                            f"https://paste.ee/p/{pid}", metadata_extra={"site": "paste.ee", "paste_id": pid})
                                        if new > 0:
                                            stats["new"] += new; ss["iocs"] += new
                            except Exception:
                                pass
                            await asyncio.sleep(1)
                        ss["status"] = "ok"; stats["sites_working"] += 1
                    else:
                        ss["status"] = f"http_{resp.status_code}"
                except Exception as e:
                    ss["status"] = f"error: {str(e)[:60]}"
            else:
                ss["status"] = "skipped_no_key"
            stats["site_results"]["paste_ee"] = ss

            # Site 3: paste.centos.org
            stats["sites_tried"] += 1
            ss = {"name": "paste.centos.org", "pastes": 0, "iocs": 0, "status": "unknown"}
            try:
                resp = await c.get("https://paste.centos.org/", headers={"User-Agent": "ArgusWatch/16.4"}, timeout=10.0)
                if resp.status_code == 200:
                    paste_ids = list(dict.fromkeys(re.findall(r'href="/view/([a-z0-9]+)"', resp.text)))[:20]
                    ss["pastes"] = len(paste_ids)
                    stats["total_pastes"] += len(paste_ids)
                    for pid in paste_ids:
                        try:
                            rr = await c.get(f"https://paste.centos.org/view/raw/{pid}", timeout=10.0)
                            if rr.status_code == 200 and len(rr.text) > 20:
                                stats["pastes_scanned"] += 1
                                new = await _store_ioc_matches(db, rr.text[:50000], "centos_paste",
                                    f"https://paste.centos.org/view/{pid}", metadata_extra={"site": "paste.centos.org", "paste_id": pid})
                                if new > 0:
                                    stats["new"] += new; ss["iocs"] += new
                        except Exception:
                            pass
                        await asyncio.sleep(1)
                    ss["status"] = "ok"; stats["sites_working"] += 1
                else:
                    ss["status"] = f"http_{resp.status_code}"
            except Exception as e:
                ss["status"] = f"error: {str(e)[:60]}"
            stats["site_results"]["centos_paste"] = ss

            # Site 4: paste.ubuntu.com
            stats["sites_tried"] += 1
            ss = {"name": "paste.ubuntu.com", "pastes": 0, "iocs": 0, "status": "unknown"}
            try:
                resp = await c.get("https://paste.ubuntu.com/", headers={"User-Agent": "ArgusWatch/16.4"}, timeout=10.0)
                if resp.status_code == 200:
                    paste_ids = list(dict.fromkeys(re.findall(r'href="/p/([A-Za-z0-9]+)/"', resp.text)))[:20]
                    ss["pastes"] = len(paste_ids)
                    stats["total_pastes"] += len(paste_ids)
                    for pid in paste_ids:
                        try:
                            rr = await c.get(f"https://paste.ubuntu.com/p/{pid}/plain/", timeout=10.0)
                            if rr.status_code == 200 and len(rr.text) > 20:
                                stats["pastes_scanned"] += 1
                                new = await _store_ioc_matches(db, rr.text[:50000], "ubuntu_paste",
                                    f"https://paste.ubuntu.com/p/{pid}/", metadata_extra={"site": "paste.ubuntu.com", "paste_id": pid})
                                if new > 0:
                                    stats["new"] += new; ss["iocs"] += new
                        except Exception:
                            pass
                        await asyncio.sleep(1)
                    ss["status"] = "ok"; stats["sites_working"] += 1
                else:
                    ss["status"] = f"http_{resp.status_code}"
            except Exception as e:
                ss["status"] = f"error: {str(e)[:60]}"
            stats["site_results"]["ubuntu_paste"] = ss

            await insert_collector_run(db, "alt_paste", "completed", stats, started, datetime.utcnow())
            await db.commit()
    log.info(f"Alt Paste: {stats['new']} IOCs from {stats['pastes_scanned']} pastes across {stats['sites_working']}/{stats['sites_tried']} sites")
    return stats


# ════════════════════════════════════════════════════════════
# v16.4.3: GRAYHATWARFARE + LEAKIX + TELEGRAM
# ════════════════════════════════════════════════════════════

GRAYHAT_KEY = os.getenv("GRAYHATWARFARE_API_KEY", "")
LEAKIX_KEY = os.getenv("LEAKIX_API_KEY", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHANNELS = os.getenv("TELEGRAM_CHANNELS", "")


async def collect_grayhatwarfare():
    """GrayHatWarfare  -  search exposed S3/Azure/GCS buckets per customer domain.
    API: https://buckets.grayhatwarfare.com/api/v2
    Auth: Bearer token in Authorization header.
    Free tier: 100 results per search.
    Unlocks: Cat 12 (SaaS Misconfig  -  s3_bucket_ref, s3_public_url, azure_blob_public, gcs_public_bucket)
    
    NOT TESTED: needs runtime verification of response format.
    """
    if not GRAYHAT_KEY:
        log.info("GrayHatWarfare: skipped (no GRAYHATWARFARE_API_KEY)")
        return {"skipped": True, "reason": "no GRAYHATWARFARE_API_KEY", "new": 0}
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "customers_searched": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            # Get customer domains
            async with AsyncSessionLocal() as db:
                r = await db.execute(text("""
                    SELECT DISTINCT ca.asset_value, ca.customer_id, cu.name
                    FROM customer_assets ca JOIN customers cu ON cu.id = ca.customer_id
                    WHERE ca.asset_type IN ('domain','keyword','brand_name')
                    AND cu.active = true LIMIT 20
                """))
                customer_assets = r.all()

            async with AsyncSessionLocal() as db:
                for asset_val, cust_id, cust_name in customer_assets:
                    stats["customers_searched"] += 1
                    for search_type in ["buckets", "files"]:
                        try:
                            resp = await c.get(
                                f"https://buckets.grayhatwarfare.com/api/v2/{search_type}",
                                params={"keywords": asset_val, "limit": 20},
                                headers={"Authorization": f"Bearer {GRAYHAT_KEY}"},
                                timeout=15.0,
                            )
                            if resp.status_code != 200:
                                continue
                            data = resp.json()
                            items = data.get(search_type, data.get("results", []))
                            if not isinstance(items, list):
                                continue
                            stats["total"] += len(items)
                            for item in items[:20]:
                                bucket = item.get("bucket", "") or item.get("bucketName", "")
                                url = item.get("url", "") or item.get("fileUrl", "")
                                fname = item.get("filename", "") or item.get("key", "")
                                cloud = item.get("type", "aws")  # aws, azure, gcp
                                # Determine IOC type
                                if "s3" in cloud.lower() or "aws" in cloud.lower():
                                    ioc_type = "s3_public_url"
                                elif "azure" in cloud.lower():
                                    ioc_type = "azure_blob_public"
                                elif "gcp" in cloud.lower() or "google" in cloud.lower():
                                    ioc_type = "gcs_public_bucket"
                                else:
                                    ioc_type = "cloud_misconfiguration"
                                ioc_val = url or f"{cloud}://{bucket}/{fname}"
                                raw = f"GrayHatWarfare [{cust_name}]: Exposed {cloud} {search_type[:-1]}  -  {bucket}/{fname}"
                                det_id = await insert_detection(db, "grayhatwarfare", ioc_type,
                                    ioc_val, "HIGH", 12, raw[:2000], confidence=0.8,
                                    customer_id=cust_id,
                                    metadata={"bucket": bucket, "file": fname, "cloud": cloud,
                                              "url": url, "customer": cust_name})
                                if det_id:
                                    stats["new"] += 1
                            await asyncio.sleep(1)
                        except Exception as e:
                            log.debug(f"GrayHatWarfare {asset_val}/{search_type}: {e}")
                    await asyncio.sleep(2)
                await insert_collector_run(db, "grayhatwarfare", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"GrayHatWarfare: {stats['new']} exposed buckets/files from {stats['customers_searched']} customers")
    except Exception as e:
        log.error(f"GrayHatWarfare failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_leakix():
    """LeakIX  -  search for exposed services AND leaked data per customer domain.
    API: https://leakix.net/search
    Auth: api-key header (free tier = anonymous, limited results)
    Two scopes: 'leak' (data leaks) and 'service' (exposed services)
    Unlocks: Cat 7 (Infrastructure Leaks), Cat 12 (SaaS Misconfig), Cat 1 (Credentials)
    
    NOT TESTED: needs runtime verification.
    """
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "customers_searched": 0, "leaks": 0, "services": 0}
    headers = {"Accept": "application/json", "User-Agent": "ArgusWatch/16.4"}
    if LEAKIX_KEY:
        headers["api-key"] = LEAKIX_KEY
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            async with AsyncSessionLocal() as db:
                # Get customer domains
                try:
                    r = await db.execute(text("""
                        SELECT DISTINCT ca.asset_value, ca.customer_id, cu.name
                        FROM customer_assets ca JOIN customers cu ON cu.id = ca.customer_id
                        WHERE ca.asset_type IN ('domain','ip')
                        AND cu.active = true LIMIT 15
                    """))
                    customer_assets = r.all()
                except Exception:
                    customer_assets = []

                for asset_val, cust_id, cust_name in customer_assets:
                    stats["customers_searched"] += 1
                    for scope in ["leak", "service"]:
                        try:
                            resp = await c.get("https://leakix.net/search",
                                params={"scope": scope, "q": asset_val},
                                headers=headers, timeout=15.0)
                            if resp.status_code != 200:
                                continue
                            results = resp.json()
                            if not isinstance(results, list):
                                continue
                            stats["total"] += len(results)
                            for item in results[:15]:
                                ip = item.get("ip", "")
                                host = item.get("host", "") or item.get("hostname", "")
                                port = item.get("port", "")
                                protocol = item.get("protocol", "")
                                summary = item.get("summary", "") or item.get("event_description", "")
                                leak_type = item.get("type_tags", []) or []
                                severity_tag = item.get("leak", {}).get("severity", "medium") if isinstance(item.get("leak"), dict) else "medium"
                                sev = "CRITICAL" if severity_tag == "critical" else "HIGH" if severity_tag == "high" else "MEDIUM"
                                sla = 4 if sev == "CRITICAL" else 12 if sev == "HIGH" else 48
                                if scope == "leak":
                                    ioc_type = "data_leak"
                                    stats["leaks"] += 1
                                    # Also run pattern_matcher on leak content
                                    content = item.get("leak", {}).get("data", "") if isinstance(item.get("leak"), dict) else ""
                                    if content and _pm_scan_v2:
                                        new_from_pm = await _store_ioc_matches(
                                            db, content[:50000], "leakix_content",
                                            f"https://leakix.net/host/{ip}",
                                            customer_id=cust_id,
                                            metadata_extra={"scope": scope, "host": host})
                                        stats["new"] += new_from_pm
                                else:
                                    ioc_type = "elasticsearch_exposed" if "elastic" in str(leak_type).lower() else \
                                               "open_analytics_service" if any(t in str(leak_type).lower() for t in ["kibana", "grafana"]) else \
                                               "cloud_misconfiguration"
                                    stats["services"] += 1
                                raw = f"LeakIX [{scope}] [{cust_name}]: {host or ip}:{port} {protocol}  -  {summary[:200]}"
                                det_id = await insert_detection(db, "leakix", ioc_type,
                                    f"{ip or host}:{port}", sev, sla, raw[:2000],
                                    confidence=0.75, customer_id=cust_id,
                                    metadata={"scope": scope, "ip": ip, "host": host,
                                              "port": port, "protocol": protocol,
                                              "leak_type": leak_type, "customer": cust_name})
                                if det_id:
                                    stats["new"] += 1
                            await asyncio.sleep(2)
                        except Exception as e:
                            log.debug(f"LeakIX {asset_val}/{scope}: {e}")
                    await asyncio.sleep(2)
                await insert_collector_run(db, "leakix", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"LeakIX: {stats['new']} new ({stats['leaks']} leaks, {stats['services']} services) from {stats['customers_searched']} customers")
    except Exception as e:
        log.error(f"LeakIX failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_telegram():
    """Telegram Public Channels  -  scrape public channel web previews for IOCs.
    
    APPROACH: Uses t.me/s/{channel} web preview (NO Telethon, NO bot token needed for reading).
    Public channels have a web-accessible preview at https://t.me/s/channelname
    We parse the HTML for messages, run pattern_matcher on each.
    
    For PRIVATE channels or real-time monitoring: needs TELEGRAM_BOT_TOKEN.
    Bot API: https://api.telegram.org/bot{token}/getUpdates
    
    DEFAULT CHANNELS (public threat intel):
    - @vaborosecurity, @darkwebinformer, @breaborosecurity, @ransomwatch
    - Configurable via TELEGRAM_CHANNELS env var
    
    NOT TESTED: t.me/s/ HTML structure needs runtime verification.
    """
    started = datetime.utcnow()
    stats = {"new": 0, "messages_scanned": 0, "channels_checked": 0, "channel_results": {}}

    # Default public threat intel channels
    default_channels = [
        "darkwebinformer",
        "RansomwareLeaks",
        "breaborosecurity",
        "daborosecurity",
        "caborosecurity",
        "infosec_news",
    ]
    custom = TELEGRAM_CHANNELS.split(",") if TELEGRAM_CHANNELS else []
    channels = list(dict.fromkeys([c.strip().lstrip("@") for c in (custom + default_channels) if c.strip()]))

    _load_pm()
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            async with AsyncSessionLocal() as db:
                for channel in channels[:10]:
                    stats["channels_checked"] += 1
                    ch_stats = {"name": channel, "messages": 0, "iocs": 0, "status": "unknown"}
                    try:
                        # Fetch public web preview
                        resp = await c.get(f"https://t.me/s/{channel}",
                            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                            timeout=15.0)
                        if resp.status_code != 200:
                            ch_stats["status"] = f"http_{resp.status_code}"
                            stats["channel_results"][channel] = ch_stats
                            continue

                        html = resp.text
                        # Parse messages from tgme_widget_message_text divs
                        import re as _re
                        messages = _re.findall(
                            r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
                            html, _re.DOTALL)
                        ch_stats["messages"] = len(messages)
                        stats["messages_scanned"] += len(messages)

                        for msg_html in messages[:30]:
                            # Strip HTML tags to get plain text
                            text = _re.sub(r'<[^>]+>', ' ', msg_html).strip()
                            text = _re.sub(r'\s+', ' ', text)
                            if len(text) < 20:
                                continue

                            # Run pattern_matcher
                            new = await _store_ioc_matches(
                                db, text, "telegram", f"https://t.me/s/{channel}",
                                metadata_extra={"channel": channel, "source": "telegram_web"})
                            if new > 0:
                                stats["new"] += new
                                ch_stats["iocs"] += new
                            else:
                                # Even without IOC match, check for ransom/breach keywords
                                keywords = ["leak", "breach", "ransom", "dump", "stealer",
                                            "credential", "exfiltrat", "auction", "selling data"]
                                if any(kw in text.lower() for kw in keywords):
                                    await insert_darkweb(db, "telegram", "channel_mention",
                                        f"[{channel}] {text[:200]}", severity="MEDIUM",
                                        metadata={"channel": channel, "full_text": text[:500]})
                                    stats["new"] += 1
                                    ch_stats["iocs"] += 1

                        ch_stats["status"] = "ok"
                        await asyncio.sleep(3)  # Rate limit between channels
                    except Exception as e:
                        ch_stats["status"] = f"error: {str(e)[:60]}"
                        log.debug(f"Telegram {channel}: {e}")
                    stats["channel_results"][channel] = ch_stats

                await insert_collector_run(db, "telegram", "completed", stats, started, datetime.utcnow())
                await db.commit()

        working = sum(1 for ch in stats["channel_results"].values() if ch.get("status") == "ok")
        log.info(f"Telegram: {stats['new']} IOCs from {stats['messages_scanned']} messages across {working}/{stats['channels_checked']} channels")
    except Exception as e:
        log.error(f"Telegram failed: {e}")
        stats["error"] = str(e)
    return stats


# ════════════════════════════════════════════════════════════
# NEW COLLECTORS v16.4.4: crt.sh, HIBP breaches, GitHub Code Search, URLScan community
# ════════════════════════════════════════════════════════════

async def collect_crtsh():
    """crt.sh Certificate Transparency - discovers ALL subdomains via SSL cert logs. FREE."""
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "customers": 0}
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as c:
            async with AsyncSessionLocal() as db:
                try:
                    r = await db.execute(text(
                        "SELECT DISTINCT ca.asset_value, ca.customer_id, c.name "
                        "FROM customer_assets ca JOIN customers c ON c.id = ca.customer_id "
                        "WHERE ca.asset_type = 'domain' LIMIT 10"))
                    domains = r.all()
                except Exception:
                    domains = []
                for domain, cust_id, cust_name in domains:
                    stats["customers"] += 1
                    try:
                        resp = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                            headers={"User-Agent": "ArgusWatch/16.4"}, timeout=25.0)
                        if resp.status_code != 200: continue
                        certs = resp.json()
                        seen = set()
                        for cert in certs[:100]:
                            name = cert.get("name_value", "") or cert.get("common_name", "")
                            for subdomain in name.split("\n"):
                                subdomain = subdomain.strip().lower()
                                if not subdomain or subdomain in seen or subdomain == domain:
                                    continue
                                if not subdomain.endswith(f".{domain}") and subdomain != domain:
                                    continue
                                seen.add(subdomain)
                                stats["total"] += 1
                                raw = f"CT Log: subdomain {subdomain} found for {cust_name} ({domain})"
                                det_id = await insert_detection(db, "crtsh", "subdomain",
                                    subdomain, "MEDIUM", 24, raw, confidence=0.95,
                                    customer_id=cust_id,
                                    metadata={"domain": domain, "customer": cust_name,
                                              "issuer": cert.get("issuer_name", "")[:100],
                                              "not_before": cert.get("not_before", ""),
                                              "source": "certificate_transparency"})
                                if det_id: stats["new"] += 1
                        await asyncio.sleep(2)
                    except Exception as e:
                        log.debug(f"crt.sh {domain}: {e}")
                await insert_collector_run(db, "crtsh", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"crt.sh: {stats['new']} subdomains from {stats['customers']} customers")
    except Exception as e:
        log.error(f"crt.sh failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_hibp_breaches():
    """HIBP Breach Database - cross-refs customer domains against ALL known breaches. FREE (no key for breach list)."""
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "breaches_checked": 0}
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as c:
            resp = await c.get("https://haveibeenpwned.com/api/v3/breaches",
                headers={"User-Agent": "ArgusWatch/16.4"})
            if resp.status_code != 200:
                return {"error": f"HIBP returned {resp.status_code}", "new": 0}
            breaches = resp.json()
            stats["breaches_checked"] = len(breaches)
            async with AsyncSessionLocal() as db:
                try:
                    r = await db.execute(text(
                        "SELECT DISTINCT ca.asset_value, ca.customer_id, c.name "
                        "FROM customer_assets ca JOIN customers c ON c.id = ca.customer_id "
                        "WHERE ca.asset_type = 'domain' LIMIT 10"))
                    domains = r.all()
                except Exception:
                    domains = []
                domain_set = {d[0].lower() for d in domains}
                domain_cust = {d[0].lower(): (d[1], d[2]) for d in domains}
                # Also build name-based lookup for fuzzy matching
                name_cust = {}
                for d in domains:
                    cname = d[2].lower().strip()
                    if len(cname) > 3:  # Skip very short names to avoid false matches
                        name_cust[cname] = (d[1], d[2])
                for breach in breaches:
                    bdomain = (breach.get("Domain") or "").lower()
                    bname = breach.get("Name", "")
                    btitle = breach.get("Title", "").lower()
                    if not bdomain and not bname: continue
                    stats["total"] += 1
                    matched_domain = None
                    matched_cust = None
                    # Method 1: Domain match
                    for cd in domain_set:
                        if bdomain == cd or bdomain.endswith(f".{cd}") or cd.endswith(f".{bdomain}"):
                            matched_domain = cd
                            matched_cust = domain_cust[matched_domain]
                            break
                    # Method 2: Company name in breach title (e.g. "Yahoo" in "Yahoo Voices")
                    if not matched_cust:
                        for cname, cdata in name_cust.items():
                            if cname in btitle or cname in bname.lower():
                                matched_cust = cdata
                                matched_domain = cname
                                break
                    if matched_cust:
                        cust_id, cust_name = matched_cust
                        pwn_count = breach.get("PwnCount", 0)
                        data_classes = breach.get("DataClasses", [])
                        severity = "CRITICAL" if pwn_count > 1000000 or "Passwords" in data_classes else \
                                   "HIGH" if pwn_count > 100000 or "Credit cards" in data_classes else "MEDIUM"
                        sla = 4 if severity == "CRITICAL" else 12 if severity == "HIGH" else 24
                        raw = (f"HIBP Breach: {bname} affected {bdomain} ({pwn_count:,} records). "
                               f"Data exposed: {', '.join(data_classes[:5])}. Customer: {cust_name}")
                        det_id = await insert_detection(db, "hibp_breaches", "breach_record",
                            f"{bname}:{bdomain}", severity, sla, raw, confidence=0.95,
                            customer_id=cust_id,
                            metadata={"breach_name": bname, "breach_date": breach.get("BreachDate"),
                                      "pwn_count": pwn_count, "data_classes": data_classes[:10],
                                      "customer": cust_name, "domain": bdomain})
                        if det_id: stats["new"] += 1
                await insert_collector_run(db, "hibp_breaches", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"HIBP Breaches: {stats['new']} customer matches from {stats['breaches_checked']} breaches")
    except Exception as e:
        log.error(f"HIBP Breaches failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_github_code_search():
    """GitHub Code Search API - finds leaked secrets in public repos. Needs GITHUB_TOKEN (free)."""
    github_token = os.getenv("GITHUB_TOKEN", "")
    if not github_token:
        return {"skipped": True, "reason": "no GITHUB_TOKEN", "new": 0}
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "queries": 0}
    queries = [
        # Original 6
        ("AKIA extension:env", "aws_access_key"),
        ("sk_live_ extension:env", "stripe_live_key"),
        ("xoxb- extension:env", "slack_bot_token"),
        ("ghp_ extension:env", "github_pat"),
        ("DATABASE_URL= extension:env", "db_connection"),
        ("PRIVATE KEY extension:pem", "private_key"),
        # Fix BROKEN: replaces Sourcegraph for these 6 IOC types
        (".blob.core.windows.net extension:env", "azure_blob_public"),
        ("storage.googleapis.com extension:env", "gcs_public_bucket"),
        ("s3:// extension:env", "s3_bucket_ref"),
        ("ngrok.io extension:env", "dev_tunnel_exposed"),
        ("SharedAccessSignature= extension:env", "azure_sas_token"),
        ("Bearer ey extension:env", "azure_bearer"),
        # Fix PATTERN EXISTS: high-value secrets
        ("xoxp- extension:env", "slack_user_token"),
        ("glpat- extension:env", "gitlab_pat"),
        ("sk-ant-api extension:env", "anthropic_api_key"),
        ("SG. extension:env", "sendgrid_api_key"),
        ("ya29. extension:env", "google_oauth_bearer"),
        ("eyJhbG extension:env", "jwt_token"),
    ]
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as c:
            headers = {"Authorization": f"token {github_token}",
                       "Accept": "application/vnd.github.v3.text-match+json",
                       "User-Agent": "ArgusWatch/16.4"}
            async with AsyncSessionLocal() as db:
                for query, label in queries:
                    stats["queries"] += 1
                    try:
                        resp = await c.get("https://api.github.com/search/code",
                            params={"q": query, "per_page": 20},
                            headers=headers, timeout=15.0)
                        if resp.status_code == 403:
                            log.warning("GitHub Code Search rate limited")
                            break
                        if resp.status_code != 200: continue
                        data = resp.json()
                        items = data.get("items", [])
                        stats["total"] += len(items)
                        for item in items[:15]:
                            repo = item.get("repository", {}).get("full_name", "")
                            fpath = item.get("path", "")
                            html_url = item.get("html_url", "")
                            text_matches = item.get("text_matches", [])
                            snippet = "\n".join(tm.get("fragment", "") for tm in text_matches[:3])[:500]
                            if not repo or not snippet: continue
                            raw = f"GitHub Code: {label} found in {repo}/{fpath}\n{snippet[:300]}"
                            new = await _store_ioc_matches(db, snippet, "github_code", html_url,
                                metadata_extra={"repo": repo, "file": fpath, "query": label})
                            stats["new"] += new
                        await asyncio.sleep(3)  # GitHub rate limit
                    except Exception as e:
                        log.debug(f"GitHub Code '{label}': {e}")
                await insert_collector_run(db, "github_code", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"GitHub Code Search: {stats['new']} IOCs from {stats['queries']} queries")
    except Exception as e:
        log.error(f"GitHub Code Search failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_urlscan_community():
    """URLScan.io Community Feed - detects phishing pages targeting customer brands. FREE."""
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "customers": 0}
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as c:
            async with AsyncSessionLocal() as db:
                try:
                    r = await db.execute(text(
                        "SELECT DISTINCT ca.asset_value, ca.customer_id, c.name "
                        "FROM customer_assets ca JOIN customers c ON c.id = ca.customer_id "
                        "WHERE ca.asset_type = 'domain' LIMIT 8"))
                    domains = r.all()
                except Exception:
                    domains = []
                for domain, cust_id, cust_name in domains:
                    stats["customers"] += 1
                    try:
                        resp = await c.get("https://urlscan.io/api/v1/search/",
                            params={"q": f"domain:{domain}", "size": 20},
                            headers={"User-Agent": "ArgusWatch/16.4"}, timeout=15.0)
                        if resp.status_code != 200: continue
                        data = resp.json()
                        for result in data.get("results", [])[:15]:
                            task = result.get("task", {})
                            page = result.get("page", {})
                            scan_url = task.get("url", "")
                            scan_domain = task.get("domain", "")
                            if not scan_url: continue
                            stats["total"] += 1
                            is_sus = scan_domain and scan_domain != domain and domain in scan_url
                            severity = "HIGH" if is_sus else "MEDIUM"
                            sla = 12 if is_sus else 24
                            raw = (f"URLScan: {scan_url[:200]} "
                                   f"{'SUSPICIOUS - different domain mentions ' + cust_name if is_sus else 'scan result for ' + cust_name}")
                            det_id = await insert_detection(db, "urlscan_community", "url",
                                scan_url[:500], severity, sla, raw, confidence=0.7 if is_sus else 0.5,
                                customer_id=cust_id,
                                metadata={"domain": scan_domain, "customer": cust_name,
                                          "suspicious": is_sus, "country": page.get("country", ""),
                                          "server": page.get("server", ""),
                                          "result_url": f"https://urlscan.io/result/{task.get('uuid', '')}/"})
                            if det_id: stats["new"] += 1
                        await asyncio.sleep(2)
                    except Exception as e:
                        log.debug(f"URLScan {domain}: {e}")
                await insert_collector_run(db, "urlscan_community", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"URLScan Community: {stats['new']} from {stats['customers']} customers")
    except Exception as e:
        log.error(f"URLScan Community failed: {e}")
        stats["error"] = str(e)
    return stats


# Stub enterprise collectors - ready for key activation
async def collect_cybersixgill():
    if not SIXGILL_ID: return {"skipped": True, "reason": "no CYBERSIXGILL_CLIENT_ID", "new": 0}
    return {"skipped": True, "reason": "enterprise integration pending", "new": 0}

async def collect_recordedfuture():
    if not RF_KEY: return {"skipped": True, "reason": "no RECORDED_FUTURE_KEY", "new": 0}
    return {"skipped": True, "reason": "enterprise integration pending", "new": 0}

async def collect_cyberint():
    if not CYBERINT_KEY: return {"skipped": True, "reason": "no CYBERINT_API_KEY", "new": 0}
    return {"skipped": True, "reason": "enterprise integration pending", "new": 0}

async def collect_flare():
    if not FLARE_KEY: return {"skipped": True, "reason": "no FLARE_API_KEY", "new": 0}
    return {"skipped": True, "reason": "enterprise integration pending", "new": 0}


# ════════════════════════════════════════════════════════════
# ENRICHMENT ENDPOINTS - real lookups
# ════════════════════════════════════════════════════════════

async def enrich_domain(domain: str) -> dict:
    """Real DNS + WHOIS-like enrichment for a domain."""
    result = {"domain": domain, "dns": {}, "whois": {}, "reputation": {}}
    async with httpx.AsyncClient(timeout=10.0) as c:
        # DNS via DNS-over-HTTPS (Cloudflare)
        try:
            resp = await c.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
                              headers={"Accept": "application/dns-json"})
            if resp.status_code == 200:
                data = resp.json()
                result["dns"]["A"] = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
        except: pass
        # MX records
        try:
            resp = await c.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX",
                              headers={"Accept": "application/dns-json"})
            if resp.status_code == 200:
                data = resp.json()
                result["dns"]["MX"] = [a["data"] for a in data.get("Answer", []) if a.get("type") == 15]
        except: pass
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
        except: pass
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
            except: pass
    return result

async def enrich_ip(ip: str) -> dict:
    """Real IP enrichment."""
    result = {"ip": ip, "geo": {}, "reputation": {}, "rdns": ""}
    async with httpx.AsyncClient(timeout=10.0) as c:
        # Reverse DNS
        try:
            resp = await c.get(f"https://cloudflare-dns.com/dns-query?name={ip}&type=PTR",
                              headers={"Accept": "application/dns-json"})
            if resp.status_code == 200:
                data = resp.json()
                ptrs = [a["data"] for a in data.get("Answer", []) if a.get("type") == 12]
                result["rdns"] = ptrs[0] if ptrs else ""
        except: pass
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
            except: pass
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
            except: pass
    return result


# ════════════════════════════════════════════════════════════
# ASSET DISCOVERY - real OSINT for customer domains
# ════════════════════════════════════════════════════════════

async def discover_assets(domain: str) -> dict:
    """Real asset discovery using free OSINT sources."""
    result = {"domain": domain, "subdomains": [], "ips": [], "emails": [], "certs": []}
    async with httpx.AsyncClient(timeout=15.0) as c:
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
        except: pass
        # DNS lookups for found subdomains
        for sub in result["subdomains"][:20]:
            try:
                resp = await c.get(f"https://cloudflare-dns.com/dns-query?name={sub}&type=A",
                    headers={"Accept": "application/dns-json"})
                if resp.status_code == 200:
                    for a in resp.json().get("Answer", []):
                        if a.get("type") == 1:
                            result["ips"].append({"subdomain": sub, "ip": a["data"]})
            except: pass
        # Common email patterns
        result["emails"] = [f"{prefix}@{domain}" for prefix in
            ["security", "admin", "abuse", "info", "support", "hr", "legal", "privacy"]]
    return result


# ════════════════════════════════════════════════════════════
# V16.4.5: NEW HIGH-VALUE FREE COLLECTORS
# ════════════════════════════════════════════════════════════

async def collect_shodan_internetdb():
    """Shodan InternetDB - FREE exposed service scan per customer IP. NO key needed.
    API: https://internetdb.shodan.io/{ip} - returns open ports, CVEs, hostnames.
    Customer-targeted: looks up every customer IP asset.
    """
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "ips_checked": 0, "vulns_found": 0}
    try:
        async with AsyncSessionLocal() as db:
            r = await db.execute(text(
                "SELECT ca.asset_value, ca.customer_id, c.name "
                "FROM customer_assets ca JOIN customers c ON c.id = ca.customer_id "
                "WHERE ca.asset_type = 'ip' AND c.active = true LIMIT 50"
            ))
            ip_assets = r.all()
        if not ip_assets:
            return {"skipped": True, "reason": "no customer IP assets", "new": 0}
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as c:
            async with AsyncSessionLocal() as db:
                for ip_val, cust_id, cust_name in ip_assets:
                    stats["ips_checked"] += 1
                    try:
                        resp = await c.get(f"https://internetdb.shodan.io/{ip_val}")
                        if resp.status_code != 200:
                            continue
                        data = resp.json()
                        ports = data.get("ports", [])
                        cves = data.get("vulns", [])
                        hostnames = data.get("hostnames", [])
                        # Insert open port finding
                        if ports:
                            risky_ports = [p for p in ports if p in (21,22,23,25,110,135,139,445,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017)]
                            if risky_ports:
                                sev = "HIGH" if any(p in (3389,445,23,21) for p in risky_ports) else "MEDIUM"
                                raw = f"Shodan InternetDB: {ip_val} has {len(ports)} open ports. Risky: {risky_ports}. Hostnames: {hostnames[:3]}"
                                await insert_detection(db, "shodan_internetdb", "exposed_service",
                                    f"{ip_val}:ports:{','.join(str(p) for p in risky_ports[:5])}",
                                    sev, 24, raw, confidence=0.90, customer_id=cust_id,
                                    metadata={"ip": ip_val, "ports": ports, "risky_ports": risky_ports,
                                              "hostnames": hostnames, "customer": cust_name})
                                stats["new"] += 1
                            # V16.4.5: Map specific ports to IOC types
                            SERVICE_PORT_MAP = {
                                9200: ("elasticsearch_exposed", "CRITICAL", "Elasticsearch"),
                                5601: ("open_analytics_service", "HIGH", "Kibana"),
                                3000: ("open_analytics_service", "HIGH", "Grafana"),
                                27017: ("exposed_service", "CRITICAL", "MongoDB"),
                                6379: ("exposed_service", "CRITICAL", "Redis"),
                                5432: ("exposed_service", "HIGH", "PostgreSQL"),
                                3306: ("exposed_service", "HIGH", "MySQL"),
                                3389: ("exposed_service", "CRITICAL", "RDP"),
                                445: ("exposed_service", "CRITICAL", "SMB"),
                            }
                            for port in ports:
                                if port in SERVICE_PORT_MAP:
                                    ioc_t, sev_t, svc_name = SERVICE_PORT_MAP[port]
                                    raw = f"Shodan InternetDB: {svc_name} exposed on {ip_val}:{port} ({cust_name})"
                                    await insert_detection(db, "shodan_internetdb", ioc_t,
                                        f"{ip_val}:{port}:{svc_name.lower()}", sev_t, 4 if sev_t == "CRITICAL" else 12,
                                        raw, confidence=0.92, customer_id=cust_id,
                                        metadata={"ip": ip_val, "port": port, "service": svc_name, "customer": cust_name})
                                    stats["new"] += 1
                        # Insert CVE findings for this IP
                        for cve_id in cves[:10]:
                            raw = f"Shodan InternetDB: {ip_val} ({cust_name}) vulnerable to {cve_id}"
                            await insert_detection(db, "shodan_internetdb", "cve_id",
                                cve_id, "CRITICAL", 4, raw, confidence=0.85, customer_id=cust_id,
                                metadata={"ip": ip_val, "customer": cust_name, "source": "shodan_internetdb"})
                            stats["vulns_found"] += 1
                            stats["new"] += 1
                        await asyncio.sleep(0.5)  # Rate limit
                    except Exception as e:
                        log.debug(f"InternetDB {ip_val}: {e}")
                await insert_collector_run(db, "shodan_internetdb", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"Shodan InternetDB: {stats['ips_checked']} IPs checked, {stats['new']} findings, {stats['vulns_found']} CVEs")
    except Exception as e:
        log.error(f"Shodan InternetDB failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_crtsh():
    """crt.sh Certificate Transparency - periodic subdomain discovery.
    FREE, no key. Finds NEW certificates issued since last scan.
    Discovers: shadow IT, dev environments, internal tools with public certs,
    forgotten services, new subdomains the customer may not know about.
    Runs for all active customers with domain assets.
    """
    started = datetime.utcnow()
    stats = {"new_subdomains": 0, "new_detections": 0, "customers": 0, "errors": 0}
    INTERESTING_KEYWORDS = ["admin", "vpn", "api", "staging", "dev", "test", "beta",
                            "internal", "corp", "priv", "login", "sso", "auth", "portal",
                            "jenkins", "gitlab", "grafana", "kibana", "elastic", "mongo",
                            "redis", "phpmyadmin", "wp-admin", "backup", "db", "sql",
                            "ftp", "sftp", "ssh", "rdp", "remote", "jump", "bastion"]
    try:
        async with AsyncSessionLocal() as db:
            r = await db.execute(text(
                "SELECT ca.asset_value, ca.customer_id, c.name "
                "FROM customer_assets ca JOIN customers c ON c.id = ca.customer_id "
                "WHERE ca.asset_type = 'domain' AND c.active = true LIMIT 20"
            ))
            domains = r.all()
        if not domains:
            return {"skipped": True, "reason": "no customer domains", "new": 0}

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as c:
            async with AsyncSessionLocal() as db:
                for domain_val, cust_id, cust_name in domains:
                    stats["customers"] += 1
                    try:
                        resp = await c.get(
                            f"https://crt.sh/?q=%.{domain_val}&output=json",
                            headers={"User-Agent": "ArgusWatch/1.0"}
                        )
                        if resp.status_code != 200:
                            stats["errors"] += 1
                            continue
                        certs = resp.json()
                        # Extract unique subdomains
                        subs = set()
                        for cert in certs[:500]:  # Cap at 500 certs per domain
                            cn = (cert.get("common_name") or "").lower().strip()
                            if cn and domain_val in cn and "*" not in cn and cn != domain_val and "@" not in cn and cn.endswith("." + domain_val):
                                subs.add(cn)
                            for name in (cert.get("name_value") or "").lower().split("\n"):
                                name = name.strip()
                                if name and domain_val in name and "*" not in name and name != domain_val and "@" not in name and name.endswith("." + domain_val):
                                    subs.add(name)

                        # Check which subdomains are NEW (not already in customer_assets)
                        existing = await db.execute(text(
                            "SELECT asset_value FROM customer_assets "
                            "WHERE customer_id = :cid AND asset_type IN ('domain','subdomain')"
                        ), {"cid": cust_id})
                        known = {row[0].lower() for row in existing.all()}

                        new_subs = subs - known
                        for sub in list(new_subs)[:100]:  # Cap at 100 new per customer per run
                            # Register as customer asset
                            is_interesting = any(kw in sub.split('.')[0] for kw in INTERESTING_KEYWORDS)
                            criticality = "high" if is_interesting else "medium"
                            try:
                                await db.execute(text("""
                                    INSERT INTO customer_assets (customer_id, asset_type, asset_value,
                                        criticality, confidence, confidence_sources, discovery_source, created_at)
                                    VALUES (:cid, 'subdomain', :v, :crit, 0.85,
                                        :csrc, 'crtsh_collector', NOW())
                                    ON CONFLICT DO NOTHING
                                """), {"cid": cust_id, "v": sub, "crit": criticality,
                                       "csrc": json.dumps(["crt.sh"])})
                                stats["new_subdomains"] += 1
                            except Exception:
                                pass

                            # Create detection for interesting subdomains
                            if is_interesting:
                                raw = (f"crt.sh: New certificate discovered for {sub} "
                                       f"({cust_name}). This subdomain was not in the asset "
                                       f"inventory. May indicate shadow IT or new service deployment.")
                                await insert_detection(
                                    db, "crtsh", "domain", sub,
                                    "MEDIUM", 48, raw,
                                    confidence=0.85, customer_id=cust_id,
                                    metadata={"customer": cust_name, "domain": domain_val,
                                              "is_interesting": True,
                                              "keywords_matched": [kw for kw in INTERESTING_KEYWORDS if kw in sub]})
                                stats["new_detections"] += 1

                        await db.flush()
                        await asyncio.sleep(3)  # crt.sh rate limit: be polite
                    except Exception as e:
                        log.debug(f"crt.sh {domain_val}: {e}")
                        stats["errors"] += 1
                await insert_collector_run(db, "crtsh", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"crt.sh CT: {stats['customers']} customers, {stats['new_subdomains']} new subs, {stats['new_detections']} detections")
    except Exception as e:
        log.error(f"crt.sh CT collector failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_typosquat():
    """Typosquat domain detector - generates permutations of customer domains, checks DNS.
    FREE, no key. Finds active phishing/typosquat domains targeting customers.
    Techniques: char swap, missing char, double char, homoglyph, tld swap.
    """
    started = datetime.utcnow()
    stats = {"new": 0, "total_permutations": 0, "resolved": 0, "customers": 0}
    HOMOGLYPHS = {'a': ['à','á','â','ã','ä','å','ɑ'], 'e': ['è','é','ê','ë','ē'],
                  'i': ['ì','í','î','ï','ı'], 'o': ['ò','ó','ô','õ','ö','ø','0'],
                  'u': ['ù','ú','û','ü'], 'l': ['1','ĺ'], 's': ['5','ś','$'],
                  'g': ['q','ɡ'], 'n': ['ñ','ń'], 'c': ['ç','ć']}
    ALT_TLDS = ['.net', '.org', '.co', '.io', '.xyz', '.info', '.app', '.dev', '.biz']
    try:
        async with AsyncSessionLocal() as db:
            r = await db.execute(text(
                "SELECT ca.asset_value, ca.customer_id, c.name "
                "FROM customer_assets ca JOIN customers c ON c.id = ca.customer_id "
                "WHERE ca.asset_type = 'domain' AND c.active = true LIMIT 10"
            ))
            domains = r.all()
        if not domains:
            return {"skipped": True, "reason": "no customer domains", "new": 0}
        async with httpx.AsyncClient(timeout=5.0) as c:
            async with AsyncSessionLocal() as db:
                for domain_val, cust_id, cust_name in domains:
                    stats["customers"] += 1
                    name_part = domain_val.split('.')[0]
                    tld = '.' + '.'.join(domain_val.split('.')[1:])
                    permutations = set()
                    # Char swap: gogle.com
                    for i in range(len(name_part)-1):
                        p = list(name_part); p[i], p[i+1] = p[i+1], p[i]
                        permutations.add(''.join(p) + tld)
                    # Missing char: gogle.com
                    for i in range(len(name_part)):
                        permutations.add(name_part[:i] + name_part[i+1:] + tld)
                    # Double char: googgle.com
                    for i in range(len(name_part)):
                        permutations.add(name_part[:i] + name_part[i]*2 + name_part[i+1:] + tld)
                    # Homoglyph: goog1e.com
                    for i, ch in enumerate(name_part):
                        for hg in HOMOGLYPHS.get(ch, [])[:2]:
                            permutations.add(name_part[:i] + hg + name_part[i+1:] + tld)
                    # TLD swap: google.net
                    for alt_tld in ALT_TLDS:
                        if alt_tld != tld:
                            permutations.add(name_part + alt_tld)
                    # Hyphen: goo-gle.com
                    for i in range(1, len(name_part)):
                        permutations.add(name_part[:i] + '-' + name_part[i:] + tld)
                    permutations.discard(domain_val)
                    stats["total_permutations"] += len(permutations)
                    # DNS resolve top candidates
                    for perm in list(permutations)[:30]:
                        try:
                            resp = await c.get(
                                f"https://cloudflare-dns.com/dns-query?name={perm}&type=A",
                                headers={"Accept": "application/dns-json"})
                            if resp.status_code == 200:
                                answers = resp.json().get("Answer", [])
                                if answers:
                                    ip = next((a["data"] for a in answers if a.get("type") == 1), "")
                                    stats["resolved"] += 1
                                    raw = (f"Typosquat ALERT: {perm} resolves to {ip} - "
                                           f"possible phishing domain targeting {cust_name} ({domain_val})")
                                    await insert_detection(db, "typosquat", "domain",
                                        perm, "HIGH", 12, raw, confidence=0.75, customer_id=cust_id,
                                        metadata={"original_domain": domain_val, "typosquat_domain": perm,
                                                  "resolved_ip": ip, "customer": cust_name,
                                                  "technique": "dns_permutation"})
                                    stats["new"] += 1
                            await asyncio.sleep(0.1)
                        except Exception:
                            pass
                await insert_collector_run(db, "typosquat", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"Typosquat: {stats['customers']} customers, {stats['total_permutations']} perms, {stats['resolved']} resolved, {stats['new']} findings")
    except Exception as e:
        log.error(f"Typosquat failed: {e}")
        stats["error"] = str(e)
    return stats


async def collect_epss_top():
    """EPSS Top Exploited CVEs - FREE from FIRST.org. No key needed.
    Fetches CVEs with highest exploitation probability. Cross-refs with customer tech_stack.
    This catches CVEs that CISA KEV hasn't added yet but are actively exploited.
    """
    started = datetime.utcnow()
    stats = {"new": 0, "total": 0, "customer_matches": 0}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
            # Get top 100 CVEs by EPSS score
            resp = await c.get("https://api.first.org/data/v1/epss?order=!epss&limit=100")
            if resp.status_code != 200:
                return {"error": f"EPSS returned {resp.status_code}", "new": 0}
            data = resp.json().get("data", [])
            stats["total"] = len(data)
            async with AsyncSessionLocal() as db:
                # Get tech_stack assets
                r = await db.execute(text(
                    "SELECT ca.asset_value, ca.customer_id, c.name "
                    "FROM customer_assets ca JOIN customers c ON c.id = ca.customer_id "
                    "WHERE ca.asset_type = 'tech_stack' AND c.active = true"
                ))
                tech_assets = r.all()
                # Get product map for matching
                for epss_entry in data:
                    cve_id = epss_entry.get("cve", "")
                    epss_score = float(epss_entry.get("epss", 0))
                    percentile = float(epss_entry.get("percentile", 0))
                    if not cve_id or epss_score < 0.1:
                        continue
                    sev = "CRITICAL" if epss_score >= 0.5 else "HIGH" if epss_score >= 0.2 else "MEDIUM"
                    sla = 4 if sev == "CRITICAL" else 12
                    raw = f"EPSS Top: {cve_id} has {epss_score:.1%} exploitation probability (top {100-percentile*100:.0f}%)"
                    meta = {"epss_score": epss_score, "percentile": percentile, "source": "epss_first_org"}
                    det_id = await insert_detection(db, "epss", "cve_id",
                        cve_id, sev, sla, raw, confidence=min(0.95, 0.5 + epss_score),
                        metadata=meta)
                    if det_id:
                        stats["new"] += 1
                    # Also populate cve_product_map if we can find it in NVD
                    # (The correlation engine will handle matching via existing cve_product_map)
                await insert_collector_run(db, "epss", "completed", stats, started, datetime.utcnow())
                await db.commit()
        log.info(f"EPSS Top: {stats['new']} new from {stats['total']} high-EPSS CVEs")
    except Exception as e:
        log.error(f"EPSS Top failed: {e}")
        stats["error"] = str(e)
    return stats


# ════════════════════════════════════════════════════════════
# FASTAPI APP
# ════════════════════════════════════════════════════════════

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
    # ── v16.4.3: RAW TEXT → PATTERN_MATCHER collectors ──
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
    "crtsh": collect_crtsh,
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
    "telegram":         {"tier": "free",       "name": "Telegram Channels",     "key_env": None,                    "description": "Public threat intel channels  -  IOC + breach mention scanning (Cat 1,9,15)"},
    "crtsh":            {"tier": "free",       "name": "crt.sh CT Logs",        "key_env": None,                    "description": "Certificate Transparency subdomain discovery per customer domain"},
    "hibp_breaches":    {"tier": "free",       "name": "HIBP Breach List",      "key_env": None,                    "description": "Cross-reference customer domains against 700+ known data breaches"},
    "github_code":      {"tier": "key_optional","name": "GitHub Code Search",   "key_env": "GITHUB_TOKEN",          "description": "Search public repos for leaked secrets (AKIA, sk_live_, xoxb-, etc.)"},
    "urlscan_community":{"tier": "free",       "name": "URLScan Community",     "key_env": None,                    "description": "Detect phishing pages and suspicious scans targeting customer domains"},
    "shodan_internetdb": {"tier": "free",      "name": "Shodan InternetDB",     "key_env": None,                    "description": "FREE exposed service + CVE scan per customer IP (no key)"},
    "typosquat":         {"tier": "free",      "name": "Typosquat Detector",    "key_env": None,                    "description": "DNS permutation phishing domain discovery per customer (no key)"},
    "crtsh":             {"tier": "free",      "name": "crt.sh CT Logs",        "key_env": None,                    "description": "FREE Certificate Transparency subdomain discovery per customer (no key)"},
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
    log.info("=" * 55)
    log.info("  Intel Proxy Gateway - Starting")
    log.info("  Collecting REAL threat intel from public feeds...")
    log.info("=" * 55)

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
    async def auto_collect():
        await asyncio.sleep(5)  # Let backend finish migrations
        log.info("  Starting real-time collection from all sources...")
        results = {}
        for name, func in ALL_COLLECTORS.items():
            try:
                r = await func()
                results[name] = r
                new = r.get("new", 0)
                log.info(f"  {'✓' if not r.get('error') else '✗'} {name}: {new} new")
            except Exception as e:
                log.error(f"  ✗ {name}: {e}")
                results[name] = {"error": str(e)}
        total_new = sum(r.get("new", 0) for r in results.values())
        total_err = sum(1 for r in results.values() if r.get("error"))
        log.info("=" * 55)
        log.info(f"  Intel Proxy - Collection complete")
        log.info(f"  {total_new} new IOCs from {len(results)-total_err}/{len(results)} sources")
        log.info("=" * 55)
    asyncio.create_task(auto_collect())
    yield

app = FastAPI(title="ArgusWatch Intel Proxy Gateway", lifespan=lifespan)

@app.post("/settings/key")
async def set_runtime_key(request: Request):
    """Accept API key updates at runtime from backend Settings page.
    Sets os.environ so collectors pick it up on next run.
    Keys are IN-MEMORY only  -  add to .env for persistence."""
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
    async with httpx.AsyncClient(timeout=5.0) as c:
        for name, url in [("cisa", "https://www.cisa.gov"), ("abuse_ch", "https://abuse.ch"), ("github", "https://github.com")]:
            try:
                r = await c.head(url)
                tests[name] = {"ok": True, "status": r.status_code}
            except Exception as e:
                tests[name] = {"ok": False, "error": str(e)[:60]}
    return {"status": "ok", "network": tests, "internet_access": any(t["ok"] for t in tests.values())}

@app.post("/collect/all")
async def collect_all():
    """Trigger all collectors."""
    results = {}
    for name, func in ALL_COLLECTORS.items():
        try:
            results[name] = await func()
        except Exception as e:
            results[name] = {"error": str(e)}
    return {"status": "ok", "results": results}

@app.post("/collect/{collector_name}")
async def collect_one(collector_name: str):
    """Trigger a specific collector."""
    func = ALL_COLLECTORS.get(collector_name)
    if not func:
        return {"error": f"Unknown collector: {collector_name}", "available": list(ALL_COLLECTORS.keys())}
    try:
        return await func()
    except Exception as e:
        return {"error": str(e)}

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
            async with httpx.AsyncClient(timeout=10.0) as c:
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
            async with httpx.AsyncClient(timeout=10.0) as c:
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

    # Step 5: Sourcegraph (any text  -  search public code)
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
            async with httpx.AsyncClient(timeout=10.0) as c:
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
        except: pass
        
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
