"""CIRCL MISP + Pulsedive - structured CTI feeds.
CIRCL: Luxembourg CERT curated STIX-format intelligence.
Pulsedive: community threat enrichment with risk scores.
Both free tier.
"""
import httpx, logging, asyncio
from arguswatch.config import settings
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run
from sqlalchemy import select

logger = logging.getLogger("arguswatch.collectors.circl_misp")

CIRCL_FEED = "https://www.circl.lu/doc/misp/feed-osint/hashes.csv"
CIRCL_RECENT = "https://www.circl.lu/doc/misp/feed-osint/"
PULSEDIVE_BASE = "https://pulsedive.com/api"

async def fetch_circl_iocs(client: httpx.AsyncClient) -> list[dict]:
    """Fetch recent IOCs from CIRCL MISP OSINT feed."""
    iocs = []
    try:
        # CIRCL publishes JSON manifests for their MISP feeds
        resp = await client.get(
            "https://www.circl.lu/doc/misp/feed-osint/manifest.json",
            timeout=15.0, headers={"User-Agent": "ArgusWatch/8.0"})
        if resp.status_code == 200:
            manifest = resp.json()
            # Get most recent 5 events
            events = sorted(manifest.items(), key=lambda x: x[1].get("timestamp", 0), reverse=True)[:5]
            for event_id, meta in events:
                try:
                    ev_resp = await client.get(
                        f"https://www.circl.lu/doc/misp/feed-osint/{event_id}.json",
                        timeout=15.0)
                    if ev_resp.status_code != 200:
                        continue
                    event_data = ev_resp.json()
                    event = event_data.get("Event", {})
                    for attr in event.get("Attribute", [])[:20]:
                        atype = attr.get("type", "")
                        value = attr.get("value", "")
                        if not value:
                            continue
                        ioc_type = {
                            "ip-dst": "ipv4", "ip-src": "ipv4",
                            "domain": "domain", "hostname": "domain",
                            "url": "url", "md5": "md5",
                            "sha256": "sha256", "sha1": "sha1",
                            "email-dst": "email",
                        }.get(atype)
                        if ioc_type:
                            iocs.append({
                                "value": value,
                                "type": ioc_type,
                                "comment": attr.get("comment", "")[:200],
                                "event": event.get("info", "")[:100],
                                "source": "circl_misp",
                            })
                except Exception:
                    continue
    except Exception as e:
        logger.debug(f"CIRCL MISP error: {e}")
    return iocs

async def fetch_pulsedive_threats(client: httpx.AsyncClient) -> list[dict]:
    """Fetch recent threats from Pulsedive community feed."""
    api_key = getattr(settings, "PULSEDIVE_API_KEY", "") or ""
    threats = []
    try:
        params = {"list": "threat", "limit": "20", "pretty": "1"}
        if api_key:
            params["key"] = api_key
        resp = await client.get(f"{PULSEDIVE_BASE}/browse.php",
            params=params, timeout=15.0, headers={"User-Agent": "ArgusWatch/8.0"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        for threat in data.get("results", [])[:10]:
            name = threat.get("threat", "")
            risk = threat.get("risk", "medium")
            if name:
                threats.append({
                    "value": f"pulsedive:threat:{name}",
                    "type": "threat_actor_intel",
                    "comment": f"Pulsedive threat: {name} risk={risk}",
                    "event": name,
                    "source": "pulsedive",
                    "risk": risk,
                })
    except Exception as e:
        logger.debug(f"Pulsedive error: {e}")
    return threats

async def run_collection() -> dict:
    stats = {"circl_iocs": 0, "pulsedive_iocs": 0, "new": 0, "skipped": 0}

    async with async_session() as db:
        async with httpx.AsyncClient(timeout=20.0) as client:
            all_iocs = []
            circl_iocs = await fetch_circl_iocs(client)
            all_iocs.extend(circl_iocs)
            stats["circl_iocs"] = len(circl_iocs)

            pulsedive_iocs = await fetch_pulsedive_threats(client)
            all_iocs.extend(pulsedive_iocs)
            stats["pulsedive_iocs"] = len(pulsedive_iocs)

            for ioc in all_iocs:
                val = ioc["value"][:200]
                src = ioc["source"]
                r = await db.execute(select(Detection).where(
                    Detection.ioc_value == val, Detection.source == src))
                if r.scalar_one_or_none():
                    stats["skipped"] += 1
                    continue

                sev = SeverityLevel.MEDIUM
                if ioc.get("risk") in ("critical", "high"):
                    sev = SeverityLevel.HIGH

                db.add(Detection(
                    source=src, ioc_type=ioc["type"],
                    ioc_value=val,
                    raw_text=f"{src}: {ioc['event']} - {ioc['comment']}",
                    severity=sev, sla_hours=48,
                    status=DetectionStatus.NEW, confidence=0.75,
                    metadata_={"event": ioc["event"], "comment": ioc["comment"]},
                ))
                stats["new"] += 1

        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"CIRCL/Pulsedive ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.circl_misp_collector.collect_circl_misp")
def collect_circl_misp():
    async def _wrapped():
        async with record_collector_run("circl_misp") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
