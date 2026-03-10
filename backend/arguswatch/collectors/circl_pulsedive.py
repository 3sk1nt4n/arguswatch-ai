"""CIRCL MISP + Pulsedive Collector.
CIRCL: Luxembourg CERT curated STIX-format threat intelligence (free).
Pulsedive: community threat enrichment with risk scores (free tier).
"""
import httpx, logging, asyncio, json
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus, CustomerAsset, Customer
from arguswatch.config import settings
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.circl_pulsedive")

CIRCL_FEED = "https://www.circl.lu/doc/misp/feed-osint/"
CIRCL_MANIFEST = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
PULSEDIVE_BASE = "https://pulsedive.com/api/explore.php"


async def _fetch_pulsedive_threats(query: str, client: httpx.AsyncClient) -> list[dict]:
    """Pulsedive explore API for threat intelligence on a keyword."""
    key = getattr(settings, "PULSEDIVE_API_KEY", "") or ""
    try:
        params = {
            "q": f'[{"indicator" if "." in query or "/" in query else "threat"}="{query}"]',
            "limit": 20,
            "pretty": 1,
        }
        if key:
            params["key"] = key
        resp = await client.get(PULSEDIVE_BASE, params=params, timeout=15.0,
                                headers={"User-Agent": "ArgusWatch/8.0"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        results = data.get("results", []) or []
        return results[:10]
    except Exception as e:
        logger.debug(f"Pulsedive error for '{query}': {e}")
        return []


async def _fetch_circl_recent(client: httpx.AsyncClient) -> list[dict]:
    """Fetch recent CIRCL OSINT MISP events."""
    try:
        resp = await client.get(CIRCL_MANIFEST, timeout=20.0,
                                headers={"User-Agent": "ArgusWatch/8.0"})
        if resp.status_code != 200:
            return []
        manifest = resp.json()
        # Get 5 most recent events
        events = sorted(manifest.items(), key=lambda x: x[1].get("timestamp", ""), reverse=True)[:5]
        iocs = []
        for event_id, meta in events:
            try:
                event_resp = await client.get(
                    f"https://www.circl.lu/doc/misp/feed-osint/{event_id}.json",
                    timeout=15.0, headers={"User-Agent": "ArgusWatch/8.0"})
                if event_resp.status_code != 200:
                    continue
                event_data = event_resp.json()
                event_info = event_data.get("Event", {})
                attributes = event_info.get("Attribute", [])
                for attr in attributes[:20]:
                    iocs.append({
                        "type": attr.get("type", ""),
                        "value": attr.get("value", ""),
                        "category": attr.get("category", ""),
                        "comment": attr.get("comment", ""),
                        "event_info": event_info.get("info", ""),
                        "timestamp": event_info.get("timestamp", ""),
                    })
            except Exception:
                continue
        return iocs
    except Exception as e:
        logger.warning(f"CIRCL fetch error: {e}")
        return []


# Map MISP types to our IOC types
MISP_TYPE_MAP = {
    "ip-dst": "ipv4",
    "ip-src": "ipv4",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email-src": "email",
    "email-dst": "email",
    "hostname": "domain",
    "filename": "infra_code_leaks",
}


async def run_collection() -> dict:
    stats = {"circl_iocs": 0, "pulsedive_queries": 0, "new": 0, "skipped": 0}

    async with async_session() as db:
        r = await db.execute(select(Customer).where(Customer.active == True))
        customers = r.scalars().all()

        async with httpx.AsyncClient(timeout=25.0) as client:
            # ── CIRCL MISP ── fetch recent OSINT events
            circl_iocs = await _fetch_circl_recent(client)
            stats["circl_iocs"] = len(circl_iocs)

            for ioc in circl_iocs:
                misp_type = ioc.get("type", "")
                ioc_type = MISP_TYPE_MAP.get(misp_type, "")
                value = ioc.get("value", "").strip()
                if not value or not ioc_type:
                    continue

                det_key = f"circl-{hash(value+misp_type)}"
                rd = await db.execute(select(Detection).where(Detection.ioc_value == det_key))
                if rd.scalar_one_or_none():
                    stats["skipped"] += 1
                    continue

                db.add(Detection(
                    source="circl_misp",
                    ioc_type=ioc_type,
                    ioc_value=det_key,
                    customer_id=None,  # Will be routed by pipeline
                    matched_asset=value,
                    raw_text=f"CIRCL MISP: [{ioc.get('category','')}] {value} - {ioc.get('event_info','')[:100]}",
                    severity=SeverityLevel.MEDIUM,
                    sla_hours=24,
                    status=DetectionStatus.NEW,
                    confidence=0.80,
                    metadata_={
                        "misp_type": misp_type,
                        "category": ioc.get("category", ""),
                        "event": ioc.get("event_info", "")[:200],
                        "comment": ioc.get("comment", "")[:200],
                    },
                ))
                stats["new"] += 1

            # ── Pulsedive ── per-customer domain queries
            for customer in customers:
                ra = await db.execute(select(CustomerAsset).where(
                    CustomerAsset.customer_id == customer.id,
                    CustomerAsset.asset_type == "domain"))
                domain_assets = ra.scalars().all()

                for asset in domain_assets[:2]:  # Rate limit
                    domain = asset.asset_value
                    await asyncio.sleep(1)
                    results = await _fetch_pulsedive_threats(domain, client)
                    stats["pulsedive_queries"] += 1

                    for result in results:
                        risk_level = result.get("risk", "none").lower()
                        if risk_level in ("none", "unknown", ""):
                            continue
                        indicator = result.get("indicator", "") or result.get("ioc", "")
                        if not indicator:
                            continue

                        det_key = f"pulsedive-{hash(indicator+domain)}-{customer.id}"
                        rd = await db.execute(select(Detection).where(
                            Detection.ioc_value == det_key))
                        if rd.scalar_one_or_none():
                            stats["skipped"] += 1
                            continue

                        sev_map = {"critical": SeverityLevel.CRITICAL, "high": SeverityLevel.HIGH,
                                   "medium": SeverityLevel.MEDIUM, "low": SeverityLevel.LOW}
                        sev = sev_map.get(risk_level, SeverityLevel.MEDIUM)

                        db.add(Detection(
                            source="pulsedive",
                            ioc_type=result.get("type", "domain"),
                            ioc_value=det_key,
                            customer_id=customer.id,
                            matched_asset=domain,
                            raw_text=f"Pulsedive [{risk_level}]: {indicator} linked to {domain}",
                            severity=sev,
                            sla_hours=24 if sev != SeverityLevel.CRITICAL else 4,
                            status=DetectionStatus.NEW,
                            confidence=0.72,
                            metadata_={
                                "indicator": indicator,
                                "risk": risk_level,
                                "threats": result.get("threats", [])[:3],
                                "feeds": result.get("feeds", [])[:3],
                            },
                        ))
                        stats["new"] += 1

        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"CIRCL/Pulsedive ingest: {stats}")
    return stats


@celery_app.task(name="arguswatch.collectors.circl_pulsedive.collect_circl_pulsedive")
def collect_circl_pulsedive():
    async def _wrapped():
        async with record_collector_run("circl_pulsedive") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
