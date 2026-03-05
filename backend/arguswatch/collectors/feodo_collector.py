"""Feodo Tracker Collector - botnet C2 IP blocklist (free, no key)."""
import httpx, logging
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.feodo")

FEODO_JSON_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

async def run_collection() -> dict:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(FEODO_JSON_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.error(f"Feodo error: {e}"); return {"error": str(e)}
    entries = data if isinstance(data, list) else data.get("blocklist", [])
    stats = {"total": len(entries), "new": 0, "skipped": 0}
    async with async_session() as db:
        for entry in entries:
            ip = entry.get("ip_address", "") if isinstance(entry, dict) else str(entry)
            if not ip: continue
            r = await db.execute(select(Detection).where(Detection.ioc_value == ip, Detection.source == "feodotracker"))
            if r.scalar_one_or_none():
                stats["skipped"] += 1; continue
            malware = entry.get("malware", "Unknown") if isinstance(entry, dict) else "Unknown"
            db.add(Detection(
                source="feodotracker", ioc_type="ipv4", ioc_value=ip,
                raw_text=f"Feodo Tracker C2: {ip} ({malware})",
                severity=SeverityLevel.CRITICAL, sla_hours=4,
                status=DetectionStatus.NEW, confidence=0.95,
                metadata_={"malware": malware, "port": entry.get("port", "") if isinstance(entry, dict) else "",
                           "status": entry.get("status", "") if isinstance(entry, dict) else ""},
            ))
            stats["new"] += 1
        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"Feodo ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.feodo_collector.collect_feodo")
def collect_feodo():
    import asyncio
    async def _wrapped():
        async with record_collector_run("feodo") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
