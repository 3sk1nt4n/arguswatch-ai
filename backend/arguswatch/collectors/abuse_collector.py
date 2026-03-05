"""AbuseIPDB Collector - top 1000 reported IPs (free tier, no key needed for list)."""
import httpx, logging
from functools import lru_cache
from sqlalchemy import select, create_engine
from sqlalchemy.orm import sessionmaker
from arguswatch.config import settings
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.abuse")

# Public blacklist - no API key required
ABUSE_BLACKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

@lru_cache(maxsize=1)
def _sync_engine():
    return create_engine(settings.SYNC_DATABASE_URL, pool_pre_ping=True, pool_size=3)
@lru_cache(maxsize=1)
def _sync_session_factory():
    return sessionmaker(bind=_sync_engine())

async def run_collection() -> dict:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(ABUSE_BLACKLIST_URL)
        resp.raise_for_status()
    ips = [l.strip() for l in resp.text.splitlines() if l.strip() and not l.startswith("#")]
    stats = {"total": len(ips), "new": 0, "skipped": 0}
    async with async_session() as db:
        for ip in ips[:500]:  # cap at 500 per run
            r = await db.execute(select(Detection).where(Detection.ioc_value == ip, Detection.source == "abuse_ch"))
            if r.scalar_one_or_none():
                stats["skipped"] += 1; continue
            db.add(Detection(
                source="abuse_ch", ioc_type="ipv4", ioc_value=ip,
                raw_text=f"Feodo Tracker C2 IP: {ip}",
                severity=SeverityLevel.HIGH, sla_hours=12,
                status=DetectionStatus.NEW, confidence=0.9,
                metadata_={"blocklist": "feodotracker", "category": "c2"},
            ))
            stats["new"] += 1
        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"Abuse ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.abuse_collector.collect_abuse")
def collect_abuse():
    import asyncio
    async def _wrapped():
        async with record_collector_run("feodo_abuse") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
