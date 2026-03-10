"""OpenPhish Collector - phishing URLs (free public feed)."""
import httpx, logging
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.openphish")
OPENPHISH_URL = "https://openphish.com/feed.txt"

async def run_collection() -> dict:
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(OPENPHISH_URL)
            resp.raise_for_status()
    except Exception as e:
        logger.error(f"OpenPhish error: {e}"); return {"error": str(e)}
    urls = [l.strip() for l in resp.text.splitlines() if l.strip().startswith("http")]
    stats = {"total": len(urls), "new": 0, "skipped": 0}
    async with async_session() as db:
        for url in urls[:200]:
            r = await db.execute(select(Detection).where(Detection.ioc_value == url, Detection.source == "openphish"))
            if r.scalar_one_or_none():
                stats["skipped"] += 1; continue
            db.add(Detection(
                source="openphish", ioc_type="url", ioc_value=url,
                raw_text=f"OpenPhish phishing URL: {url}",
                severity=SeverityLevel.HIGH, sla_hours=8,
                status=DetectionStatus.NEW, confidence=0.85,
                metadata_={"category": "phishing"},
            ))
            stats["new"] += 1
        await db.commit()
    return stats

@celery_app.task(name="arguswatch.collectors.openphish_collector.collect_openphish")
def collect_openphish():
    import asyncio
    async def _wrapped():
        async with record_collector_run("openphish") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
