"""VX-Underground - malware source, threat actor profiles, campaign docs.
Zero auth. Scrapes public threat actor and malware intelligence.
Not in IAMPilot free tier - ArgusWatch advantage.
"""
import httpx, logging, asyncio
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run
from arguswatch.engine.pattern_matcher import scan_text
from sqlalchemy import select

logger = logging.getLogger("arguswatch.collectors.vxunderground")

VXU_BASE = "https://vx-underground.org"
FEEDS = [
    "https://vx-underground.org/APTs",
    "https://vx-underground.org/Samples",
]

async def run_collection() -> dict:
    stats = {"pages": 0, "iocs": 0, "new": 0, "skipped": 0}

    async with async_session() as db:
        async with httpx.AsyncClient(timeout=20.0,
                headers={"User-Agent": "ArgusWatch/8.0 (threat intel)"}) as client:
            # Scrape APT pages for IOCs
            try:
                resp = await client.get(f"{VXU_BASE}/APTs", timeout=15.0)
                if resp.status_code == 200:
                    stats["pages"] += 1
                    text = resp.text[:50000]  # Cap text size
                    matches = scan_text(text)
                    for m in matches[:30]:
                        if m.category not in ("file_hash_iocs", "network_iocs", "threat_actor_intel"):
                            continue
                        ioc_val = m.value[:200]
                        r = await db.execute(select(Detection).where(
                            Detection.ioc_value == ioc_val, Detection.source == "vxunderground"))
                        if r.scalar_one_or_none():
                            stats["skipped"] += 1
                            continue
                        stats["iocs"] += 1
                        db.add(Detection(
                            source="vxunderground",
                            ioc_type=m.ioc_type,
                            ioc_value=ioc_val,
                            raw_text=m.context[:500],
                            severity=SeverityLevel.MEDIUM, sla_hours=48,
                            status=DetectionStatus.NEW, confidence=m.confidence,
                            metadata_={"category": m.category, "page": "APTs"},
                        ))
                        stats["new"] += 1
            except Exception as e:
                logger.debug(f"VX-Underground error: {e}")

        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"VX-Underground ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.vxunderground_collector.collect_vxunderground")
def collect_vxunderground():
    async def _wrapped():
        async with record_collector_run("vxunderground") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
