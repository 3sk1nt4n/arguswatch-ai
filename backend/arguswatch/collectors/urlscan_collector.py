"""URLScan.io Collector - recent scans for phishing/malware (free 1000/day)."""
import httpx, logging
from datetime import datetime, timedelta
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus
from arguswatch.config import settings
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.urlscan")
URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"

async def run_collection() -> dict:
    headers = {"Content-Type": "application/json"}
    if settings.URLSCAN_API_KEY:
        headers["API-Key"] = settings.URLSCAN_API_KEY
    # Search for phishing/malware scans in last 2h
    params = {"q": "verdicts.malicious:true", "size": 100, "sort": "date:desc"}
    try:
        async with httpx.AsyncClient(timeout=20.0, headers=headers) as client:
            resp = await client.get(URLSCAN_SEARCH, params=params)
            if resp.status_code in (429, 401):
                return {"skipped": "rate_limited_or_no_key"}
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.error(f"URLScan error: {e}"); return {"error": str(e)}
    results = data.get("results", [])
    stats = {"total": len(results), "new": 0, "skipped": 0}
    async with async_session() as db:
        for r in results:
            page = r.get("page", {})
            url = page.get("url", "")
            if not url: continue
            r2 = await db.execute(select(Detection).where(Detection.ioc_value == url, Detection.source == "urlscan"))
            if r2.scalar_one_or_none():
                stats["skipped"] += 1; continue
            score = r.get("verdicts", {}).get("overall", {}).get("score", 0)
            db.add(Detection(
                source="urlscan", ioc_type="url", ioc_value=url,
                raw_text=f"URLScan malicious verdict: {url}",
                severity=SeverityLevel.HIGH, sla_hours=12,
                status=DetectionStatus.NEW, confidence=min(score / 100.0, 1.0) if score else 0.8,
                metadata_={"domain": page.get("domain", ""), "ip": page.get("ip", ""),
                           "score": score, "scan_id": r.get("_id", ""),
                           "categories": r.get("verdicts", {}).get("urlscan", {}).get("categories", [])},
            ))
            stats["new"] += 1
        await db.commit()
    return stats

@celery_app.task(name="arguswatch.collectors.urlscan_collector.collect_urlscan")
def collect_urlscan():
    import asyncio
    async def _wrapped():
        async with record_collector_run("urlscan") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
