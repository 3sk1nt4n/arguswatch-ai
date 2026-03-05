"""ThreatFox (abuse.ch) - IOC feed: IPs, domains, URLs, hashes (free, no key)."""
import httpx, logging, json
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.threatfox")

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

IOC_TYPE_MAP = {
    "ip:port": "ipv4", "domain": "domain", "url": "url",
    "md5_hash": "md5", "sha256_hash": "sha256",
}
CONFIDENCE_MAP = {"100%": 1.0, "75%": 0.75, "50%": 0.5, "25%": 0.25}

async def run_collection() -> dict:
    payload = {"query": "get_iocs", "days": 1}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(THREATFOX_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.error(f"ThreatFox error: {e}"); return {"error": str(e)}
    iocs = data.get("data", []) or []
    stats = {"total": len(iocs), "new": 0, "skipped": 0}
    async with async_session() as db:
        for ioc in iocs:
            val = ioc.get("ioc_value", "")
            if not val: continue
            ioc_type = IOC_TYPE_MAP.get(ioc.get("ioc_type", ""), ioc.get("ioc_type", "unknown"))
            r = await db.execute(select(Detection).where(Detection.ioc_value == val, Detection.source == "threatfox"))
            if r.scalar_one_or_none():
                stats["skipped"] += 1; continue
            conf_str = ioc.get("confidence_level", "75%")
            conf = CONFIDENCE_MAP.get(conf_str, 0.75)
            db.add(Detection(
                source="threatfox", ioc_type=ioc_type, ioc_value=val,
                raw_text=ioc.get("threat_type_desc", ""),
                severity=SeverityLevel.HIGH if conf >= 0.75 else SeverityLevel.MEDIUM,
                sla_hours=24, status=DetectionStatus.NEW, confidence=conf,
                metadata_={"malware": ioc.get("malware", ""), "threat_type": ioc.get("threat_type", ""),
                           "tags": ioc.get("tags", []), "reporter": ioc.get("reporter", "")},
            ))
            stats["new"] += 1
        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"ThreatFox ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.threatfox_collector.collect_threatfox")
def collect_threatfox():
    import asyncio
    async def _wrapped():
        async with record_collector_run("threatfox") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
