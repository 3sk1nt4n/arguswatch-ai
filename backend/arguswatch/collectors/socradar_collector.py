"""SocRadar Free Tier - leak alerts and brand monitoring.
Free tier: brand monitoring, leak detection alerts.
"""
import httpx, logging, asyncio
from arguswatch.config import settings
from arguswatch.database import async_session
from arguswatch.models import Detection, DarkWebMention, SeverityLevel, DetectionStatus, CustomerAsset
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run
from sqlalchemy import select

logger = logging.getLogger("arguswatch.collectors.socradar")

SOCRADAR_BASE = "https://platform.socradar.com/api"

async def run_collection() -> dict:
    stats = {"checked": 0, "new": 0, "skipped": 0}
    api_key = getattr(settings, "SOCRADAR_API_KEY", "") or ""
    if not api_key:
        logger.info("SocRadar: SOCRADAR_API_KEY not set - skipping")
        return {"skipped": "no_key", "note": "Add SOCRADAR_API_KEY to .env"}

    async with async_session() as db:
        r = await db.execute(select(CustomerAsset).where(
            CustomerAsset.asset_type.in_(["domain", "keyword"])))
        assets = r.scalars().all()

        async with httpx.AsyncClient(timeout=20.0) as client:
            for asset in assets[:20]:
                val = asset.asset_value
                stats["checked"] += 1
                try:
                    resp = await client.get(
                        f"{SOCRADAR_BASE}/company/search",
                        params={"q": val, "type": "leak"},
                        headers={"SOCRadar-API-Key": api_key, "User-Agent": "ArgusWatch/8.0"},
                    )
                    if resp.status_code == 401:
                        return {"error": "invalid_socradar_key"}
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                    alerts = data.get("data", data.get("results", []))
                    if isinstance(alerts, dict):
                        alerts = alerts.get("items", [])
                    for alert in alerts[:5]:
                        title = alert.get("title", alert.get("name", "SocRadar alert"))
                        url = alert.get("url", alert.get("source_url", ""))
                        dedup_key = f"socradar:{val}:{title}"[:499]
                        r2 = await db.execute(select(DarkWebMention).where(
                            DarkWebMention.title == dedup_key,
                            DarkWebMention.source == "socradar"))
                        if r2.scalar_one_or_none():
                            stats["skipped"] += 1
                            continue
                        db.add(DarkWebMention(
                            source="socradar", mention_type="leak_alert",
                            title=dedup_key, url=url[:500],
                            customer_id=asset.customer_id,
                            threat_actor="",
                            severity=SeverityLevel.HIGH,
                            metadata_={"search_term": val, "alert_type": alert.get("type", ""),
                                       "date": alert.get("date", "")},
                        ))
                        stats["new"] += 1
                except Exception as e:
                    logger.debug(f"SocRadar error for {val}: {e}")

        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"SocRadar ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.socradar_collector.collect_socradar")
def collect_socradar():
    async def _wrapped():
        async with record_collector_run("socradar") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
