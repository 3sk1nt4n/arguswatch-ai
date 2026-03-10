"""Shodan Collector - exposed services on customer IP ranges and domains."""
import httpx, logging
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus, CustomerAsset
from arguswatch.config import settings
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.shodan")

async def shodan_search(query: str, limit: int = 50) -> list[dict]:
    if not settings.SHODAN_API_KEY:
        return []
    url = "https://api.shodan.io/shodan/host/search"
    params = {"key": settings.SHODAN_API_KEY, "query": query, "limit": limit}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url, params=params)
            if r.status_code in (401, 429):
                logger.info(f"Shodan: {r.status_code}")
                return []
            r.raise_for_status()
            return r.json().get("matches", [])
    except Exception as e:
        logger.debug(f"Shodan error: {e}")
        return []

async def run_collection() -> dict:
    stats = {"queries": 0, "new": 0, "skipped": 0}
    # Get all customer domains/IPs to search
    async with async_session() as db:
        r = await db.execute(select(CustomerAsset).where(
            CustomerAsset.asset_type.in_(["domain", "ip", "cidr"])))
        assets = r.scalars().all()
    if not assets:
        return {"status": "no_assets", "note": "Add customer assets to enable Shodan monitoring"}
    for asset in assets[:10]:  # Respect Shodan free tier rate limits
        query = f'hostname:"{asset.asset_value}"' if asset.asset_type.value == "domain" else f'ip:"{asset.asset_value}"'
        matches = await shodan_search(query)
        stats["queries"] += 1
        async with async_session() as db:
            for m in matches:
                ip = m.get("ip_str", "")
                port = m.get("port", "")
                product = m.get("product", "")
                key = f"shodan:{ip}:{port}"
                r = await db.execute(select(Detection).where(Detection.ioc_value == key, Detection.source == "shodan"))
                if r.scalar_one_or_none():
                    stats["skipped"] += 1; continue
                vulns = m.get("vulns", {})
                sev = SeverityLevel.CRITICAL if vulns else SeverityLevel.MEDIUM
                db.add(Detection(
                    source="shodan", ioc_type="exposed_infrastructure", ioc_value=key,
                    raw_text=f"Shodan: {ip}:{port} {product} (asset: {asset.asset_value})",
                    severity=sev, sla_hours=4 if vulns else 48,
                    status=DetectionStatus.NEW, confidence=0.92,
                    customer_id=asset.customer_id, matched_asset=asset.asset_value,
                    metadata_={"ip": ip, "port": port, "product": product,
                               "vulns": list(vulns.keys())[:10], "org": m.get("org", ""),
                               "hostnames": m.get("hostnames", [])},
                ))
                stats["new"] += 1
            await db.commit()
            await trigger_pipeline_for_new(db)
    return stats

@celery_app.task(name="arguswatch.collectors.shodan_collector.collect_shodan")
def collect_shodan():
    import asyncio
    async def _wrapped():
        async with record_collector_run("shodan") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
