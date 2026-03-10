"""Hudson Rock Cavalier - free stealer log lookup.
Free tier: per-email, per-domain lookups. Finds Raccoon/RedLine/Vidar victims.
"""
import httpx, logging, asyncio
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus, CustomerAsset
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run
from sqlalchemy import select

logger = logging.getLogger("arguswatch.collectors.hudsonrock")

CAVALIER_BASE = "https://cavalier.hudsonrock.com/api/json/v2"

async def run_collection() -> dict:
    stats = {"checked": 0, "stealers_found": 0, "new": 0, "skipped": 0}

    async with async_session() as db:
        r = await db.execute(select(CustomerAsset).where(
            CustomerAsset.asset_type.in_(["email", "domain"])))
        assets = r.scalars().all()

        async with httpx.AsyncClient(timeout=20.0) as client:
            for asset in assets[:50]:
                val = asset.asset_value
                stats["checked"] += 1
                try:
                    if asset.asset_type == "domain":
                        resp = await client.get(f"{CAVALIER_BASE}/osint-tools/search-by-domain",
                            params={"domain": val}, headers={"User-Agent": "ArgusWatch/7.0"})
                    else:
                        resp = await client.get(f"{CAVALIER_BASE}/osint-tools/search-by-email",
                            params={"email": val}, headers={"User-Agent": "ArgusWatch/7.0"})
                    if resp.status_code == 429:
                        logger.info("Hudson Rock: rate limited"); break
                    if resp.status_code not in (200, 201): continue
                    data = resp.json()
                except Exception as e:
                    logger.warning(f"Hudson Rock {val}: {e}"); continue

                employees = data.get("employees", data.get("stealers", []))
                if not employees: continue

                for victim in employees[:5]:
                    computer_name = victim.get("computer_name","")
                    stealer = victim.get("stealer_family", victim.get("malware_path","unknown"))
                    date_compromised = victim.get("date_compromised","")
                    ioc_val = f"hudsonrock:{val}:{computer_name}"[:200]
                    r2 = await db.execute(select(Detection).where(
                        Detection.ioc_value == ioc_val, Detection.source == "hudsonrock"))
                    if r2.scalar_one_or_none():
                        stats["skipped"] += 1; continue
                    stats["stealers_found"] += 1
                    db.add(Detection(
                        source="hudsonrock", ioc_type="session_auth_tokens",
                        ioc_value=ioc_val, customer_id=asset.customer_id,
                        matched_asset=val,
                        raw_text=f"Hudson Rock: {val} victim on {computer_name} ({stealer})",
                        severity=SeverityLevel.CRITICAL, sla_hours=4,
                        status=DetectionStatus.NEW, confidence=0.90,
                        metadata_={"stealer_family": stealer, "computer_name": computer_name,
                                   "date_compromised": date_compromised,
                                   "credentials_count": victim.get("credentials", 0),
                                   "free_tier": True},
                    ))
                    stats["new"] += 1

        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"Hudson Rock ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.hudsonrock_collector.collect_hudsonrock")
def collect_hudsonrock():
    async def _wrapped():
        async with record_collector_run("hudsonrock") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
