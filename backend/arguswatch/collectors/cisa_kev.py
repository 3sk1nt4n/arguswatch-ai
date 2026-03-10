"""CISA KEV Collector - fetches Known Exploited Vulnerabilities, stores as CRITICAL detections."""
import httpx, logging
from functools import lru_cache
from sqlalchemy import select, create_engine
from sqlalchemy.orm import sessionmaker
from arguswatch.config import settings
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus, CveProductMap
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new

logger = logging.getLogger("arguswatch.collectors.cisa_kev")


# ── Sync engine for Celery (created once via lru_cache, never leaked) ──
@lru_cache(maxsize=1)
def _sync_engine():
    return create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True, pool_size=5)

@lru_cache(maxsize=1)
def _sync_session_factory():
    return sessionmaker(bind=_sync_engine())


# ── Shared ingest logic ──
def _build_detection(v: dict) -> Detection:
    return Detection(
        source="cisa_kev", ioc_type="cve_id", ioc_value=v.get("cveID", ""),
        raw_text=f"{v.get('vendorProject','')} {v.get('product','')}: {v.get('shortDescription','')}",
        severity=SeverityLevel.CRITICAL, sla_hours=4, status=DetectionStatus.NEW, confidence=1.0,
        metadata_={"vendor": v.get("vendorProject",""), "product": v.get("product",""),
            "description": v.get("shortDescription",""), "date_added": v.get("dateAdded",""),
            "due_date": v.get("dueDate",""), "known_ransomware": v.get("knownRansomwareCampaignUse","Unknown"), "kev": True},
    )


# ── Async path (FastAPI lifespan + manual trigger) ──

async def fetch_kev_json() -> dict:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(settings.CISA_KEV_URL)
        resp.raise_for_status()
        return resp.json()

async def ingest_kev(data: dict) -> dict:
    vulns = data.get("vulnerabilities", [])
    stats = {"total": len(vulns), "new": 0, "skipped": 0}
    async with async_session() as db:
        for v in vulns:
            cve_id = v.get("cveID", "")
            if not cve_id: continue
            existing = await db.execute(select(Detection).where(Detection.ioc_value == cve_id, Detection.source == "cisa_kev"))
            if existing.scalar_one_or_none():
                stats["skipped"] += 1; continue
            db.add(_build_detection(v)); stats["new"] += 1
        await db.commit()
        await trigger_pipeline_for_new(db)
    # Mark matching cve_product_map entries as actively_exploited
    kev_ids = [v.get("cveID", "") for v in data.get("vulnerabilities", []) if v.get("cveID")]
    if kev_ids:
        async with async_session() as db:
            from arguswatch.models import CveProductMap
            from sqlalchemy import update as sql_update
            # Batch update - mark all CPE entries for KEV CVEs as actively exploited
            await db.execute(
                sql_update(CveProductMap)
                .where(CveProductMap.cve_id.in_(kev_ids))
                .values(actively_exploited=True)
            )
            await db.commit()
            logger.info(f"KEV: marked {len(kev_ids)} CVEs as actively_exploited in cve_product_map")

    logger.info(f"KEV ingest: {stats}")
    return stats

async def run_collection() -> dict:
    logger.info("Starting CISA KEV collection...")
    data = await fetch_kev_json()
    return await ingest_kev(data)


# ── Sync path (Celery beat - no event loop conflict, no engine leak) ──

@celery_app.task(name="arguswatch.collectors.cisa_kev.collect_kev", bind=False)
def collect_kev():
    """Sync wrapper for Celery. Engine created once via lru_cache, reused across all task calls."""
    import asyncio
    from datetime import datetime, timezone

    SyncSession = _sync_session_factory()
    logger.info("Starting CISA KEV collection (Celery sync)...")
    resp = httpx.get(settings.CISA_KEV_URL, timeout=30.0)
    resp.raise_for_status()
    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    stats = {"total": len(vulns), "new": 0, "skipped": 0}
    started = datetime.utcnow()
    new_cve_ids = []
    with SyncSession() as db:
        for v in vulns:
            cve_id = v.get("cveID", "")
            if not cve_id: continue
            existing = db.execute(select(Detection).where(Detection.ioc_value == cve_id, Detection.source == "cisa_kev")).scalar_one_or_none()
            if existing:
                stats["skipped"] += 1; continue
            det = _build_detection(v)
            db.add(det)
            db.flush()
            if det.id:
                new_cve_ids.append(det.id)
            stats["new"] += 1
        db.commit()
    # Fire ingest pipeline for each new detection
    if new_cve_ids:
        from arguswatch.services.ingest_pipeline import fire_pipeline
        for det_id in new_cve_ids:
            try:
                fire_pipeline.delay(det_id)
            except Exception as e:
                logger.debug(f"Pipeline trigger skipped: {e}")
        logger.info(f"KEV: queued pipeline for {len(new_cve_ids)} new detections")
    logger.info(f"KEV ingest (sync): {stats}")

    # Record run in collector_runs table
    async def _record():
        from arguswatch.database import async_session
        from arguswatch.models import CollectorRun
        async with async_session() as db:
            db.add(CollectorRun(
                collector_name="kev",
                status="success",
                started_at=started,
                completed_at=datetime.utcnow(),
                stats=stats,
            ))
            await db.commit()
    try:
        asyncio.run(_record())
    except Exception as e:
        logger.debug(f"CollectorRun record failed: {e}")

    return stats
