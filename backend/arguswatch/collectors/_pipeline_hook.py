"""
Pipeline hook - imported by all collectors.

COLLECTOR PATTERN (unchanged - all existing collectors work without modification):
    db.add(Detection(...))
    ...
    await db.commit()
    await trigger_pipeline_for_new(db)   ← fires pipeline for all new detections

The pipeline itself handles:
    routing → finding merge/create → enrichment → attribution → campaign → exposure → action → dispatch

DEDUPLICATION: Handled in the pipeline at Step 3 (finding_manager.get_or_create_finding).
Collectors do NOT need to call dedup manually. The finding layer absorbs duplicates -
same IOC from two sources becomes one Finding with source_count=2.

The old route_and_dedup_before_commit is kept for backward compat but now just
delegates to the pipeline. Don't use it in new collectors.
"""
import logging
from contextlib import asynccontextmanager
from datetime import datetime

logger = logging.getLogger("arguswatch.collectors.hook")


def trigger_pipeline(detection_id: int):
    """Trigger ingest pipeline for a single detection (fire-and-forget Celery task)."""
    try:
        from arguswatch.services.ingest_pipeline import fire_pipeline
        fire_pipeline(detection_id)
    except Exception as e:
        logger.debug(f"Pipeline trigger skipped (Celery not running): {e}")


async def trigger_pipeline_for_new(db, limit: int = 100):
    """Trigger pipeline for all NEW detections not yet linked to a finding.

    Call after db.commit() in any collector. Fires Celery tasks - non-blocking.
    The pipeline handles routing, dedup (via finding_manager), enrichment, attribution.
    """
    try:
        from arguswatch.models import Detection, DetectionStatus
        from sqlalchemy import select, and_
        from arguswatch.services.ingest_pipeline import fire_pipeline

        # ALL new detections without a finding - not just unrouted ones
        # (Routed detections also need enrichment, attribution, action generation)
        r = await db.execute(
            select(Detection.id)
            .where(
                Detection.status == DetectionStatus.NEW,
                Detection.finding_id == None,
            )
            .order_by(Detection.id.desc())
            .limit(limit)
        )
        ids = [row[0] for row in r.all()]
        for det_id in ids:
            fire_pipeline(det_id)
        if ids:
            logger.debug(f"Pipeline triggered for {len(ids)} new detections")
    except Exception as e:
        logger.debug(f"Batch pipeline trigger skipped: {e}")


async def route_and_dedup_before_commit(detection, db) -> bool:
    """Kept for backward compat. In V11, dedup happens in the pipeline via finding_manager.
    This function still works - routes the detection and returns True (always new at this point).
    The finding layer will handle the actual merge when the pipeline runs.
    """
    try:
        from arguswatch.engine.correlation_engine import route_detection
        await route_detection(detection, db)
    except Exception as e:
        logger.debug(f"Route skipped: {e}")
    return True


@asynccontextmanager
async def record_collector_run(collector_name: str):
    """
    Async context manager - wraps a collector run and writes a CollectorRun
    row to the database. Powers /api/collectors/status.

    Usage in any collector:
        async with record_collector_run("threatfox") as run_ctx:
            stats = await _do_collection()
            run_ctx["stats"] = stats
        return stats
    """
    from arguswatch.database import async_session
    from arguswatch.models import CollectorRun

    run_ctx: dict = {"stats": {}, "error": None}
    started = datetime.utcnow()

    async with async_session() as db:
        run = CollectorRun(
            collector_name=collector_name,
            status="running",
            started_at=started,
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    try:
        yield run_ctx
        status = "success"
    except Exception as exc:
        run_ctx["error"] = str(exc)
        status = "error"
        logger.warning(f"[{collector_name}] run failed: {exc}")
        raise
    finally:
        try:
            async with async_session() as db:
                from sqlalchemy import select
                r = await db.execute(select(CollectorRun).where(CollectorRun.id == run_id))
                run = r.scalar_one_or_none()
                if run:
                    run.status = status
                    run.completed_at = datetime.utcnow()
                    run.stats = run_ctx.get("stats", {})
                    if run_ctx.get("error"):
                        run.error_msg = run_ctx["error"]
                    await db.commit()
        except Exception as e:
            logger.debug(f"CollectorRun finalize error: {e}")
