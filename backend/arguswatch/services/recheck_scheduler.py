"""72h Post-Remediation Re-Check Scheduler.
When a detection is marked REMEDIATED, this service schedules a re-scan
72 hours later. If the same IOC resurfaces, it re-opens with ESCALATION flag.
"""
import logging
from datetime import datetime, timezone, timedelta
from arguswatch.celery_app import celery_app

logger = logging.getLogger("arguswatch.services.recheck")

def schedule_recheck(detection_id: int, customer_id: int, ioc_type: str, ioc_value: str):
    """Schedule a 72h re-check via Celery ETA."""
    eta = datetime.utcnow() + timedelta(hours=72)
    perform_recheck.apply_async(
        kwargs={"detection_id": detection_id, "customer_id": customer_id,
                "ioc_type": ioc_type, "ioc_value": ioc_value},
        eta=eta,
    )
    logger.info(f"72h re-check scheduled for detection {detection_id} at {eta}")

@celery_app.task(name="arguswatch.services.recheck_scheduler.perform_recheck", bind=True, max_retries=2)
def perform_recheck(self, detection_id: int, customer_id: int, ioc_type: str, ioc_value: str):
    """Re-scan IOC at 72h mark. Re-open if still detected."""
    import asyncio
    return asyncio.run(_async_recheck(detection_id, customer_id, ioc_type, ioc_value))

async def _async_recheck(detection_id: int, customer_id: int, ioc_type: str, ioc_value: str):
    from arguswatch.database import async_session
    from arguswatch.models import Detection, DetectionStatus, SeverityLevel
    from sqlalchemy import select, and_
    from arguswatch.engine.pattern_matcher import scan_text

    logger.info(f"72h re-check: detection {detection_id} | {ioc_type}:{ioc_value[:50]}")

    # Check if same IOC has re-appeared in new detections
    async with async_session() as db:
        r = await db.execute(select(Detection).where(
            and_(Detection.ioc_value == ioc_value,
                 Detection.status.in_(["NEW", "ENRICHED"]),
                 Detection.id != detection_id)))
        new_detection = r.scalar_one_or_none()

        r2 = await db.execute(select(Detection).where(Detection.id == detection_id))
        original = r2.scalar_one_or_none()

        if new_detection:
            # IOC has resurfaced - escalate
            if original and original.status == DetectionStatus.REMEDIATED:
                original.status = DetectionStatus.ESCALATION
                meta = original.metadata_ or {}
                meta["recheck_result"] = "ESCALATED"
                meta["recheck_at"] = datetime.utcnow().isoformat()
                meta["recheck_new_detection_id"] = new_detection.id
                original.metadata_ = meta
                logger.warning(f"72h re-check ESCALATED: detection {detection_id} - IOC resurfaced!")
                await db.commit()
                return {"result": "ESCALATED", "detection_id": detection_id,
                        "new_detection_id": new_detection.id}
        else:
            # Clean - mark as Verified Closed
            if original:
                original.status = DetectionStatus.VERIFIED_CLOSED
                meta = original.metadata_ or {}
                meta["recheck_result"] = "VERIFIED_CLOSED"
                meta["recheck_at"] = datetime.utcnow().isoformat()
                original.metadata_ = meta
                await db.commit()
                logger.info(f"72h re-check VERIFIED_CLOSED: detection {detection_id}")
                return {"result": "VERIFIED_CLOSED", "detection_id": detection_id}

    return {"result": "no_change", "detection_id": detection_id}
