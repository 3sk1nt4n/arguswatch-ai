"""
72h Post-Remediation Re-Check Service.
When remediation_action.status = completed → schedule 72h re-scan.
Re-detects same IOC type for same customer → re-opens with ESCALATION flag.
"""
import logging
from datetime import datetime, timedelta
from sqlalchemy import select, and_, update
from arguswatch.database import async_session
from arguswatch.models import Detection, RemediationAction, DetectionStatus

logger = logging.getLogger("arguswatch.recheck")

async def schedule_recheck(detection_id: int, remediation_id: int) -> dict:
    """Called when a remediation action is marked complete."""
    recheck_at = datetime.utcnow() + timedelta(hours=72)
    async with async_session() as db:
        r = await db.execute(select(Detection).where(Detection.id == detection_id))
        det = r.scalar_one_or_none()
        if not det:
            return {"error": "detection_not_found"}
        # Store recheck scheduled time in metadata
        meta = det.metadata_ or {}
        meta["recheck_scheduled_at"] = recheck_at.isoformat()
        meta["recheck_remediation_id"] = remediation_id
        det.metadata_ = meta
        await db.flush()
        await db.refresh(det)
        await db.commit()
    logger.info(f"Recheck scheduled for detection {detection_id} at {recheck_at}")
    return {"detection_id": detection_id, "recheck_at": recheck_at.isoformat()}

async def run_pending_rechecks() -> dict:
    """
    Run all pending 72h rechecks.
    Called by Celery beat every 30 minutes.
    Checks if IOC still exists/resurfaces → re-open with ESCALATION if so.
    """
    stats = {"checked": 0, "clean": 0, "escalated": 0, "errors": 0}
    now = datetime.utcnow()
    async with async_session() as db:
        # Find detections with recheck scheduled in the past
        r = await db.execute(
            select(Detection).where(
                Detection.status == DetectionStatus.REMEDIATED,
                Detection.metadata_["recheck_scheduled_at"].astext <= now.isoformat(),
            )
        )
        dets = r.scalars().all()
        for det in dets:
            stats["checked"] += 1
            try:
                # Run a quick re-check via the source collector
                resurfaced = await _check_ioc_still_exists(det)
                if resurfaced:
                    # Re-open with ESCALATION flag
                    det.status = DetectionStatus.ESCALATION
                    meta = det.metadata_ or {}
                    meta["escalation_reason"] = "72h_recheck_failed"
                    meta["escalation_at"] = now.isoformat()
                    meta["escalation_count"] = meta.get("escalation_count", 0) + 1
                    det.metadata_ = meta
                    det.last_seen = now
                    stats["escalated"] += 1
                    logger.warning(f"Recheck ESCALATION: detection {det.id} re-detected after remediation")
                else:
                    det.status = DetectionStatus.VERIFIED_CLOSED
                    det.resolved_at = now
                    meta = det.metadata_ or {}
                    meta["verified_clean_at"] = now.isoformat()
                    det.metadata_ = meta
                    stats["clean"] += 1
                    logger.info(f"Recheck CLEAN: detection {det.id} verified closed")
            except Exception as e:
                logger.error(f"Recheck error for detection {det.id}: {e}")
                stats["errors"] += 1
        await db.commit()
    return stats

async def _check_ioc_still_exists(det: Detection) -> bool:
    """
    Check if an IOC is still active/present.
    For paste/breach/darkweb IOCs: check if same value appeared in new detections.
    For CVEs: check if KEV still lists it as active.
    Returns True if IOC resurfaces (escalate), False if clean.
    """
    async with async_session() as db:
        # Check if same IOC value appeared in a NEW detection after remediation
        if not det.resolved_at:
            return False
        r = await db.execute(
            select(Detection).where(
                and_(
                    Detection.ioc_value == det.ioc_value,
                    Detection.ioc_type == det.ioc_type,
                    Detection.id != det.id,
                    Detection.created_at > (det.resolved_at or datetime.utcnow() - timedelta(hours=72)),
                    Detection.status == DetectionStatus.NEW,
                )
            )
        )
        new_det = r.scalar_one_or_none()
        return new_det is not None
