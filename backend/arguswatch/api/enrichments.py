"""Enrichment, remediation, playbook, STIX, and CEF/Syslog APIs."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel
from typing import Optional
from arguswatch.database import get_db
from arguswatch.models import Enrichment, RemediationAction, Detection, DetectionStatus
from arguswatch.engine.playbooks import get_all_playbooks, get_playbook, get_playbook_detail, IOC_TO_PLAYBOOK
from arguswatch.engine.stix_exporter import bundle_to_json
from arguswatch.engine.syslog_exporter import send_cef
from arguswatch.services.recheck import schedule_recheck

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


enrich_router = APIRouter(prefix="/api/enrichments", tags=["enrichments"])
remed_router = APIRouter(prefix="/api/remediations", tags=["remediations"])
playbook_router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])
export_router = APIRouter(prefix="/api/export", tags=["export"])

# ── Playbooks ──
@playbook_router.get("/")
async def list_playbooks():
    return get_all_playbooks()

@playbook_router.get("/{ioc_type}")
async def get_playbook_for_ioc(ioc_type: str):
    detail = get_playbook_detail(ioc_type)
    if not detail:
        raise HTTPException(404, f"No playbook for IOC type: {ioc_type}")
    return detail

# ── STIX Export ──
@export_router.get("/stix/{detection_id}")
async def export_stix(detection_id: int, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Detection).where(Detection.id == detection_id))
    d = r.scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Detection not found")
    det_dict = {
        "id": d.id, "ioc_type": d.ioc_type, "ioc_value": d.ioc_value,
        "source": d.source, "severity": _sev(d.severity) or "MEDIUM",
        "confidence": d.confidence, "raw_text": d.raw_text,
        "customer_id": d.customer_id, "matched_asset": d.matched_asset,
        "sla_hours": d.sla_hours,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }
    return {"stix_bundle": bundle_to_json(det_dict), "detection_id": detection_id}

@export_router.post("/cef/{detection_id}")
async def push_cef(detection_id: int, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Detection).where(Detection.id == detection_id))
    d = r.scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Detection not found")
    det_dict = {
        "id": d.id, "ioc_type": d.ioc_type, "ioc_value": d.ioc_value,
        "source": d.source, "severity": _sev(d.severity) or "MEDIUM",
        "confidence": d.confidence, "customer_id": d.customer_id, "sla_hours": d.sla_hours,
    }
    sent = send_cef(det_dict)
    return {"sent": sent, "detection_id": detection_id}

# ── Remediations ──
class RemediationCreate(BaseModel):
    detection_id: int
    action_type: str
    description: Optional[str] = None
    assigned_to: Optional[str] = None

class StatusUpdate(BaseModel):
    status: str  # pending | in_progress | completed | verified

@remed_router.get("/")
async def list_remediations(detection_id: Optional[int] = None, db: AsyncSession = Depends(get_db)):
    q = select(RemediationAction)
    if detection_id:
        q = q.where(RemediationAction.detection_id == detection_id)
    r = await db.execute(q)
    items = r.scalars().all()
    return [{
        "id": a.id, "detection_id": a.detection_id, "action_type": a.action_type,
        "description": a.description, "assigned_to": a.assigned_to,
        "status": a.status, "created_at": a.created_at.isoformat() if a.created_at else None,
        "completed_at": a.completed_at.isoformat() if a.completed_at else None,
    } for a in items]

@remed_router.post("/")
async def create_remediation(req: RemediationCreate, db: AsyncSession = Depends(get_db)):
    # Auto-generate from playbook if action_type == "auto"
    r2 = await db.execute(select(Detection).where(Detection.id == req.detection_id))
    det = r2.scalar_one_or_none()
    if not det:
        raise HTTPException(404, "Detection not found")
    action_type = req.action_type
    description = req.description
    assigned_to = req.assigned_to
    if action_type == "auto" and det:
        pb = get_playbook(det.ioc_type)
        if pb:
            action_type = IOC_TO_PLAYBOOK.get(det.ioc_type, det.ioc_type)
            description = "\n".join(f"{i+1}. {s.step}" for i, s in enumerate(pb.technical_steps))
            assigned_to = assigned_to or pb.assignee_role
    from datetime import datetime, timezone, timedelta
    from arguswatch.engine.severity_scorer import score as score_ioc
    scored = score_ioc(det.ioc_type or "", det.ioc_type or "")
    due_at = datetime.utcnow() + timedelta(hours=scored.sla_hours)
    action = RemediationAction(
        detection_id=req.detection_id, action_type=action_type,
        description=description, assigned_to=assigned_to, status="pending",
    )
    db.add(action)
    await db.flush()
    await db.refresh(action)
    await db.commit()
    return {"id": action.id, "detection_id": action.detection_id, "status": action.status,
            "action_type": action.action_type, "assigned_to": action.assigned_to, "due_at": due_at.isoformat()}

@remed_router.patch("/{action_id}/status")
async def update_remediation_status(action_id: int, req: StatusUpdate, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(RemediationAction).where(RemediationAction.id == action_id))
    action = r.scalar_one_or_none()
    if not action:
        raise HTTPException(404, "Not found")
    from datetime import datetime, timezone
    action.status = req.status
    if req.status == "completed":
        action.completed_at = datetime.utcnow()
        # Trigger 72h re-check
        await schedule_recheck(action.detection_id, action_id)
        # Mark detection as REMEDIATED
        r2 = await db.execute(select(Detection).where(Detection.id == action.detection_id))
        det = r2.scalar_one_or_none()
        if det:
            det.status = DetectionStatus.REMEDIATED
            det.resolved_at = datetime.utcnow()
    await db.flush()
    await db.commit()
    recheck_msg = " 72h re-check scheduled." if req.status == "completed" else ""
    return {"id": action_id, "status": req.status, "message": f"Updated.{recheck_msg}"}
