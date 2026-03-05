from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from arguswatch.database import get_db
from arguswatch.models import Detection, SeverityLevel, DetectionStatus

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


router = APIRouter(prefix="/api/detections", tags=["detections"])

@router.get("/")
async def list_detections(
    limit: int = Query(50, le=500),
    offset: int = 0,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    customer_id: Optional[int] = None,
    ioc_type: Optional[str] = None,
    date: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    filters = []
    if severity:
        try: filters.append(Detection.severity == SeverityLevel(severity))
        except ValueError: pass
    if status:
        try: filters.append(Detection.status == DetectionStatus(status))
        except ValueError: pass
    if source: filters.append(Detection.source == source)
    if customer_id: filters.append(Detection.customer_id == customer_id)
    if ioc_type: filters.append(Detection.ioc_type == ioc_type)
    if date:
        from datetime import datetime as _dt, timedelta
        try:
            d = _dt.fromisoformat(date.replace('Z', '+00:00')) if 'T' in date else _dt.strptime(date, '%Y-%m-%d')
            filters.append(Detection.created_at >= d)
            filters.append(Detection.created_at < d + timedelta(days=1))
        except Exception: pass
    if search: filters.append(Detection.ioc_value.ilike(f"%{search}%"))

    q = select(Detection)
    if filters: q = q.where(and_(*filters))
    count_q = select(func.count(Detection.id))
    if filters: count_q = count_q.where(and_(*filters))
    total_r = await db.execute(count_q)
    total = total_r.scalar() or 0

    q = q.order_by(desc(Detection.created_at)).limit(limit).offset(offset)
    r = await db.execute(q)
    items = r.scalars().all()
    # Batch-load customer names
    det_cust_ids = list({d.customer_id for d in items if d.customer_id})
    det_cust_names = {}
    if det_cust_ids:
        from arguswatch.models import Customer as CustModel
        cnr = await db.execute(select(CustModel.id, CustModel.name).where(CustModel.id.in_(det_cust_ids)))
        det_cust_names = {row.id: row.name for row in cnr.all()}
    return {
        "total": total,
        "items": [{
            "id": d.id, "source": d.source, "ioc_type": d.ioc_type, "ioc_value": d.ioc_value,
            "severity": _sev(d.severity) or None,
            "status": d.status.value if d.status else None,
            "confidence": d.confidence, "customer_id": d.customer_id,
            "customer_name": det_cust_names.get(d.customer_id, ""),
            "matched_asset": d.matched_asset, "sla_hours": d.sla_hours,
            "correlation_type": d.correlation_type,
            "source_count": d.source_count,
            "created_at": d.created_at.isoformat() if d.created_at else None,
            "ai_summary": getattr(d, "ai_summary", None),
            "discovered_at": d.first_seen.isoformat() if d.first_seen else (d.created_at.isoformat() if d.created_at else None),
        } for d in items]
    }

@router.get("/{did}")
async def get_detection(did: int, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Detection).where(Detection.id == did))
    d = r.scalar_one_or_none()
    if not d: raise HTTPException(404, "Not found")
    return {
        "id": d.id, "source": d.source, "ioc_type": d.ioc_type, "ioc_value": d.ioc_value,
        "raw_text": d.raw_text, "severity": _sev(d.severity) or None,
        "status": d.status.value if d.status else None, "confidence": d.confidence,
        "sla_hours": d.sla_hours, "metadata": d.metadata_,
        "created_at": d.created_at.isoformat() if d.created_at else None,
        # V12: full fields for dashboard modal
        "customer_id": d.customer_id,
        "correlation_type": d.correlation_type,
        "source_count": d.source_count,
        "matched_asset": d.matched_asset,
        "finding_id": d.finding_id,
        "first_seen": d.first_seen.isoformat() if d.first_seen else None,
        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
    }

class _StatusBody(BaseModel):
    status: str
    notes: Optional[str] = ""
    assignee: Optional[str] = ""

@router.patch("/{did}/status")
async def update_status(did: int, body: _StatusBody, db: AsyncSession = Depends(get_db)):
    """Accepts JSON body {status, notes?, assignee?} - matches dashboard updDst() call."""
    r = await db.execute(select(Detection).where(Detection.id == did))
    d = r.scalar_one_or_none()
    if not d: raise HTTPException(404, "Not found")
    try: d.status = DetectionStatus(body.status.upper())
    except ValueError: raise HTTPException(400, f"Invalid status: {body.status}")
    await db.flush(); await db.refresh(d)
    return {"id": d.id, "status": d.status.value}
