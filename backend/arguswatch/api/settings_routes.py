"""ArgusWatch Settings Routes -  Extracted from main.py"""
import os
import json
import logging
from typing import Optional
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, case, distinct, desc, text, exists
from pydantic import BaseModel

from arguswatch.database import get_db
from arguswatch.auth import require_role
from arguswatch.config import settings
from arguswatch.models import (
    Detection, Finding, FindingRemediation, FindingSource, Customer, CustomerAsset,
    CustomerExposure, ThreatActor, Campaign, ActorIoc, DarkWebMention,
    Enrichment, SeverityLevel, DetectionStatus, ExposureHistory,
    FPPattern, SectorAdvisory, CollectorRun, GlobalThreatActivity,
    AssetType, CveProductMap,
)
from arguswatch.services.exposure_scorer import calculate_all_exposures, calculate_customer_exposure, get_customer_top_threats, get_customer_risk_summary

logger = logging.getLogger("arguswatch.api.settings")

def _sev(val):
    """Safe severity value extraction - handles both enum and string."""
    if val is None: return None
    return val.value if hasattr(val, 'value') else str(val)


# Pydantic models for request validation
class AgentQuery(BaseModel):
    text: str
    provider: str = "auto"
    conversation_history: list = []

class ToolRequest(BaseModel):
    args: dict = {}


router = APIRouter(tags=["settings"])

_write_deps = [Depends(require_role("admin", "analyst"))]
_admin_deps = [Depends(require_role("admin"))]

@router.get("/api/actor-iocs")
async def list_actor_iocs(actor_id: int = None, ioc_type: str = None,
                           limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List known actor IOCs from the DB-driven attribution table."""
    from arguswatch.models import ActorIoc
    q = select(ActorIoc)
    if actor_id:
        q = q.where(ActorIoc.actor_id == actor_id)
    if ioc_type:
        q = q.where(ActorIoc.ioc_type == ioc_type)
    q = q.limit(limit)
    r = await db.execute(q)
    return [{"id": ai.id, "actor_id": ai.actor_id, "actor_name": ai.actor_name,
             "ioc_type": ai.ioc_type, "ioc_value": ai.ioc_value,
             "ioc_role": ai.ioc_role, "confidence": ai.confidence, "source": ai.source}
            for ai in r.scalars().all()]


@router.post("/api/actor-iocs", dependencies=[Depends(require_role("admin", "analyst"))])
async def create_actor_ioc(
    actor_id: int, ioc_type: str, ioc_value: str,
    ioc_role: str = None, source: str = "manual",
    db: AsyncSession = Depends(get_db),
):
    """Manually add a known actor IOC to the attribution table."""
    from arguswatch.models import ActorIoc, ThreatActor
    r = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))
    actor = r.scalar_one_or_none()
    if not actor:
        raise HTTPException(404, "Actor not found")
    ai = ActorIoc(actor_id=actor_id, actor_name=actor.name,
                  ioc_type=ioc_type, ioc_value=ioc_value,
                  ioc_role=ioc_role, source=source)
    db.add(ai)
    await db.commit()
    return {"id": ai.id, "actor_name": actor.name, "ioc_value": ioc_value}


@router.get("/api/unattributed-intel")
async def unattributed_intel(limit: int = 100, db: AsyncSession = Depends(get_db)):
    """Detections not yet matched to any customer - valuable intel for new customer onboarding.
    When you onboard a new customer, run /api/customers/{cid}/recorrelate to match these."""
    r = await db.execute(
        select(Detection)
        .where(Detection.customer_id == None)
        .order_by(Detection.created_at.desc())
        .limit(limit)
    )
    return [{
        "id": d.id, "ioc_type": d.ioc_type, "ioc_value": d.ioc_value,
        "severity": _sev(d.severity) or None,
        "source": d.source, "confidence": d.confidence,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    } for d in r.scalars().all()]


@router.post("/api/agent/query", dependencies=[Depends(require_role("admin", "analyst"))])
async def agent_query(req: AgentQuery):
    from arguswatch.agent.agent_core import run_agent
    result = await run_agent(req.text, req.provider, req.conversation_history)
    return result

@router.get("/api/settings/ai")
async def get_ai_settings():
    """Return current AI configuration - mode, provider, autonomous status."""
    from arguswatch.config import settings as _s
    from arguswatch.services.ai_pipeline_hooks import _provider, _pipeline_ai_available
    from arguswatch.agent.tools import TOOL_REGISTRY
    tool_count = len(TOOL_REGISTRY)
    rag_available = False
    try:
        import importlib
        importlib.import_module("arguswatch.services.ai_rag_context")
        rag_available = True
    except Exception as e:
        logger.debug(f"Suppressed: {e}")
    prov = _provider()
    return {
        "autonomous": getattr(_s, "AI_AUTONOMOUS", False),
        "provider": prov,
        "active_provider": prov,
        "pipeline_ai_available": _pipeline_ai_available(),
        "anthropic_configured": bool(getattr(_s, "ANTHROPIC_API_KEY", "")),
        "openai_configured": bool(getattr(_s, "OPENAI_API_KEY", "")),
        "google_configured": bool(getattr(_s, "GOOGLE_AI_API_KEY", "")),
        "ollama_url": getattr(_s, "OLLAMA_URL", ""),
        "model": (getattr(_s, "ANTHROPIC_MODEL", "") if getattr(_s, "ANTHROPIC_API_KEY", "")
                  else getattr(_s, "OPENAI_MODEL", "") if getattr(_s, "OPENAI_API_KEY", "")
                  else getattr(_s, "OLLAMA_MODEL", "")),
        "rag_available": rag_available,
        "tool_count": tool_count,
    }


@router.get("/api/agent/tools")
async def list_tools():
    from arguswatch.agent.tools import TOOL_REGISTRY
    return {"tools": list(TOOL_REGISTRY.keys()), "count": len(TOOL_REGISTRY)}

@router.get("/api/agent/providers")
async def agent_provider_health():
    """Check which LLM providers are available right now."""
    from arguswatch.agent.agent_core import check_provider_health
    from arguswatch.config import settings
    from arguswatch.services.ai_pipeline_hooks import _provider, _get_active_provider_from_redis
    health = await check_provider_health()
    active = [k for k, v in health.items() if v == "ok"]
    current = _provider()  # What the pipeline is actually using right now

    # Provider metadata for UI
    provider_meta = {
        "ollama": {
            "status": health.get("ollama", "unknown"),
            "model": settings.OLLAMA_MODEL,
            "has_key": True,  # no key needed
            "label": "Local AI",
            "icon": "llama",
            "is_active": current == "ollama",
        },
        "anthropic": {
            "status": health.get("anthropic", "unknown"),
            "model": settings.ANTHROPIC_MODEL if settings.ANTHROPIC_API_KEY else "",
            "has_key": bool(settings.ANTHROPIC_API_KEY),
            "label": "Claude",
            "icon": "claude",
            "is_active": current == "anthropic",
        },
        "openai": {
            "status": health.get("openai", "unknown"),
            "model": settings.OPENAI_MODEL if settings.OPENAI_API_KEY else "",
            "has_key": bool(settings.OPENAI_API_KEY),
            "label": "GPT",
            "icon": "gpt",
            "is_active": current == "openai",
        },
        "google": {
            "status": health.get("google", "unknown"),
            "model": getattr(settings, "GOOGLE_AI_MODEL", "gemini-2.5-pro") if getattr(settings, "GOOGLE_AI_API_KEY", "") else "",
            "has_key": bool(getattr(settings, "GOOGLE_AI_API_KEY", "")),
            "label": "Gemini",
            "icon": "gemini",
            "is_active": current == "google",
        },
    }

    return {
        "providers": provider_meta,
        "active": active,
        "current": current,  # What pipeline is actually using
        "selected": _get_active_provider_from_redis(),
        "recommended": active[0] if active else "none",
        "pipeline_ai_enabled": len(active) > 0,
    }


@router.post("/api/settings/active-provider", dependencies=_admin_deps)
async def set_active_provider(request: Request):
    """Switch which AI provider the pipeline uses.
    Called by the dashboard AI switcher when user clicks a provider button.
    Body: {"provider": "ollama"|"anthropic"|"openai"|"google"|"auto"}
    """
    from arguswatch.services.ai_pipeline_hooks import _set_active_provider_in_redis, _provider
    body = await request.json()
    prov = body.get("provider", "ollama")
    # Map aliases
    if prov == "local": prov = "ollama"
    if prov == "claude": prov = "anthropic"
    if prov not in ("ollama", "anthropic", "openai", "google", "auto"):
        raise HTTPException(400, f"Invalid provider: {prov}")
    _set_active_provider_in_redis(prov)
    current = _provider()  # What it resolved to after the switch
    return {"selected": prov, "resolved": current, "status": "ok"}

# Individual tool endpoints

@router.post("/api/agent/tools/{tool_name}", dependencies=[Depends(require_role("admin", "analyst"))])
async def call_tool(tool_name: str, req: ToolRequest):
    from arguswatch.agent.tools import TOOL_REGISTRY
    if tool_name not in TOOL_REGISTRY:
        raise HTTPException(404, f"Tool not found: {tool_name}")
    try:
        result = await TOOL_REGISTRY[tool_name](**req.args)
        return result
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/api/exposure/recalculate", dependencies=[Depends(require_role("admin", "analyst"))])
async def recalculate_exposure():
    from arguswatch.services.exposure_scorer import calculate_all_exposures
    result = await calculate_all_exposures()
    return {"status": "ok", "result": result}

@router.get("/api/exposure/customer/{customer_id}")
async def customer_exposure_scores(customer_id: int):
    from arguswatch.services.exposure_scorer import get_customer_top_threats
    threats = await get_customer_top_threats(customer_id, limit=20)
    return {"customer_id": customer_id, "top_threats": threats}

@router.get("/api/exposure/leaderboard")
async def exposure_leaderboard(sector: str = None, db: AsyncSession = Depends(get_db)):
    """Top customers by exposure score. Uses LEFT JOIN so new customers appear too.
    Falls back to ExposureHistory overall_score for customers without per-actor exposure."""
    from arguswatch.models import CustomerExposure, Customer as CustomerModel, ExposureHistory
    from sqlalchemy import case
    
    # Primary: per-actor exposure scores (LEFT JOIN so all customers included)
    q = (
        select(CustomerModel.id, CustomerModel.name, CustomerModel.industry,
               func.coalesce(func.max(CustomerExposure.exposure_score), 0.0).label("max_score"),
               func.count(CustomerExposure.id).label("actor_count"))
        .outerjoin(CustomerExposure, CustomerExposure.customer_id == CustomerModel.id)
        .where(CustomerModel.active == True)
    )
    if sector:
        q = q.where(CustomerModel.industry == sector.lower())
    q = q.group_by(CustomerModel.id, CustomerModel.name, CustomerModel.industry
        ).order_by(desc("max_score")).limit(20)
    r = await db.execute(q)
    results = []
    for row in r:
        score = row.max_score
        d1 = d2 = d3 = d4 = d5 = 0.0
        # Always fetch latest ExposureHistory for D1-D5 + fallback overall score
        eh = await db.execute(
            select(ExposureHistory)
            .where(ExposureHistory.customer_id == row.id)
            .order_by(ExposureHistory.snapshot_date.desc())
            .limit(1)
        )
        eh_row = eh.scalar_one_or_none()
        if eh_row:
            d1 = eh_row.d1_score or 0.0
            d2 = eh_row.d2_score or 0.0
            d3 = eh_row.d3_score or 0.0
            d4 = eh_row.d4_score or 0.0
            d5 = eh_row.d5_score or 0.0
            if score == 0 and eh_row.overall_score:
                score = eh_row.overall_score
        # Fallback: severity-weighted estimate when D1-D5 scorer hasn't run
        if score == 0:
            from arguswatch.models import Finding as FindingModel
            fc_r = await db.execute(select(func.count(FindingModel.id)).where(FindingModel.customer_id == row.id))
            fc = fc_r.scalar() or 0
            if fc > 0:
                cc_r = await db.execute(select(func.count(FindingModel.id)).where(
                    FindingModel.customer_id == row.id, FindingModel.severity == "CRITICAL"))
                hc_r = await db.execute(select(func.count(FindingModel.id)).where(
                    FindingModel.customer_id == row.id, FindingModel.severity == "HIGH"))
                cc = cc_r.scalar() or 0
                hc = hc_r.scalar() or 0
                score = min(75, cc * 6 + hc * 3 + max(0, fc - cc - hc) * 0.5)
        results.append({"id": row.id, "name": row.name, "industry": row.industry,
                        "max_exposure_score": round(score, 1),
                        "actor_count": row.actor_count,
                        "d1": round(d1, 1), "d2": round(d2, 1), "d3": round(d3, 1),
                        "d4": round(d4, 1), "d5": round(d5, 1),
                        "d1_score": round(d1, 1), "d2_score": round(d2, 1),
                        "d3_score": round(d3, 1), "d4_score": round(d4, 1),
                        "d5_score": round(d5, 1)})
    # Re-sort after fallback scores applied
    results.sort(key=lambda x: x["max_exposure_score"], reverse=True)
    return results


@router.get("/api/exposure/customer/{customer_id}/ai-interpretation")
async def exposure_ai_interpretation(customer_id: int, db: AsyncSession = Depends(get_db)):
    """AI interprets the exposure score -  explains what the biggest risk is and what to do about it."""
    from arguswatch.models import ExposureHistory, Customer as CustModel
    from arguswatch.services.ai_pipeline_hooks import hook_ai_exposure_interpretation

    # Get customer
    cr = await db.execute(select(CustModel).where(CustModel.id == customer_id))
    cust = cr.scalar_one_or_none()
    if not cust:
        raise HTTPException(404, "Customer not found")

    # Get latest exposure scores
    eh = await db.execute(
        select(ExposureHistory).where(ExposureHistory.customer_id == customer_id)
        .order_by(ExposureHistory.snapshot_date.desc()).limit(1)
    )
    eh_row = eh.scalar_one_or_none()
    d1 = d2 = d3 = d4 = d5 = overall = 0.0
    if eh_row:
        overall = eh_row.overall_score or 0.0
        d1 = eh_row.d1_score or 0.0
        d2 = eh_row.d2_score or 0.0
        d3 = eh_row.d3_score or 0.0
        d4 = eh_row.d4_score or 0.0
        d5 = eh_row.d5_score or 0.0

    # Get finding counts
    fc_r = await db.execute(select(func.count(Finding.id)).where(Finding.customer_id == customer_id))
    finding_count = fc_r.scalar() or 0
    cc_r = await db.execute(select(func.count(Finding.id)).where(
        Finding.customer_id == customer_id, Finding.severity == SeverityLevel.CRITICAL))
    critical_count = cc_r.scalar() or 0

    # Call AI
    ai_result = await hook_ai_exposure_interpretation(
        customer_name=cust.name,
        industry=cust.industry or "unknown",
        overall_score=overall,
        d1=d1, d2=d2, d3=d3, d4=d4, d5=d5,
        finding_count=finding_count,
        critical_count=critical_count,
    )

    return {
        "customer_id": customer_id,
        "customer_name": cust.name,
        "overall_score": round(overall, 1),
        "d1": round(d1, 1), "d2": round(d2, 1), "d3": round(d3, 1),
        "d4": round(d4, 1), "d5": round(d5, 1),
        "finding_count": finding_count,
        "critical_count": critical_count,
        "ai_interpretation": ai_result.get("interpretation", ""),
        "ai_priority_action": ai_result.get("priority_action", ""),
        "ai_provider": ai_result.get("provider", ""),
        "ai_generated": ai_result.get("ai_generated", False),
    }


@router.get("/api/customers/{cid}/exposure-trend")
async def customer_exposure_trend(cid: int, days: int = 30, db: AsyncSession = Depends(get_db)):
    """Historical exposure trend from daily snapshots. Returns up to {days} data points."""
    from arguswatch.models import ExposureHistory
    
    cutoff = datetime.utcnow() - timedelta(days=days)
    r = await db.execute(
        select(ExposureHistory).where(
            ExposureHistory.customer_id == cid,
            ExposureHistory.snapshot_date >= cutoff,
        ).order_by(ExposureHistory.snapshot_date.asc())
    )
    snapshots = r.scalars().all()
    
    if not snapshots:
        return {
            "customer_id": cid,
            "days": days,
            "data_points": 0,
            "trend": [],
            "note": "No historical data yet. Snapshots are taken daily - check back tomorrow.",
        }
    
    return {
        "customer_id": cid,
        "days": days,
        "data_points": len(snapshots),
        "trend": [{
            "date": s.snapshot_date.strftime("%Y-%m-%d"),
            "overall": s.overall_score,
            "d1": s.d1_score, "d2": s.d2_score, "d3": s.d3_score,
            "d4": s.d4_score, "d5": s.d5_score,
            "detections": s.total_detections,
            "critical": s.critical_count,
        } for s in snapshots],
    }


@router.post("/api/reports/generate/{customer_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def generate_report(customer_id: int, period_days: int = 30):
    from arguswatch.services.pdf_report import generate_pdf_report
    result = await generate_pdf_report(customer_id, period_days)
    if "error" in result:
        raise HTTPException(400, result["error"])
    return result

@router.get("/api/reports/download/{file_name}")
async def download_report(file_name: str):
    from fastapi.responses import FileResponse
    from pathlib import Path
    fpath = Path("/app/reports") / file_name
    if not fpath.exists():
        raise HTTPException(404, "Report not found")
    return FileResponse(str(fpath), media_type="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename={file_name}"})


@router.post("/api/stix/export/{detection_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def export_stix(detection_id: int, db: AsyncSession = Depends(get_db)):
    from arguswatch.engine.stix_exporter import export_detection_to_stix
    r = await db.execute(select(Detection).where(Detection.id == detection_id))
    d = r.scalar_one_or_none()
    if not d: raise HTTPException(404, "Detection not found")
    bundle = export_detection_to_stix(d)
    return bundle


@router.get("/api/attribution/cve/{cve_id}")
async def cve_attribution(cve_id: str, db: AsyncSession = Depends(get_db)):
    from arguswatch.engine.attribution_engine import CVE_ACTOR_MAP
    actors = CVE_ACTOR_MAP.get(cve_id.upper(), [])
    if not actors:
        return {"cve_id": cve_id, "actors": [], "message": "No known actor attribution"}
    r = await db.execute(
        select(ThreatActor).where(ThreatActor.name.in_(actors))
    )
    found = r.scalars().all()
    return {
        "cve_id": cve_id,
        "actor_names": actors,
        "actors": [{"id": a.id, "name": a.name, "mitre_id": a.mitre_id,
                    "origin_country": a.origin_country, "technique_count": len(a.techniques or [])}
                   for a in found]
    }

@router.post("/api/attribution/enrich-detection/{detection_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def enrich_detection_attribution(detection_id: int, db: AsyncSession = Depends(get_db)):
    from arguswatch.engine.attribution_engine import attribute_detection_by_id
    result = await attribute_detection_by_id(detection_id, db)
    return result


@router.get("/api/customers/{customer_id}/risk")
async def get_customer_risk(customer_id: int, db: AsyncSession = Depends(get_db)):
    from arguswatch.services.exposure_scorer import get_customer_risk_summary
    return await get_customer_risk_summary(customer_id, db)


@router.get("/api/customers/{cid}/exposure-breakdown")
async def customer_exposure_breakdown(cid: int, db: AsyncSession = Depends(get_db)):
    """Live D1-D5 exposure breakdown with step-by-step calculation."""
    from arguswatch.models import Customer, CustomerExposure, ThreatActor, ExposureHistory, Finding
    
    r = await db.execute(select(Customer).where(Customer.id == cid))
    customer = r.scalar_one_or_none()
    if not customer:
        raise HTTPException(404, "Customer not found")
    
    # Severity counts
    sev_r = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.customer_id == cid).group_by(Finding.severity)
    )
    sev_counts = {(s.value if hasattr(s, 'value') else str(s)): c for s, c in sev_r.all() if s}
    
    det_count = (await db.execute(
        select(func.count(Detection.id)).where(Detection.customer_id == cid)
    )).scalar() or 0
    asset_count = (await db.execute(
        select(func.count(CustomerAsset.id)).where(CustomerAsset.customer_id == cid)
    )).scalar() or 0
    
    d1, d2, d3, d4, d5 = 0.0, 0.0, 0.0, 0.0, 0.0
    f1, f2, f3, f4, f5 = {}, {}, {}, {}, {}
    try:
        from arguswatch.engine.exposure_scorer import (
            _dim1_direct_exposure, _dim2_active_exploitation,
            _dim3_actor_intent, _dim4_attack_surface, _dim5_asset_criticality,
        )
        d1, f1 = await _dim1_direct_exposure(cid, db)
        d2, f2 = await _dim2_active_exploitation(cid, db)
        d4, f4 = await _dim4_attack_surface(cid, db)
        d5, f5 = await _dim5_asset_criticality(cid, db)
        top_r = await db.execute(
            select(CustomerExposure, ThreatActor)
            .join(ThreatActor, CustomerExposure.actor_id == ThreatActor.id)
            .where(CustomerExposure.customer_id == cid)
            .order_by(CustomerExposure.exposure_score.desc()).limit(1)
        )
        top = top_r.one_or_none()
        if top:
            d3, f3 = await _dim3_actor_intent(customer, top.ThreatActor, db)
    except Exception as e:
        pass
    
    eh_r = await db.execute(
        select(ExposureHistory).where(ExposureHistory.customer_id == cid)
        .order_by(ExposureHistory.snapshot_date.desc()).limit(1)
    )
    eh = eh_r.scalar_one_or_none()
    if eh and eh.overall_score and d1 == 0 and d2 == 0:
        d1, d2, d3, d4, d5 = eh.d1_score, eh.d2_score, eh.d3_score, eh.d4_score, eh.d5_score
    
    exposure_base = (d1 * 0.50) + (d2 * 0.30) + (d3 * 0.20)
    surface_floor = d4 * 0.20
    base = max(exposure_base, surface_floor)
    impact_modifier = 0.75 + (d4 * 0.00125) + (d5 * 0.00125)
    final = min(base * impact_modifier, 100.0)
    stored_score = eh.overall_score if eh else None
    # Live D1-D5 calculation is authoritative -  no stale overrides
    
    def _clean_factors(fdict):
        out = {}
        for k, v in fdict.items():
            if isinstance(v, dict):
                out[k] = {kk: (vv if not hasattr(vv, '__dict__') else str(vv)) for kk, vv in v.items()}
            else:
                out[k] = v
        return out
    
    # Live D1-D5 calculation is authoritative - update stored score to match
    try:
        from arguswatch.services.exposure_scorer import calculate_customer_exposure
        await calculate_customer_exposure(cid, db)
        await db.commit()
    except Exception:
        pass  # non-critical
    
    return {
        "customer": customer.name, "final_score": round(final, 1),
        "label": "CRITICAL" if final >= 80 else "HIGH" if final >= 60 else "MEDIUM" if final >= 40 else "LOW",
        "dimensions": {
            "d1": {"name": "Direct Exposure", "score": round(d1, 1), "weight": "50%", "weighted": round(d1 * 0.50, 1), "factors": _clean_factors(f1)},
            "d2": {"name": "Active Exploitation", "score": round(d2, 1), "weight": "30%", "weighted": round(d2 * 0.30, 1), "factors": _clean_factors(f2)},
            "d3": {"name": "Actor Intent", "score": round(d3, 1), "weight": "20%", "weighted": round(d3 * 0.20, 1), "factors": _clean_factors(f3)},
            "d4": {"name": "Attack Surface", "score": round(d4, 1), "weight": "floor", "weighted": round(d4 * 0.20, 1), "factors": _clean_factors(f4)},
            "d5": {"name": "Asset Criticality", "score": round(d5, 1), "weight": "impact", "weighted": round(d5 * 0.00125, 3), "factors": _clean_factors(f5)},
        },
        "steps": {
            "exposure_base": round(exposure_base, 1), "surface_floor": round(surface_floor, 1),
            "base": round(base, 1), "impact_modifier": round(impact_modifier, 3), "final": round(final, 1),
        },
        "context": {"detections": det_count, "findings_by_severity": sev_counts, "assets": asset_count},
    }


@router.post("/api/attribution/run", dependencies=[Depends(require_role("admin", "analyst"))])
async def run_attribution(db: AsyncSession = Depends(get_db)):
    from arguswatch.engine.attribution_engine import run_attribution_pass
    return await run_attribution_pass(db)


@router.post("/api/correlate", dependencies=[Depends(require_role("admin", "analyst"))])
async def run_correlation(db: AsyncSession = Depends(get_db)):
    from arguswatch.engine.correlation_engine import correlate_new_detections
    return await correlate_new_detections(db)


@router.post("/api/export/stix", dependencies=[Depends(require_role("admin", "analyst"))])
async def export_stix_bulk():
    """V10: Renamed from export_stix to avoid duplicate route function name."""
    from arguswatch.engine.stix_exporter import export_all_to_stix
    return await export_all_to_stix()

@router.post("/api/export/siem", dependencies=[Depends(require_role("admin", "analyst"))])
async def export_siem():
    from arguswatch.engine.syslog_exporter import send_recent_to_siem
    return await send_recent_to_siem()


@router.post("/api/customers/{cid}/discover", dependencies=[Depends(require_role("admin", "analyst"))])
async def discover_assets(cid: int, request: Request):
    """Upload asset discovery file. Accepts CSV, JSON, BIND zone, DHCP, CT log, agent bundle.
    Query param: ?type=auto|csv|json|bind_zone|dhcp_lease|ct_log|agent_bundle
    Body: raw file content."""
    from arguswatch.services.asset_discovery import (
        parse_csv_import, parse_json_import, parse_bind_zone,
        parse_dhcp_leases, parse_ct_log, parse_agent_bundle,
        ingest_assets, AGENT_SCHEMA,
    )
    from arguswatch.models import Customer, CustomerAsset
    from arguswatch.database import async_session
    from sqlalchemy import select

    # Verify customer exists
    async with async_session() as db:
        r = await db.execute(select(Customer).where(Customer.id == cid))
        cust = r.scalar_one_or_none()
        if not cust:
            from fastapi import HTTPException
            raise HTTPException(404, "Customer not found")
        customer_domain = ""
        # Get primary domain from existing assets
        ar = await db.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == cid,
                CustomerAsset.asset_type == "domain",
            ).limit(1)
        )
        da = ar.scalar_one_or_none()
        if da:
            customer_domain = da.asset_value

    body = await request.body()
    content = body.decode("utf-8", errors="replace")
    file_type = request.query_params.get("type", "auto")

    # Auto-detect file type
    if file_type == "auto":
        stripped = content.strip()
        if stripped.startswith("[") or stripped.startswith("{"):
            # Could be JSON, CT log, or agent bundle
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict) and "agent_id" in parsed:
                    file_type = "agent_bundle"
                elif isinstance(parsed, dict) and any(k in parsed for k in ("common_name", "name_value")):
                    file_type = "ct_log"
                elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                    if "common_name" in parsed[0] or "name_value" in parsed[0]:
                        file_type = "ct_log"
                    else:
                        file_type = "json"
                else:
                    file_type = "json"
            except json.JSONDecodeError:
                file_type = "csv"
        elif stripped.startswith("$ORIGIN") or stripped.startswith("$TTL") or "\tIN\t" in stripped:
            file_type = "bind_zone"
        elif "lease " in stripped and "{" in stripped:
            file_type = "dhcp_lease"
        else:
            file_type = "csv"

    # Parse based on detected type
    records = []
    metadata = {}
    if file_type == "csv":
        records = parse_csv_import(content)
    elif file_type == "json":
        records = parse_json_import(content)
    elif file_type == "bind_zone":
        records = parse_bind_zone(content, customer_domain=customer_domain)
    elif file_type == "dhcp_lease":
        records = parse_dhcp_leases(content)
    elif file_type == "ct_log":
        customer_domains = [customer_domain] if customer_domain else []
        records = parse_ct_log(content, customer_domains=customer_domains)
    elif file_type == "agent_bundle":
        from arguswatch.config import settings
        signing_key = getattr(settings, "AGENT_SIGNING_KEY", "")
        records, metadata = parse_agent_bundle(content, signing_key=signing_key)
    else:
        return {"error": f"Unknown file_type: {file_type}"}

    if not records:
        return {"parsed": 0, "added": 0, "file_type": file_type,
                "message": "No valid asset records found in uploaded file"}

    # Ingest into DB
    result = await ingest_assets(cid, records)
    result["file_type"] = file_type
    if metadata:
        result["agent_metadata"] = metadata
    return result


@router.get("/api/discovery/agent-schema")
async def get_agent_schema():
    """Return the canonical agent telemetry bundle schema."""
    from arguswatch.services.asset_discovery import AGENT_SCHEMA
    return AGENT_SCHEMA


@router.get("/api/discovery/providers")
async def list_discovery_providers():
    """Return available discovery providers and their configuration status."""
    from arguswatch.services.discovery_providers import get_configured_providers
    return {"providers": get_configured_providers()}


@router.post("/api/customers/{cid}/discover/external", dependencies=[Depends(require_role("admin", "analyst"))])
async def discover_external(cid: int, provider: str = ""):
    """Smart asset discovery for a customer.
    1. Auto-infers domain from customer name if no domain asset exists
    2. Adds the domain asset automatically
    3. Runs offline discovery (always works, no network needed)
    4. Tries online OSINT if network available (bonus)
    5. Auto-advances onboarding state
    """
    from arguswatch.services.asset_discovery import AssetRecord, ingest_assets
    from arguswatch.services.osint_discovery import run_osint_discovery
    from arguswatch.models import Customer, CustomerAsset, AssetType
    from arguswatch.database import async_session
    from sqlalchemy import select
    from datetime import datetime, timezone as _dt

    async with async_session() as db:
        r = await db.execute(select(Customer).where(Customer.id == cid))
        cust = r.scalar_one_or_none()
        if not cust:
            raise HTTPException(404, "Customer not found")

        # Check for existing domain asset
        ar = await db.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == cid,
                CustomerAsset.asset_type == "domain",
            ).limit(1)
        )
        domain_asset = ar.scalar_one_or_none()

        # Auto-infer domain from customer name if none exists
        if not domain_asset:
            # Smart domain inference: "Paypal" -> "paypal.com", "Amazon Web Services" -> "aws.amazon.com"
            name_lower = (cust.name or "").strip().lower()
            # Common company -> domain mappings
            known_domains = {
                "paypal": "paypal.com", "amazon": "amazon.com", "google": "google.com",
                "microsoft": "microsoft.com", "apple": "apple.com", "meta": "meta.com",
                "facebook": "facebook.com", "netflix": "netflix.com", "tesla": "tesla.com",
                "twitter": "twitter.com", "x": "x.com", "github": "github.com",
                "stripe": "stripe.com", "shopify": "shopify.com", "adobe": "adobe.com",
                "oracle": "oracle.com", "ibm": "ibm.com", "cisco": "cisco.com",
                "intel": "intel.com", "nvidia": "nvidia.com", "uber": "uber.com",
                "airbnb": "airbnb.com", "slack": "slack.com", "zoom": "zoom.us",
                "salesforce": "salesforce.com", "twilio": "twilio.com",
                "cloudflare": "cloudflare.com", "crowdstrike": "crowdstrike.com",
                "paloalto": "paloaltonetworks.com", "fortinet": "fortinet.com",
                "solvent": "solventcyber.com", "solvent cybersecurity": "solventcyber.com",
            }
            domain = known_domains.get(name_lower)
            if not domain:
                # Fallback: derive from name - take first word, add .com
                slug = name_lower.split()[0].replace(" ", "")
                # If email exists, extract domain from it
                if cust.email and "@" in cust.email:
                    domain = cust.email.split("@")[1]
                else:
                    domain = slug + ".com"

            # Auto-create the domain asset
            db.add(CustomerAsset(
                customer_id=cid,
                asset_type=AssetType.DOMAIN,
                asset_value=domain,
                criticality="critical",
                confidence=0.9,
                confidence_sources=["auto_inferred"],
                discovery_source="auto_infer",
            ))
            await db.commit()
        else:
            domain = domain_asset.asset_value

    # Run OSINT discovery (handles network failure gracefully with offline fallback)
    raw = await run_osint_discovery(domain, customer_name=cust.name)

    # Convert to AssetRecords and ingest
    records = []
    for item in raw:
        if isinstance(item, dict) and "error" not in item:
            records.append(AssetRecord(
                asset_type=item.get("asset_type", "subdomain"),
                asset_value=item.get("asset_value", ""),
                criticality=item.get("criticality", "medium"),
                confidence=item.get("confidence", 0.5),
                source=f"osint_discovery",
            ))

    if not records:
        return {"added": 0, "domain": domain, "message": "No new assets discovered"}

    result = await ingest_assets(cid, records)
    result["domain"] = domain

    # Auto-advance onboarding if assets were added
    if result.get("added", 0) > 0:
        async with async_session() as db:
            cr = await db.execute(select(Customer).where(Customer.id == cid))
            cu = cr.scalar_one_or_none()
            if cu and cu.onboarding_state in ("created", None):
                cu.onboarding_state = "assets_added"
                cu.onboarding_updated_at = _dt.utcnow()
                await db.commit()

    return result



@router.get("/api/sector/advisories")
async def list_sector_advisories(
    status: str = "active", limit: int = 20, db: AsyncSession = Depends(get_db)
):
    """List sector advisories - cross-customer threat intelligence."""
    from arguswatch.models import SectorAdvisory
    q = select(SectorAdvisory).order_by(SectorAdvisory.created_at.desc()).limit(limit)
    if status:
        q = q.where(SectorAdvisory.status == status)
    r = await db.execute(q)
    return [{
        "id": a.id, "ioc_value": a.ioc_value, "ioc_type": a.ioc_type,
        "affected_customer_count": a.affected_customer_count,
        "affected_industries": a.affected_industries,
        "severity": _sev(a.severity) or "HIGH",
        "classification": a.classification, "ai_narrative": a.ai_narrative,
        "ai_recommended_actions": a.ai_recommended_actions, "status": a.status,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    } for a in r.scalars().all()]

@router.post("/api/sector/detect-now", dependencies=[Depends(require_role("admin", "analyst"))])
async def trigger_sector_detection(db: AsyncSession = Depends(get_db)):
    """Manually trigger cross-customer sector detection."""
    from arguswatch.engine.sector_detection import detect_sector_campaigns
    result = await detect_sector_campaigns(db, hours=48)
    await db.commit()
    return result


@router.post("/api/darkweb/triage-now", dependencies=[Depends(require_role("admin", "analyst"))])
async def trigger_darkweb_triage(db: AsyncSession = Depends(get_db)):
    """Manually trigger dark web mention triage."""
    from arguswatch.engine.darkweb_triage import triage_untriaged_mentions
    result = await triage_untriaged_mentions(db, limit=50)
    await db.commit()
    return result

@router.get("/api/darkweb/triage-stats")
async def darkweb_triage_stats(db: AsyncSession = Depends(get_db)):
    """Dark web triage statistics."""
    from arguswatch.models import DarkWebMention
    from sqlalchemy import func as _fn
    total = (await db.execute(select(_fn.count(DarkWebMention.id)))).scalar() or 0
    triaged = (await db.execute(
        select(_fn.count(DarkWebMention.id)).where(DarkWebMention.triaged_at.isnot(None))
    )).scalar() or 0
    return {"total_mentions": total, "triaged": triaged, "pending_triage": total - triaged}

@router.get("/api/customers/{customer_id}/narrative")
async def get_exposure_narrative(customer_id: int, db: AsyncSession = Depends(get_db)):
    """AI-generated exposure narrative for a customer."""
    from arguswatch.models import CustomerExposure
    r = await db.execute(
        select(CustomerExposure).where(CustomerExposure.customer_id == customer_id)
        .order_by(CustomerExposure.exposure_score.desc()).limit(1)
    )
    exp = r.scalar_one_or_none()
    if not exp:
        return {"narrative": None, "score": 0}
    return {
        "narrative": exp.score_narrative,
        "score": round(exp.exposure_score, 1),
        "last_calculated": exp.last_calculated.isoformat() if exp.last_calculated else None,
    }

@router.post("/api/settings/ai-keys", dependencies=_admin_deps)
async def set_ai_keys(request: Request):
    """Set API keys at runtime -  AI providers AND collector keys.
    AI keys: set in backend memory (instant effect).
    Collector keys: forwarded to intel-proxy as env vars + persisted to .env file.
    
    Accepts: {provider: "shodan", api_key: "xxx"} 
         or: {anthropic: "sk-...", openai: "sk-..."} (legacy format)
    """
    from arguswatch.config import settings
    body = await request.json()
    updated = []
    
    # ── Legacy format: {anthropic: "sk-...", openai: "sk-..."}
    if "anthropic" in body and body["anthropic"]:
        settings.ANTHROPIC_API_KEY = body["anthropic"].strip()
        updated.append("anthropic")
    if "openai" in body and body["openai"]:
        settings.OPENAI_API_KEY = body["openai"].strip()
        updated.append("openai")
    if "google" in body and body["google"]:
        settings.GOOGLE_AI_API_KEY = body["google"].strip()
        updated.append("google")
    
    # ── New format: {provider: "shodan", api_key: "xxx"}
    provider = body.get("provider", "")
    api_key = body.get("api_key", "").strip()
    
    if provider and api_key:
        # Map UI ids to env var names
        KEY_MAP = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_AI_API_KEY",
            "shodan": "SHODAN_API_KEY",
            "virustotal": "VIRUSTOTAL_API_KEY",
            "hibp": "HIBP_API_KEY",
            "otx": "OTX_API_KEY",
            "urlscan": "URLSCAN_API_KEY",
            "censys": "CENSYS_API_ID",
            "intelx": "INTELX_API_KEY",
            "greynoise": "GREYNOISE_API_KEY",
            "binaryedge": "BINARYEDGE_API_KEY",
            "leakcheck": "LEAKCHECK_API_KEY",
            "spycloud": "SPYCLOUD_API_KEY",
            "recordedfuture": "RECORDED_FUTURE_KEY",
            "crowdstrike": "CROWDSTRIKE_CLIENT_ID",
            "mandiant": "MANDIANT_API_KEY",
            "flare": "FLARE_API_KEY",
            "cyberint": "CYBERINT_API_KEY",
            "socradar": "SOCRADAR_API_KEY",
            "grayhatwarfare": "GRAYHATWARFARE_API_KEY",
            "leakix": "LEAKIX_API_KEY",
            "github": "GITHUB_TOKEN",
            "pulsedive": "PULSEDIVE_API_KEY",
            "hudsonrock": "HUDSON_ROCK_API_KEY",
        }
        env_var = KEY_MAP.get(provider)
        if env_var:
            # Set in backend memory
            if hasattr(settings, env_var):
                setattr(settings, env_var, api_key)
            os.environ[env_var] = api_key
            
            # Forward to intel-proxy (where collectors actually run)
            import httpx
            proxy_url = os.environ.get("INTEL_PROXY_URL", "http://intel-proxy:9000")
            try:
                async with httpx.AsyncClient(timeout=10.0) as c:
                    await c.post(f"{proxy_url}/settings/key",
                        json={"key": env_var, "value": api_key})
            except Exception as e:
                logger.debug(f"Suppressed: {e}")  # Intel-proxy may not have /settings/key yet
            
            # Also set AI provider settings specifically
            if provider == "anthropic":
                settings.ANTHROPIC_API_KEY = api_key
            elif provider == "openai":
                settings.OPENAI_API_KEY = api_key
            elif provider == "google":
                settings.GOOGLE_AI_API_KEY = api_key
            
            updated.append(provider)

    # Verify AI provider health
    from arguswatch.agent.agent_core import check_provider_health
    health = await check_provider_health()
    active = [k for k, v in health.items() if v == "ok"]

    # Auto-switch pipeline to the newly connected AI provider
    ai_providers = {"anthropic", "openai", "google"}
    if updated and updated[0] in active and updated[0] in ai_providers:
        from arguswatch.services.ai_pipeline_hooks import _set_active_provider_in_redis
        _set_active_provider_in_redis(updated[0])

    return {
        "updated": updated,
        "providers": health,
        "active": active,
        "recommended": active[0] if active else "ollama",
        "note": "Keys are active now. For persistence across restarts, also add to .env file.",
    }


@router.delete("/api/settings/ai-keys/{provider}", dependencies=_admin_deps)
async def remove_ai_key(provider: str):
    """Remove an AI provider API key at runtime. Auto-switches back to Local AI."""
    from arguswatch.config import settings
    if provider == "anthropic":
        settings.ANTHROPIC_API_KEY = ""
    elif provider == "openai":
        settings.OPENAI_API_KEY = ""
    elif provider == "google":
        settings.GOOGLE_AI_API_KEY = ""
    else:
        raise HTTPException(400, f"Unknown provider: {provider}")

    # Switch back to ollama
    from arguswatch.services.ai_pipeline_hooks import _set_active_provider_in_redis
    _set_active_provider_in_redis("ollama")

    from arguswatch.agent.agent_core import check_provider_health
    health = await check_provider_health()
    active = [k for k, v in health.items() if v == "ok"]
    return {"removed": provider, "providers": health, "active": active, "switched_to": "ollama"}


@router.get("/api/agent/status")
async def agent_status(db: AsyncSession = Depends(get_db)):
    """Full agentic AI system status."""
    from arguswatch.models import FPPattern, SectorAdvisory, DarkWebMention, CustomerExposure
    from sqlalchemy import func as _fn
    from arguswatch.services.ai_pipeline_hooks import _pipeline_ai_available
    fp_count = (await db.execute(select(_fn.count(FPPattern.id)))).scalar() or 0
    fp_hits = (await db.execute(select(_fn.sum(FPPattern.hit_count)))).scalar() or 0
    advisories = (await db.execute(
        select(_fn.count(SectorAdvisory.id)).where(SectorAdvisory.status == "active")
    )).scalar() or 0
    dw_triaged = (await db.execute(
        select(_fn.count(DarkWebMention.id)).where(DarkWebMention.triaged_at.isnot(None))
    )).scalar() or 0
    narratives = (await db.execute(
        select(_fn.count(CustomerExposure.id)).where(CustomerExposure.score_narrative.isnot(None))
    )).scalar() or 0
    return {
        "ai_available": _pipeline_ai_available(),
        "agents": {
            "fp_memory": {"status": "active", "patterns_learned": fp_count, "detections_auto_closed": fp_hits or 0},
            "darkweb_triage": {"status": "active", "mentions_triaged": dw_triaged, "schedule": "every 30 min"},
            "sector_detection": {"status": "active", "active_advisories": advisories, "schedule": "every 6 hours"},
            "exposure_narrative": {"status": "active", "narratives_generated": narratives},
            "campaign_killchain": {"status": "active", "description": "AI kill chain analysis on campaign creation"},
            "attribution_fallback": {"status": "active", "description": "AI reasoning when rules return nothing"},
            "raw_text_triage": {"status": "active", "description": "Raw source text fed to AI triage"},
        },
    }


