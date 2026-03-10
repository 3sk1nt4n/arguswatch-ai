"""ArgusWatch Stats Routes -  Extracted from main.py"""
import os
import json
import logging
from typing import Optional
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, case, distinct, desc, text
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

logger = logging.getLogger("arguswatch.api.stats")

router = APIRouter(tags=["stats"])

_write_deps = [Depends(require_role("admin", "analyst"))]
_admin_deps = [Depends(require_role("admin"))]

@router.get("/api/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    sev_counts = {}
    for sev in SeverityLevel:
        r = await db.execute(select(func.count()).where(Detection.severity == sev))
        sev_counts[sev.value] = r.scalar() or 0
    status_counts = {}
    for st in DetectionStatus:
        r = await db.execute(select(func.count()).where(Detection.status == st))
        status_counts[st.value] = r.scalar() or 0
    total = await db.execute(select(func.count(Detection.id)))
    cust_count = await db.execute(select(func.count(Customer.id)))
    actor_count = await db.execute(select(func.count(ThreatActor.id)))
    darkweb_count = await db.execute(select(func.count(DarkWebMention.id)))
    # 24h trend
    since_24h = datetime.utcnow() - timedelta(hours=24)
    new_24h = await db.execute(select(func.count()).where(Detection.created_at >= since_24h))
    # Findings + campaigns counts for dashboard
    from arguswatch.models import Finding, Campaign
    try:
        total_findings = (await db.execute(select(func.count(Finding.id)))).scalar() or 0
        open_findings = (await db.execute(select(func.count(Finding.id)).where(
            Finding.status.in_(["NEW", "ENRICHED", "ALERTED", "ESCALATION"])))).scalar() or 0
        crit_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "CRITICAL"))).scalar() or 0
        high_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "HIGH"))).scalar() or 0
        medium_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "MEDIUM"))).scalar() or 0
        low_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "LOW"))).scalar() or 0
        active_campaigns = (await db.execute(select(func.count(Campaign.id)).where(Campaign.status == "active"))).scalar() or 0
    except Exception as e:
        total_findings = open_findings = crit_findings = high_findings = medium_findings = low_findings = active_campaigns = 0
    _cust = cust_count.scalar() or 0
    _actors = actor_count.scalar() or 0
    # Formula-relevant: assets (D4/D5) and exposure score (formula output)
    asset_count = await db.execute(select(func.count(CustomerAsset.id)))
    _assets = asset_count.scalar() or 0
    max_exp_r = await db.execute(select(func.max(CustomerExposure.exposure_score)))
    _max_exp = round(max_exp_r.scalar() or 0, 1)
    # Noise elimination metric -  what % of IOCs were filtered as irrelevant
    total_det = total.scalar() or 0
    try:
        matched_r = await db.execute(select(func.count(Detection.id)).where(Detection.customer_id.isnot(None)))
        matched = matched_r.scalar() or 0
        unmatched = total_det - matched
        noise_pct = round((unmatched / total_det * 100), 1) if total_det > 0 else 0.0
    except Exception as e:
        matched = 0; unmatched = 0; noise_pct = 0.0
    
    return {
        "total_detections": total_det,
        "severity": sev_counts,
        "status": status_counts,
        "customers": _cust, "total_customers": _cust,
        "threat_actors": _actors, "total_actors": _actors,
        "total_assets": _assets,
        "darkweb_mentions": darkweb_count.scalar() or 0,
        "max_exposure_score": _max_exp,
        "total_findings": total_findings, "open_findings": open_findings,
        "critical_findings": crit_findings, "high_findings": high_findings,
        "medium_findings": medium_findings, "low_findings": low_findings,
        "active_campaigns": active_campaigns,
        "new_24h": new_24h.scalar() or 0,
        "noise_elimination": {
            "total_iocs": total_det,
            "customer_attributed": matched,
            "unmatched_noise": unmatched,
            "noise_pct": noise_pct,
            "signal_pct": round(100 - noise_pct, 1),
        },
    }


@router.get("/api/stats/sources")
async def stats_by_source(db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(Detection.source, func.count(Detection.id).label("count"))
        .group_by(Detection.source).order_by(desc("count"))
    )
    sources = [{**row._mapping} for row in r]
    # Enrich with last_run from CollectorRun
    try:
        cr = await db.execute(
            select(CollectorRun.collector_name, func.max(CollectorRun.completed_at).label("last_run"))
            .group_by(CollectorRun.collector_name)
        )
        run_map = {row.collector_name: row.last_run for row in cr}
        for s in sources:
            lr = run_map.get(s["source"])
            s["last_run"] = lr.isoformat() if lr else None
            s["name"] = s["source"]  # alias for frontend
    except Exception as e:
        for s in sources:
            s["last_run"] = None
            s["name"] = s["source"]
    return sources


@router.get("/api/stats/ioc-types")
async def stats_by_ioc_type(db: AsyncSession = Depends(get_db)):
    r = await db.execute(
        select(Detection.ioc_type, func.count(Detection.id).label("count"))
        .group_by(Detection.ioc_type).order_by(desc("count"))
    )
    return [{"ioc_type": row.ioc_type, "type": row.ioc_type, "count": row.count} for row in r]


@router.get("/api/stats/timeline")
async def detection_timeline(db: AsyncSession = Depends(get_db)):
    days = []
    for i in range(6, -1, -1):
        day_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        r = await db.execute(
            select(func.count()).where(and_(Detection.created_at >= day_start, Detection.created_at < day_end))
        )
        days.append({"date": day_start.strftime("%Y-%m-%d"), "count": r.scalar() or 0})
    return days


@router.get("/api/threat-pressure")
async def get_threat_pressure(db: AsyncSession = Depends(get_db)):
    """Compute global threat pressure index for dashboard gauge.
    Combines finding severity, active campaigns, and 24h velocity."""
    from arguswatch.models import Finding, Campaign
    try:
        crit = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "CRITICAL"))).scalar() or 0
        high = (await db.execute(select(func.count(Finding.id)).where(Finding.severity == "HIGH"))).scalar() or 0
        total_f = (await db.execute(select(func.count(Finding.id)))).scalar() or 0
        active_camps = (await db.execute(select(func.count(Campaign.id)).where(Campaign.status == "active"))).scalar() or 0
        since_24h = datetime.utcnow() - timedelta(hours=24)
        new_24h = (await db.execute(select(func.count(Detection.id)).where(Detection.created_at >= since_24h))).scalar() or 0
        # Pressure formula: weighted severity + campaigns + velocity
        pressure = min(100, int(crit * 12 + high * 5 + active_camps * 8 + min(new_24h, 100) * 0.3))
        if pressure < 20:
            level_text = "LOW"
        elif pressure < 40:
            level_text = "MODERATE"
        elif pressure < 70:
            level_text = "ELEVATED"
        else:
            level_text = "CRITICAL"
        return {
            "pressure_index": pressure,
            "level": pressure,
            "level_text": level_text,
            "summary": f"{crit + high} active threats across monitored landscape",
            "active_threats": crit + high,
            "active_campaigns": active_camps,
            "new_last_24h": new_24h,
            "critical_findings": crit,
            "high_findings": high,
            "total_findings": total_f,
        }
    except Exception as e:
        logger.debug(f"Suppressed: {e}")
        return {"pressure_index": 0, "level": 0, "level_text": "UNKNOWN",
                "summary": "Unable to compute", "active_threats": 0,
                "active_campaigns": 0, "new_last_24h": 0}



@router.get("/api/metrics")
async def get_metrics(db: AsyncSession = Depends(get_db)):
    """Platform health metrics for monitoring dashboards."""
    metrics = {}
    
    # Match rate per customer
    r = await db.execute(text("""
        SELECT c.name, c.id,
            COUNT(CASE WHEN d.customer_id IS NOT NULL THEN 1 END) as matched,
            COUNT(*) as total
        FROM customers c
        LEFT JOIN detections d ON d.customer_id = c.id
        WHERE c.active = true
        GROUP BY c.id, c.name
    """))
    metrics["match_rates"] = [{
        "customer": row[0], "customer_id": row[1],
        "matched": row[2], "total": row[3],
        "rate": round(row[2] / max(row[3], 1) * 100, 1),
    } for row in r.all()]
    
    # Collector health
    r = await db.execute(text("""
        SELECT collector_name,
            MAX(completed_at) as last_run,
            COUNT(CASE WHEN status = 'completed' THEN 1 END) as successes,
            COUNT(CASE WHEN status = 'failed' THEN 1 END) as failures,
            COUNT(*) as total_runs
        FROM collector_runs
        GROUP BY collector_name
        ORDER BY last_run DESC NULLS LAST
    """))
    metrics["collector_health"] = [{
        "collector": row[0],
        "last_run": row[1].isoformat() if row[1] else None,
        "successes": row[2], "failures": row[3], "total": row[4],
        "stale": (datetime.utcnow() - row[1]).total_seconds() > 28800 if row[1] else True,
    } for row in r.all()]
    
    # Detection counts by source
    r = await db.execute(text("""
        SELECT source, COUNT(*) as count,
            COUNT(CASE WHEN customer_id IS NOT NULL THEN 1 END) as matched
        FROM detections
        WHERE created_at > NOW() - INTERVAL '7 days'
        GROUP BY source
        ORDER BY count DESC
    """))
    metrics["detections_by_source"] = [{
        "source": row[0], "count": row[1], "matched": row[2],
        "match_rate": round(row[2] / max(row[1], 1) * 100, 1),
    } for row in r.all()]
    
    # Threat pressure by sector
    from arguswatch.models import GlobalThreatActivity
    gta_r = await db.execute(
        select(GlobalThreatActivity)
        .where(GlobalThreatActivity.activity_level > 0)
        .order_by(GlobalThreatActivity.activity_level.desc())
    )
    metrics["threat_pressure"] = [{
        "category": a.category,
        "malware_family": a.malware_family,
        "activity_level": round(a.activity_level, 1),
        "sectors": a.targeted_sectors,
    } for a in gta_r.scalars().all()]
    
    # Finding counts
    r = await db.execute(text("""
        SELECT severity, COUNT(*) FROM findings
        WHERE status IN ('NEW', 'ENRICHED', 'ALERTED')
        GROUP BY severity
    """))
    metrics["open_findings"] = {row[0]: row[1] for row in r.all()}
    
    # Single-source domination check
    r = await db.execute(text("""
        SELECT source, COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM detections WHERE created_at > NOW() - INTERVAL '24 hours'), 0)
        FROM detections
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY source
        ORDER BY 2 DESC
        LIMIT 5
    """))
    metrics["source_concentration"] = [{
        "source": row[0],
        "percentage": round(float(row[1] or 0), 1),
        "warning": float(row[1] or 0) > 30,
    } for row in r.all()]
    
    return metrics

