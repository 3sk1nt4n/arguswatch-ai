"""
Exposure Scoring - Service Layer
=================================
Thin wrapper around engine/exposure_scorer.py (Option 4 D1-D5 model).
All scoring math lives in the engine. This file handles:
  - DB session management for bulk recalculation
  - Writing results to customer_exposure table
  - Read-only helpers (top_threats, risk_summary, calculate_customer_exposure)

V16.4.1: Rewired from V10 flat scorer to Option 4 D1-D5 engine.
"""
import logging
from datetime import datetime
from sqlalchemy import select, func, and_
from arguswatch.database import async_session
from arguswatch.models import (Customer, ThreatActor, CustomerExposure, Detection, ExposureHistory,
    DarkWebMention, SeverityLevel)
from arguswatch.engine.exposure_scorer import (
    score_customer_actor as _engine_score,
    _dim1_direct_exposure, _dim2_active_exploitation,
    _dim3_actor_intent, _dim4_attack_surface, _dim5_asset_criticality,
)

logger = logging.getLogger("arguswatch.exposure_scorer")


async def score_customer_actor(customer: Customer, actor: ThreatActor, db) -> tuple[float, dict]:
    """Delegate to engine Option 4 scorer. Returns (score, factors) for compat."""
    result = await _engine_score(customer, actor, db)
    return result["score"], result.get("factors", {})


async def calculate_all_exposures() -> dict:
    """Full recalculation for all customer×actor pairs using Option 4 engine."""
    async with async_session() as db:
        cust_r = await db.execute(select(Customer).where(Customer.active == True))
        customers = cust_r.scalars().all()
        actor_r = await db.execute(select(ThreatActor).limit(200))
        actors = actor_r.scalars().all()
        stats = {"pairs_scored": 0, "new": 0, "updated": 0,
                 "critical": 0, "high": 0, "medium": 0, "low": 0}

        for customer in customers:
            for actor in actors:
                result = await _engine_score(customer, actor, db)
                final_score = result["score"]
                factors = result.get("factors", {})
                label = result.get("label", "LOW")

                if final_score < 3:
                    continue

                r = await db.execute(select(CustomerExposure).where(
                    CustomerExposure.customer_id == customer.id,
                    CustomerExposure.actor_id == actor.id,
                ))
                existing = r.scalar_one_or_none()
                if existing:
                    existing.exposure_score = final_score
                    existing.sector_match = "intent_sector_target" in factors
                    existing.detection_count = factors.get("exposure_matched_cves", {}).get("count", 0)
                    existing.darkweb_mentions = 0
                    existing.factor_breakdown = factors
                    existing.last_calculated = datetime.utcnow()
                    stats["updated"] += 1
                else:
                    db.add(CustomerExposure(
                        customer_id=customer.id,
                        actor_id=actor.id,
                        exposure_score=final_score,
                        sector_match="intent_sector_target" in factors,
                        detection_count=factors.get("exposure_matched_cves", {}).get("count", 0),
                        darkweb_mentions=0,
                        factor_breakdown=factors,
                        last_calculated=datetime.utcnow(),
                    ))
                    stats["new"] += 1
                stats[label.lower()] = stats.get(label.lower(), 0) + 1
                stats["pairs_scored"] += 1

        await db.commit()
    
    # Update ExposureHistory with REAL D1-D5 values for each customer
    # (leaderboard + cards read from ExposureHistory, must be fresh)
    async with async_session() as db:
        try:
            from arguswatch.engine.exposure_scorer import (
                _dim1_direct_exposure, _dim2_active_exploitation,
                _dim4_attack_surface, _dim5_asset_criticality,
            )
            cust_r2 = await db.execute(select(Customer).where(Customer.active == True))
            for customer in cust_r2.scalars().all():
                try:
                    d1, _ = await _dim1_direct_exposure(customer.id, db)
                    d2, _ = await _dim2_active_exploitation(customer.id, db)
                    d4, _ = await _dim4_attack_surface(customer.id, db)
                    d5, _ = await _dim5_asset_criticality(customer.id, db)
                    d3 = 0.0
                    # Get max actor D3
                    try:
                        top_r = await db.execute(
                            select(CustomerExposure, ThreatActor)
                            .join(ThreatActor, CustomerExposure.actor_id == ThreatActor.id)
                            .where(CustomerExposure.customer_id == customer.id)
                            .order_by(CustomerExposure.exposure_score.desc()).limit(1))
                        top = top_r.one_or_none()
                        if top:
                            from arguswatch.engine.exposure_scorer import _dim3_actor_intent
                            d3, _ = await _dim3_actor_intent(customer, top.ThreatActor, db)
                    except Exception:
                        pass
                    
                    exposure_base = (d1 * 0.50) + (d2 * 0.30) + (d3 * 0.20)
                    surface_floor = d4 * 0.20
                    base = max(exposure_base, surface_floor)
                    impact = 0.75 + (d4 * 0.00125) + (d5 * 0.00125)
                    final = min(base * impact, 100.0)
                    
                    db.add(ExposureHistory(
                        customer_id=customer.id, snapshot_date=datetime.utcnow(),
                        overall_score=round(final, 1),
                        d1_score=round(d1, 1), d2_score=round(d2, 1),
                        d3_score=round(d3, 1), d4_score=round(d4, 1),
                        d5_score=round(d5, 1),
                    ))
                except Exception:
                    pass
            await db.commit()
        except Exception as e:
            logger.warning(f"ExposureHistory update failed: {e}")
    logger.info(f"Exposure scoring complete (Option 4 engine): {stats}")
    return stats


async def get_customer_top_threats(customer_id: int, limit: int = 10) -> list:
    """Get top threat actors for a customer by exposure score."""
    async with async_session() as db:
        r = await db.execute(
            select(CustomerExposure, ThreatActor)
            .join(ThreatActor, CustomerExposure.actor_id == ThreatActor.id)
            .where(CustomerExposure.customer_id == customer_id)
            .order_by(CustomerExposure.exposure_score.desc())
            .limit(limit)
        )
        rows = r.all()
        return [{
            "actor_id": actor.id,
            "actor_name": actor.name,
            "mitre_id": actor.mitre_id,
            "origin_country": actor.origin_country,
            "exposure_score": exp.exposure_score,
            "sector_match": exp.sector_match,
            "detection_count": exp.detection_count,
            "darkweb_mentions": exp.darkweb_mentions,
            "factor_breakdown": exp.factor_breakdown or {},
            "recency_multiplier": exp.recency_multiplier or 1.0,
            "technique_count": len(actor.techniques or []),
            "target_sectors": (actor.target_sectors or [])[:5],
        } for exp, actor in rows]


async def get_customer_risk_summary(customer_id: int, db) -> dict:
    """Full risk summary for a customer - replaces engine/exposure_scorer version.
    Now includes factor_breakdown and recency_multiplier from V10/V11 scorer.
    Used by /api/exposure/{id} and /api/customers/{id}/risk.
    """
    from sqlalchemy import select, func, and_
    from arguswatch.models import (Customer, CustomerExposure, ThreatActor,
                                    Detection, SeverityLevel)

    r = await db.execute(select(Customer).where(Customer.id == customer_id))
    customer = r.scalar_one_or_none()
    if not customer:
        return {}

    # Top exposures with factor_breakdown
    r2 = await db.execute(
        select(CustomerExposure, ThreatActor)
        .join(ThreatActor, CustomerExposure.actor_id == ThreatActor.id)
        .where(CustomerExposure.customer_id == customer_id)
        .order_by(CustomerExposure.exposure_score.desc())
        .limit(10)
    )
    top_exposures = r2.all()

    # Detection severity counts (open only)
    counts = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        rc = await db.execute(
            select(func.count(Detection.id)).where(
                and_(
                    Detection.customer_id == customer_id,
                    Detection.severity == sev,
                    Detection.status.in_(["NEW", "ENRICHED"]),
                )
            )
        )
        counts[sev] = rc.scalar() or 0

    overall_score = max(
        (e.CustomerExposure.exposure_score for e in top_exposures), default=0.0
    )

    # Fallback: severity-weighted estimate when D1-D5 scorer hasn't run
    if overall_score == 0:
        from arguswatch.models import Finding as _F
        _fc = await db.execute(select(func.count(_F.id)).where(_F.customer_id == customer_id))
        _finding_ct = _fc.scalar() or 0
        if _finding_ct > 0:
            _cc_r = await db.execute(select(func.count(_F.id)).where(_F.customer_id == customer_id, _F.severity == "CRITICAL"))
            _hc_r = await db.execute(select(func.count(_F.id)).where(_F.customer_id == customer_id, _F.severity == "HIGH"))
            _cc_v = _cc_r.scalar() or 0
            _hc_v = _hc_r.scalar() or 0
            overall_score = min(75, _cc_v * 6 + _hc_v * 3 + max(0, _finding_ct - _cc_v - _hc_v) * 0.5)

    # CVSS summary from matched CVE detections
    try:
        from arguswatch.models import CveProductMap
        cvss_r = await db.execute(
            select(
                func.max(Detection.id),  # dummy to enable the join
                func.count(Detection.id).label("cve_count"),
            ).where(
                and_(
                    Detection.customer_id == customer_id,
                    Detection.ioc_type == "cve_id",
                    Detection.status.in_(["NEW", "ENRICHED", "ALERTED"]),
                )
            )
        )
        cve_row = cvss_r.one_or_none()
        cve_count = cve_row[1] if cve_row else 0

        # Get max CVSS from cve_product_map for matched CVEs
        max_cvss = 0.0
        kev_count = 0
        if cve_count > 0:
            cve_dets = await db.execute(
                select(Detection.ioc_value).where(
                    and_(
                        Detection.customer_id == customer_id,
                        Detection.ioc_type == "cve_id",
                    )
                ).limit(100)
            )
            cve_ids = [r[0].upper() for r in cve_dets.all()]
            if cve_ids:
                cpm_r = await db.execute(
                    select(CveProductMap).where(CveProductMap.cve_id.in_(cve_ids))
                )
                cpm_rows = cpm_r.scalars().all()
                for cpm in cpm_rows:
                    if cpm.cvss_score and cpm.cvss_score > max_cvss:
                        max_cvss = cpm.cvss_score
                    if cpm.actively_exploited:
                        kev_count += 1
    except Exception:
        cve_count = 0
        max_cvss = 0.0
        kev_count = 0

    def _label(s):
        if s >= 80: return "CRITICAL"
        if s >= 60: return "HIGH"
        if s >= 40: return "MEDIUM"
        if s > 0:   return "LOW"
        return "NONE"

    return {
        "customer_id": customer_id,
        "customer_name": customer.name,
        "industry": customer.industry,
        "overall_score": round(overall_score, 1),
        "risk_label": _label(overall_score),
        "severity_counts": counts,
        "total_open": sum(counts.values()),
        "cvss_summary": {
            "max_cvss": max_cvss,
            "kev_count": kev_count,
            "total_cves": cve_count,
        },
        "top_actors": [{
            "actor_id": e.ThreatActor.id,
            "actor": e.ThreatActor.name,
            "mitre_id": e.ThreatActor.mitre_id,
            "score": round(e.CustomerExposure.exposure_score, 1),
            "label": _label(e.CustomerExposure.exposure_score),
            "sector_match": e.CustomerExposure.sector_match,
            "recency_multiplier": e.CustomerExposure.recency_multiplier or 1.0,
            "factor_breakdown": e.CustomerExposure.factor_breakdown or {},
        } for e in top_exposures],
    }


async def calculate_customer_exposure(customer_id: int, db) -> dict:
    """Per-customer exposure calculation returning overall + d1-d5 dimension scores.

    V16.4: This function was referenced by tasks.py and main.py but never existed.
    Wraps the 5-dimensional engine scorer to produce snapshot-ready output.

    Returns dict with keys: overall_score, d1_score-d5_score (floats 0-100).
    """
    from sqlalchemy import select
    from arguswatch.models import Customer, CustomerExposure, ThreatActor

    r = await db.execute(select(Customer).where(Customer.id == customer_id))
    customer = r.scalar_one_or_none()
    if not customer:
        return {"overall_score": 0, "d1_score": 0, "d2_score": 0,
                "d3_score": 0, "d4_score": 0, "d5_score": 0}

    # Get top-scoring actor for this customer
    r2 = await db.execute(
        select(CustomerExposure, ThreatActor)
        .join(ThreatActor, CustomerExposure.actor_id == ThreatActor.id)
        .where(CustomerExposure.customer_id == customer_id)
        .order_by(CustomerExposure.exposure_score.desc()).limit(1)
    )
    top = r2.one_or_none()

    if not top:
        return {"overall_score": 0, "d1_score": 0, "d2_score": 0,
                "d3_score": 0, "d4_score": 0, "d5_score": 0}

    overall = top.CustomerExposure.exposure_score or 0.0

    # Run 5-dimensional scorer for dimension breakdown
    d1, d2, d3, d4, d5 = 0.0, 0.0, 0.0, 0.0, 0.0
    try:
        from arguswatch.engine.exposure_scorer import (
            _dim1_direct_exposure, _dim2_active_exploitation,
            _dim3_actor_intent, _dim4_attack_surface, _dim5_asset_criticality,
        )
        d1, _ = await _dim1_direct_exposure(customer_id, db)
        d2, _ = await _dim2_active_exploitation(customer_id, db)
        d3, _ = await _dim3_actor_intent(customer, top.ThreatActor, db)
        d4, _ = await _dim4_attack_surface(customer_id, db)
        d5, _ = await _dim5_asset_criticality(customer_id, db)
    except Exception:
        pass  # Dimensions stay 0 - overall_score still works

    return {
        "overall_score": round(overall, 1),
        "d1_score": round(d1, 1),
        "d2_score": round(d2, 1),
        "d3_score": round(d3, 1),
        "d4_score": round(d4, 1),
        "d5_score": round(d5, 1),
    }
