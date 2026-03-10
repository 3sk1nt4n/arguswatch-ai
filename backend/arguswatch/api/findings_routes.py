"""ArgusWatch Findings Routes -  Extracted from main.py"""
import os
import json
import logging
from typing import Optional
from datetime import datetime, timezone
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

logger = logging.getLogger("arguswatch.api.findings")

def _sev(val):
    """Safe severity value extraction - handles both enum and string."""
    if val is None: return None
    return val.value if hasattr(val, 'value') else str(val)

router = APIRouter(tags=["findings"])

_write_deps = [Depends(require_role("admin", "analyst"))]
_admin_deps = [Depends(require_role("admin"))]

@router.get("/api/escalation/overdue")
async def get_overdue(db: AsyncSession = Depends(get_db)):
    """Level 1 escalation: remediations past SLA."""
    from arguswatch.models import RemediationAction
    from datetime import datetime, timezone
    r = await db.execute(
        select(RemediationAction).where(RemediationAction.status == "pending")
    )
    overdue = []
    now = datetime.utcnow()
    for action in r.scalars().all():
        if action.created_at:
            from arguswatch.engine.severity_scorer import score as score_ioc
            # Get detection to know SLA
            try:
                det_r = await db.execute(select(Detection).where(Detection.id == action.detection_id))
                det = det_r.scalar_one_or_none()
                sla_hours = det.sla_hours if det else 72
                elapsed_h = (now - action.created_at).total_seconds() / 3600
                if elapsed_h > sla_hours:
                    overdue.append({
                        "action_id": action.id, "detection_id": action.detection_id,
                        "elapsed_hours": round(elapsed_h, 1), "sla_hours": sla_hours,
                        "assigned_to": action.assigned_to, "action_type": action.action_type,
                    })
            except Exception as e: continue
    return {"overdue_count": len(overdue), "items": overdue[:50]}



@router.get("/api/findings")
async def list_findings(
    severity: str = None,
    status: str = None,
    customer_id: int = None,
    actor_id: int = None,
    campaign_id: int = None,
    has_action: bool = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List findings with full filter support. Primary analyst view."""
    from arguswatch.models import Finding, FindingRemediation
    q = select(Finding)
    if severity:
        q = q.where(Finding.severity == severity.upper())
    if status:
        q = q.where(Finding.status == status.upper())
    if customer_id:
        q = q.where(Finding.customer_id == customer_id)
    if actor_id:
        q = q.where(Finding.actor_id == actor_id)
    if campaign_id:
        q = q.where(Finding.campaign_id == campaign_id)
    if has_action is True:
        q = q.where(exists().where(FindingRemediation.finding_id == Finding.id))
    q = q.order_by(Finding.created_at.desc()).limit(limit).offset(offset)
    r = await db.execute(q)
    findings = r.scalars().all()
    
    # Batch-load customer names to avoid N+1
    cust_ids = list({f.customer_id for f in findings if f.customer_id})
    cust_names = {}
    if cust_ids:
        cr = await db.execute(select(Customer.id, Customer.name).where(Customer.id.in_(cust_ids)))
        cust_names = {row.id: row.name for row in cr.all()}
    
    result = []
    for f in findings:
        result.append({
            "id": f.id, "ioc_type": f.ioc_type, "ioc_value": f.ioc_value,
            "severity": _sev(f.severity) or None,
            "status": f.status.value if f.status else None,
            "customer_id": f.customer_id,
            "customer_name": cust_names.get(f.customer_id, ""),
            "actor_name": f.actor_name,
            "campaign_id": f.campaign_id, "source_count": f.source_count,
            "source": f.all_sources[0] if f.all_sources else None,
            "all_sources": f.all_sources, "confidence": f.confidence,
            "correlation_type": f.correlation_type,
            "match_strategy": f.correlation_type,
            "matched_asset": f.matched_asset,
            "sla_deadline": f.sla_deadline.isoformat() if f.sla_deadline else None,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "ai_narrative": getattr(f, "ai_narrative", None),
            "ai_severity_decision": getattr(f, "ai_severity_decision", None),
            "ai_false_positive_flag": getattr(f, "ai_false_positive_flag", False),
        })
    return result


@router.get("/api/findings/{finding_id}")
async def get_finding(finding_id: int, db: AsyncSession = Depends(get_db)):
    """Full finding detail including sources, remediations, attribution."""
    from arguswatch.models import Finding, FindingSource, FindingRemediation, ThreatActor, Campaign
    r = await db.execute(select(Finding).where(Finding.id == finding_id))
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404, "Finding not found")
    # Sources
    rs = await db.execute(select(FindingSource).where(FindingSource.finding_id == finding_id))
    sources = [{"source": s.source, "detection_id": s.detection_id,
                "contributed_at": s.contributed_at.isoformat() if s.contributed_at else None}
               for s in rs.scalars().all()]
    # Remediations
    rr = await db.execute(select(FindingRemediation).where(FindingRemediation.finding_id == finding_id))
    remediations = []
    for rem in rr.scalars().all():
        remediations.append({
            "id": rem.id, "playbook_key": rem.playbook_key, "title": rem.title,
            "action_type": rem.action_type, "status": rem.status,
            "assigned_to": rem.assigned_to, "assigned_role": rem.assigned_role,
            "deadline": rem.deadline.isoformat() if rem.deadline else None,
            "sla_hours": rem.sla_hours,
            "steps_technical": rem.steps_technical,
            "steps_governance": rem.steps_governance,
            "evidence_required": rem.evidence_required,
        })
    # Actor
    actor = None
    if f.actor_id:
        ra = await db.execute(select(ThreatActor).where(ThreatActor.id == f.actor_id))
        a = ra.scalar_one_or_none()
        if a:
            actor = {"id": a.id, "name": a.name, "mitre_id": a.mitre_id,
                     "origin_country": a.origin_country}
    # Campaign
    campaign = None
    if f.campaign_id:
        rc = await db.execute(select(Campaign).where(Campaign.id == f.campaign_id))
        c = rc.scalar_one_or_none()
        if c:
            campaign = {"id": c.id, "name": c.name, "kill_chain_stage": c.kill_chain_stage,
                        "finding_count": c.finding_count, "status": c.status,
                        "severity": _sev(c.severity) or None}

    # ═══ PROOF CHAIN: CVE -> affected products (from NVD CPE data) ═══
    affected_products = []
    if f.ioc_type == "cve_id" and f.ioc_value:
        from arguswatch.models import CveProductMap
        cpe_r = await db.execute(
            select(CveProductMap).where(CveProductMap.cve_id == f.ioc_value).limit(10)
        )
        for cpe in cpe_r.scalars().all():
            affected_products.append({
                "product": cpe.product_name,
                "vendor": cpe.vendor,
                "version_range": cpe.version_range,
                "cvss_score": cpe.cvss_score,
                "severity": cpe.severity,
                "actively_exploited": cpe.actively_exploited,
                "source": cpe.source or "nvd",
            })

    # ═══ PROOF CHAIN: Asset discovery source ═══
    asset_proof = None
    if f.matched_asset and f.customer_id:
        from arguswatch.models import CustomerAsset
        asset_r = await db.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == f.customer_id,
                CustomerAsset.asset_value == f.matched_asset,
            ).limit(1)
        )
        asset = asset_r.scalar_one_or_none()
        if asset:
            # Determine real discovery source - NEVER return null/unknown
            ds = asset.discovery_source
            if not ds or ds == 'unknown' or ds == 'null':
                at = asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type)
                if at in ('domain', 'email_domain'):
                    ds = 'onboarding'
                elif at == 'tech_stack':
                    ds = 'industry_default'
                elif at in ('brand_name', 'keyword'):
                    ds = 'auto_from_name'
                elif at in ('ip', 'cidr', 'subdomain'):
                    ds = 'recon'
                elif at == 'github_org':
                    ds = 'manual_entry'
                else:
                    ds = 'onboarding'
                # Fix it in DB too so it never happens again
                try:
                    asset.discovery_source = ds
                    await db.commit()
                except Exception as e:
                    logger.debug(f"Suppressed: {e}")
            asset_proof = {
                "asset_value": asset.asset_value,
                "asset_type": asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type),
                "discovery_source": ds,
                "confidence": asset.confidence,
                "confidence_sources": asset.confidence_sources or [],
                "manual_entry": getattr(asset, "manual_entry", False),
                "ioc_hit_count": asset.ioc_hit_count or 0,
                "last_seen_in_ioc": asset.last_seen_in_ioc.isoformat() if asset.last_seen_in_ioc else None,
                "created_at": asset.created_at.isoformat() if asset.created_at else None,
                "criticality": asset.criticality,
            }

    return {
        "id": f.id, "ioc_type": f.ioc_type, "ioc_value": f.ioc_value,
        "severity": _sev(f.severity) or None,
        "status": f.status.value if f.status else None,
        "customer_id": f.customer_id,
        "customer_name": (await db.execute(select(Customer.name).where(Customer.id == f.customer_id))).scalar() if f.customer_id else None,
        "customer_industry": (await db.execute(select(Customer.industry).where(Customer.id == f.customer_id))).scalar() if f.customer_id else None,
        "correlation_type": f.correlation_type,
        "match_strategy": f.correlation_type,
        "actor_name": f.actor_name,
        "source": f.all_sources[0] if f.all_sources else None,
        "matched_asset": f.matched_asset, "source_count": f.source_count,
        "all_sources": f.all_sources, "confidence": f.confidence,
        "sla_hours": f.sla_hours,
        "sla_deadline": f.sla_deadline.isoformat() if f.sla_deadline else None,
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        "actor": actor, "campaign": campaign,
        "sources": sources, "remediations": remediations,
        # V13 AI fields
        "ai_narrative": getattr(f, "ai_narrative", None),
        "ai_severity_decision": getattr(f, "ai_severity_decision", None),
        "ai_severity_reasoning": getattr(f, "ai_severity_reasoning", None),
        "ai_severity_confidence": getattr(f, "ai_severity_confidence", None),
        "ai_rescore_decision": getattr(f, "ai_rescore_decision", None),
        "ai_rescore_reasoning": getattr(f, "ai_rescore_reasoning", None),
        "ai_rescore_confidence": getattr(f, "ai_rescore_confidence", None),
        "ai_attribution_reasoning": getattr(f, "ai_attribution_reasoning", None),
        "ai_false_positive_flag": getattr(f, "ai_false_positive_flag", False),
        "ai_false_positive_reason": getattr(f, "ai_false_positive_reason", None),
        "ai_enriched_at": f.ai_enriched_at.isoformat() if getattr(f, "ai_enriched_at", None) else None,
        "ai_provider": getattr(f, "ai_provider", None),
        # ═══ PROOF CHAIN ═══
        "affected_products": affected_products,
        "asset_proof": asset_proof,
    }


@router.patch("/api/findings/{finding_id}/status", dependencies=_write_deps)
async def update_finding_status(finding_id: int, request: Request, status: str = None, db: AsyncSession = Depends(get_db)):
    """Update finding status and/or severity. Tracks analyst overrides for prompt evolution."""
    from arguswatch.models import Finding, DetectionStatus
    from datetime import datetime, timezone

    # Accept status from query param or body
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    status = status or body.get("status", "")
    new_severity = body.get("severity")
    override_reason = body.get("reason", "")

    r = await db.execute(select(Finding).where(Finding.id == finding_id))
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404, "Finding not found")

    # ── Track analyst severity override (feeds prompt evolution data) ──
    if new_severity and new_severity.upper() != str(f.severity.value if hasattr(f.severity, 'value') else f.severity).upper():
        old_sev = str(f.severity.value if hasattr(f.severity, 'value') else f.severity)
        f.analyst_override_severity = new_severity.upper()
        f.analyst_override_at = datetime.utcnow()
        f.analyst_override_reason = override_reason or f"Analyst changed {old_sev}->{new_severity.upper()}"
        f.analyst_override_by = "analyst"  # TODO: get from auth token
        try:
            from arguswatch.models import SeverityLevel
            f.severity = SeverityLevel(new_severity.upper())
        except Exception:
            pass
        logger.info(f"[override] Finding {finding_id}: {old_sev} -> {new_severity.upper()} (reason: {override_reason[:60]})")

    # ── Status update ──
    if status:
        try:
            f.status = DetectionStatus(status.upper())
        except ValueError:
            raise HTTPException(400, f"Invalid status: {status}")
        if status.upper() in ("VERIFIED_CLOSED", "FALSE_POSITIVE", "CLOSED"):
            f.resolved_at = datetime.utcnow()

    # ── FP Pattern Learning + Cross-Customer Promotion ──
    if status and status.upper() == "FALSE_POSITIVE" and f.customer_id:
        try:
            from arguswatch.engine.fp_memory import record_fp_pattern
            await record_fp_pattern(
                customer_id=f.customer_id,
                ioc_type=f.ioc_type or "",
                ioc_value=f.ioc_value or "",
                source=(f.all_sources or ["unknown"])[0] if f.all_sources else "",
                reason=override_reason or f"Analyst marked FP on finding#{finding_id}",
                created_by="analyst",
                db=db,
            )
            # ── Cross-customer FP check: same pattern in 3+ customers -> auto-global ──
            from arguswatch.models import FPPattern
            from sqlalchemy import func as _fpfunc
            cross_r = await db.execute(
                select(_fpfunc.count(_fpfunc.distinct(FPPattern.customer_id))).where(
                    FPPattern.ioc_type == f.ioc_type,
                    FPPattern.ioc_value_pattern == f.ioc_value,
                )
            )
            cross_count = cross_r.scalar() or 0
            if cross_count >= 3:
                # Auto-promote to global -  same pattern FP'd by 3+ customers
                await db.execute(
                    FPPattern.__table__.update().where(
                        FPPattern.ioc_type == f.ioc_type,
                        FPPattern.ioc_value_pattern == f.ioc_value,
                    ).values(
                        is_global=True,
                        auto_close=True,
                        cross_customer_count=cross_count,
                        global_promoted_at=datetime.utcnow(),
                        global_promoted_by="auto_cross_customer",
                    )
                )
                logger.info(f"[fp_cross] Pattern '{f.ioc_value[:40]}' ({f.ioc_type}) -> GLOBAL (FP'd by {cross_count} customers)")
            elif cross_count >= 2:
                # Update count for visibility
                await db.execute(
                    FPPattern.__table__.update().where(
                        FPPattern.ioc_type == f.ioc_type,
                        FPPattern.ioc_value_pattern == f.ioc_value,
                    ).values(cross_customer_count=cross_count)
                )
        except Exception as _fp_e:
            logger.debug(f"[fp_memory] Failed to record FP pattern: {_fp_e}")

    await db.commit()
    return {
        "finding_id": finding_id,
        "status": f.status.value if hasattr(f.status, 'value') else str(f.status),
        "severity_overridden": bool(new_severity),
    }


@router.patch("/api/findings/{finding_id}/remediations/{rem_id}", dependencies=[Depends(require_role("admin", "analyst"))])
async def update_remediation_status(
    finding_id: int, rem_id: int, status: str,
    db: AsyncSession = Depends(get_db)
):
    """Update a remediation action status."""
    from arguswatch.models import FindingRemediation
    from datetime import datetime, timezone
    r = await db.execute(
        select(FindingRemediation).where(
            FindingRemediation.id == rem_id,
            FindingRemediation.finding_id == finding_id,
        )
    )
    rem = r.scalar_one_or_none()
    if not rem:
        raise HTTPException(404, "Remediation not found")
    rem.status = status.lower()
    if status.lower() == "completed":
        rem.completed_at = datetime.utcnow()
    await db.commit()
    return {"rem_id": rem_id, "status": rem.status}


@router.get("/api/campaigns")
async def list_campaigns(
    status: str = "active",
    customer_id: int = None,
    db: AsyncSession = Depends(get_db),
):
    """List attack campaigns."""
    from arguswatch.models import Campaign, Customer
    q = select(Campaign)
    if status and status.strip():
        q = q.where(Campaign.status == status)
    if customer_id:
        q = q.where(Campaign.customer_id == customer_id)
    # Sort: severity priority (CRITICAL first), then most recent activity
    sev_order = case(
        (Campaign.severity == SeverityLevel.CRITICAL, 0),
        (Campaign.severity == SeverityLevel.HIGH, 1),
        (Campaign.severity == SeverityLevel.MEDIUM, 2),
        (Campaign.severity == SeverityLevel.LOW, 3),
        else_=4
    )
    q = q.order_by(sev_order, Campaign.last_activity.desc()).limit(50)
    r = await db.execute(q)
    campaigns = r.scalars().all()
    # Batch-fetch customer names
    cust_ids = list(set(c.customer_id for c in campaigns if c.customer_id))
    cust_map = {}
    if cust_ids:
        cr = await db.execute(select(Customer.id, Customer.name).where(Customer.id.in_(cust_ids)))
        cust_map = {row.id: row.name for row in cr.all()}
    return [{
        "id": c.id, "name": c.name, "customer_id": c.customer_id,
        "customer_name": cust_map.get(c.customer_id, "Unknown"),
        "actor_name": c.actor_name, "kill_chain_stage": c.kill_chain_stage,
        "finding_count": c.finding_count,
        "severity": _sev(c.severity) or None,
        "status": c.status,
        "first_seen": c.first_seen.isoformat() if c.first_seen else None,
        "last_activity": c.last_activity.isoformat() if c.last_activity else None,
        "ai_narrative": getattr(c, "ai_narrative", None),
    } for c in campaigns]


@router.post("/api/campaigns/detect")
async def detect_campaigns_now(db: AsyncSession = Depends(get_db)):
    """Manually trigger campaign detection across all customers."""
    try:
        from arguswatch.engine.campaign_detector import check_and_create_campaign
        from arguswatch.models import Finding
        r = await db.execute(
            select(Finding).where(Finding.campaign_id == None).limit(500)
        )
        findings = r.scalars().all()
        created = 0
        for f in findings:
            try:
                camp = await check_and_create_campaign(f, db)
                if camp:
                    created += 1
            except Exception as e:
                logger.debug(f"Suppressed: {e}")
        await db.commit()
        return {"status": "done", "findings_checked": len(findings), "campaigns_created": created}
    except Exception as e:
        return {"status": "error", "detail": str(e)[:200]}


@router.get("/api/campaigns/{campaign_id}")
async def get_campaign(campaign_id: int, db: AsyncSession = Depends(get_db)):
    """Get full campaign detail with findings, actor, customer, remediations, and sources."""
    from arguswatch.models import Campaign, Finding, Customer, FindingSource, FindingRemediation
    r = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404, "Campaign not found")
    # Get linked findings sorted: CRITICAL first
    sev_order = case(
        (Finding.severity == SeverityLevel.CRITICAL, 0),
        (Finding.severity == SeverityLevel.HIGH, 1),
        (Finding.severity == SeverityLevel.MEDIUM, 2),
        (Finding.severity == SeverityLevel.LOW, 3),
        else_=4
    )
    fr = await db.execute(
        select(Finding).where(Finding.campaign_id == campaign_id).order_by(sev_order, Finding.created_at.desc()).limit(50)
    )
    findings = []
    finding_ids = []
    for f in fr.scalars().all():
        sev = f.severity
        sev_str = sev.value if hasattr(sev, 'value') else str(sev) if sev else None
        finding_ids.append(f.id)
        findings.append({
            "id": f.id, "ioc_value": f.ioc_value, "ioc_type": f.ioc_type,
            "severity": sev_str,
            "source": f.source if hasattr(f, 'source') else None,
            "all_sources": f.all_sources or [],
            "confidence": f.confidence,
            "matched_asset": f.matched_asset,
            "correlation_type": f.correlation_type,
            "ai_title": getattr(f, "ai_title", None),
            "ai_narrative": getattr(f, "ai_narrative", None),
            "ai_severity_reasoning": getattr(f, "ai_severity_reasoning", None),
            "confirmed_exposure": getattr(f, "confirmed_exposure", False),
            "exposure_type": getattr(f, "exposure_type", None),
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "status": f.status.value if hasattr(f.status, 'value') else str(f.status) if f.status else None,
            "remediations": [],
            "sources_detail": [],
        })
    # Batch-fetch remediations for all findings
    if finding_ids:
        rem_r = await db.execute(
            select(FindingRemediation).where(FindingRemediation.finding_id.in_(finding_ids)).order_by(FindingRemediation.created_at.desc())
        )
        rem_map = {}
        for rem in rem_r.scalars().all():
            rem_map.setdefault(rem.finding_id, []).append({
                "id": rem.id, "title": rem.title, "action_type": rem.action_type,
                "steps_technical": rem.steps_technical or [],
                "steps_governance": rem.steps_governance or [],
                "assigned_to": rem.assigned_to, "status": rem.status,
                "deadline": rem.deadline.isoformat() if rem.deadline else None,
            })
        # Batch-fetch sources
        src_r = await db.execute(
            select(FindingSource).where(FindingSource.finding_id.in_(finding_ids)).order_by(FindingSource.contributed_at.desc())
        )
        src_map = {}
        for s in src_r.scalars().all():
            src_map.setdefault(s.finding_id, []).append({
                "source": s.source,
                "contributed_at": s.contributed_at.isoformat() if s.contributed_at else None,
            })
        # Attach to findings
        for fd in findings:
            fd["remediations"] = rem_map.get(fd["id"], [])
            fd["sources_detail"] = src_map.get(fd["id"], [])
    # Get customer info
    cr = await db.execute(select(Customer).where(Customer.id == c.customer_id))
    cust = cr.scalar_one_or_none()
    cust_info = None
    if cust:
        cust_info = {
            "id": cust.id, "name": cust.name,
            "industry": getattr(cust, "industry", None),
            "tier": getattr(cust, "tier", None),
            "primary_domain": getattr(cust, "primary_domain", None),
        }
    # Get actor info
    actor_info = None
    if c.actor_id:
        from arguswatch.models import ThreatActor
        ar = await db.execute(select(ThreatActor).where(ThreatActor.id == c.actor_id))
        a = ar.scalar_one_or_none()
        if a:
            actor_info = {
                "id": a.id, "name": a.name, "mitre_id": a.mitre_id,
                "origin_country": a.origin_country, "motivation": a.motivation,
                "description": (a.description or "")[:500],
                "techniques": a.techniques or [], "aliases": a.aliases or [],
            }
    c_sev = c.severity
    c_sev_str = c_sev.value if hasattr(c_sev, 'value') else str(c_sev) if c_sev else None
    return {
        "id": c.id, "name": c.name, "customer_id": c.customer_id,
        "customer_name": cust_info["name"] if cust_info else "Unknown",
        "customer": cust_info,
        "actor_name": c.actor_name,
        "actor_id": c.actor_id, "actor": actor_info,
        "kill_chain_stage": c.kill_chain_stage, "finding_count": c.finding_count,
        "severity": c_sev_str,
        "status": c.status, "ai_narrative": c.ai_narrative,
        "first_seen": c.first_seen.isoformat() if c.first_seen else None,
        "last_activity": c.last_activity.isoformat() if c.last_activity else None,
        "findings": findings,
    }



@router.get("/api/finding-remediations/stats")
async def remediation_stats(db: AsyncSession = Depends(get_db)):
    """Stats from FindingRemediation (real playbook-generated actions)."""
    from arguswatch.models import FindingRemediation
    r = await db.execute(
        select(FindingRemediation.status, func.count(FindingRemediation.id).label("cnt"))
        .group_by(FindingRemediation.status)
    )
    by_status = {row.status: row.cnt for row in r}
    total = sum(by_status.values())
    closed = by_status.get("completed", 0)
    return {"total": total, "by_status": by_status,
            "resolution_rate": round(closed / max(total, 1) * 100, 1)}

@router.post("/api/finding-remediations/create", dependencies=[Depends(require_role("admin", "analyst"))])
async def create_manual_remediation(request: Request, db: AsyncSession = Depends(get_db)):
    """Create a manual remediation task (not linked to a specific finding)."""
    from arguswatch.models import FindingRemediation
    body = await request.json()
    title = body.get("title", "").strip()
    if not title:
        raise HTTPException(422, "title is required")
    rem = FindingRemediation(
        finding_id=body.get("finding_id") or 0,
        playbook_key="manual",
        action_type=body.get("action_type", "manual"),
        title=title,
        steps_technical=[body.get("description", "")] if body.get("description") else [],
        assigned_role=body.get("assigned_role", "analyst"),
        status=body.get("status", "pending"),
        sla_hours=body.get("sla_hours", 72),
    )
    db.add(rem)
    await db.flush()
    await db.refresh(rem)
    await db.commit()
    return {"id": rem.id, "title": rem.title, "status": rem.status}

@router.get("/api/finding-remediations/")
async def list_all_remediations(status: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """List ALL FindingRemediation actions across all findings/customers."""
    from arguswatch.models import FindingRemediation, Finding, Customer
    q = select(FindingRemediation).order_by(desc(FindingRemediation.created_at)).limit(200)
    if status and status != "all":
        q = q.where(FindingRemediation.status == status)
    r = await db.execute(q)
    items = []
    for rem in r.scalars().all():
        fr = await db.execute(select(Finding).where(Finding.id == rem.finding_id))
        f = fr.scalar_one_or_none()
        cust_name = None
        if f and f.customer_id:
            cr = await db.execute(select(Customer.name).where(Customer.id == f.customer_id))
            cust_name = cr.scalar_one_or_none()
        items.append({
            "id": rem.id,
            "finding_id": rem.finding_id,
            "playbook_key": rem.playbook_key,
            "action_type": rem.action_type,
            "title": rem.title,
            "status": rem.status or "pending",
            "assigned_to": rem.assigned_to,
            "assigned_role": rem.assigned_role,
            "deadline": rem.deadline.isoformat() if rem.deadline else None,
            "sla_hours": rem.sla_hours,
            "steps_technical": rem.steps_technical or [],
            "steps_governance": rem.steps_governance or [],
            "evidence_required": rem.evidence_required or [],
            "created_at": rem.created_at.isoformat() if rem.created_at else None,
            "completed_at": rem.completed_at.isoformat() if getattr(rem, 'completed_at', None) else None,
            "ioc_value": f.ioc_value if f else None,
            "ioc_type": f.ioc_type if f else None,
            "severity": f.severity.value if f and hasattr(f.severity, 'value') else str(f.severity) if f and f.severity else None,
            "customer_name": cust_name,
        })
    return {"items": items, "total": len(items)}


@router.get("/api/sla/breaches")
async def sla_breaches(db: AsyncSession = Depends(get_db)):
    """Detections that have exceeded their SLA without resolution."""
    breaches = []
    r = await db.execute(
        select(Detection).where(
            Detection.status.in_(["NEW", "ENRICHED"]),
            Detection.severity.in_([SeverityLevel.CRITICAL, SeverityLevel.HIGH])
        ).order_by(desc(Detection.created_at)).limit(100)
    )
    all_dets = r.scalars().all()
    # Batch-load customer names
    sla_cust_ids = list({d.customer_id for d in all_dets if d.customer_id})
    sla_cust_names = {}
    if sla_cust_ids:
        cnr = await db.execute(select(Customer.id, Customer.name).where(Customer.id.in_(sla_cust_ids)))
        sla_cust_names = {row.id: row.name for row in cnr.all()}
    for d in all_dets:
        elapsed_h = (datetime.utcnow() - d.created_at).total_seconds() / 3600 if d.created_at else 0
        if elapsed_h > (d.sla_hours or 72):
            breaches.append({
                "id": d.id, "ioc_type": d.ioc_type, "ioc_value": d.ioc_value[:60],
                "severity": _sev(d.severity) or None,
                "sla_hours": d.sla_hours, "elapsed_hours": round(elapsed_h, 1),
                "overdue_by": round(elapsed_h - (d.sla_hours or 72), 1),
                "actual_hours": round(elapsed_h, 1),
                "customer_id": d.customer_id,
                "customer_name": sla_cust_names.get(d.customer_id, ""),
                "finding_id": d.finding_id,
                "breached": True,
            })
    return {"total_breaches": len(breaches), "breaches": breaches}


@router.get("/api/fp-patterns")
async def list_fp_patterns(customer_id: int = 0, limit: int = 50, db: AsyncSession = Depends(get_db)):
    """List learned false positive patterns."""
    from arguswatch.models import FPPattern
    q = select(FPPattern).order_by(FPPattern.created_at.desc()).limit(limit)
    if customer_id:
        q = q.where(FPPattern.customer_id == customer_id)
    r = await db.execute(q)
    return [{
        "id": p.id, "customer_id": p.customer_id, "ioc_type": p.ioc_type,
        "ioc_value_pattern": p.ioc_value_pattern, "match_type": p.match_type,
        "source": p.source, "reason": p.reason, "confidence": p.confidence,
        "hit_count": p.hit_count, "created_by": p.created_by,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    } for p in r.scalars().all()]

@router.get("/api/fp-patterns/stats")
async def fp_memory_stats(db: AsyncSession = Depends(get_db)):
    """FP memory statistics - how much the system has learned."""
    from arguswatch.models import FPPattern
    from sqlalchemy import func as _fn
    total = (await db.execute(select(_fn.count(FPPattern.id)))).scalar() or 0
    total_hits = (await db.execute(select(_fn.sum(FPPattern.hit_count)))).scalar() or 0
    auto_closeable = (await db.execute(
        select(_fn.count(FPPattern.id)).where(FPPattern.confidence >= 0.85)
    )).scalar() or 0
    return {
        "total_patterns": total, "total_hits_saved": total_hits,
        "auto_closeable_patterns": auto_closeable,
        "ai_api_calls_saved_estimate": total_hits,
    }

