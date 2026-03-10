from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, delete, func, text
from sqlalchemy.ext.asyncio import AsyncSession
from arguswatch.database import get_db
from arguswatch.models import Customer, CustomerAsset
from arguswatch.api.schemas import CustomerCreate, CustomerUpdate, CustomerOut, AssetCreate, AssetOut

router = APIRouter(prefix="/api/customers", tags=["customers"])

@router.get("/", response_model=list)
async def list_customers(active_only: bool = True, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func as sqlfunc
    from arguswatch.models import Detection, CustomerAsset as CA
    q = select(Customer)
    if active_only:
        q = q.where(Customer.active == True)
    result = await db.execute(q.order_by(Customer.name))
    customers = result.scalars().all()
    out = []
    for c in customers:
        dr = await db.execute(select(sqlfunc.count(Detection.id)).where(Detection.customer_id == c.id))
        ar = await db.execute(select(sqlfunc.count(CA.id)).where(CA.customer_id == c.id))
        # Finding counts for dashboard
        from arguswatch.models import Finding
        fr = await db.execute(select(sqlfunc.count(Finding.id)).where(Finding.customer_id == c.id))
        finding_count = fr.scalar() or 0
        cr_r = await db.execute(select(sqlfunc.count(Finding.id)).where(
            Finding.customer_id == c.id, Finding.severity == "CRITICAL"))
        critical_count = cr_r.scalar() or 0
        # Exposure score: MUST match /api/exposure/leaderboard logic exactly
        # Order: CustomerExposure (per-actor max) -> ExposureHistory (D1-D5 overall) -> severity fallback
        score_source = "none"
        from arguswatch.models import CustomerExposure, ExposureHistory
        # 1. Try CustomerExposure (per-actor max) -  this is what Exposure page shows
        exp_r = await db.execute(
            select(sqlfunc.max(CustomerExposure.exposure_score)).where(CustomerExposure.customer_id == c.id))
        exposure_score = exp_r.scalar() or 0
        if exposure_score: score_source = "actor_exposure"
        # 2. Try ExposureHistory (D1-D5 overall)
        if not exposure_score:
            eh_r = await db.execute(
                select(sqlfunc.max(ExposureHistory.overall_score)).where(ExposureHistory.customer_id == c.id))
            exposure_score = eh_r.scalar() or 0
            if exposure_score: score_source = "d1d5_scorer"
        # 3. Fallback: severity-based estimate (capped at 75)
        if not exposure_score and finding_count > 0:
            # Fallback: conservative estimate (capped at 75 to signal D1-D5 scorer needed)
            hi_r2 = await db.execute(select(sqlfunc.count(Finding.id)).where(
                Finding.customer_id == c.id, Finding.severity == "HIGH"))
            high_count = hi_r2.scalar() or 0
            exposure_score = min(75, round(critical_count * 6 + high_count * 3 + max(0, finding_count - critical_count - high_count) * 0.5, 1))
            score_source = "estimated_from_findings"
        exposure_score = round(exposure_score, 1)
        # Derive primary_domain from first domain asset or email
        domain_r = await db.execute(
            select(CA.asset_value).where(CA.customer_id == c.id, CA.asset_type == "domain").limit(1)
        )
        primary_domain = domain_r.scalar() or (c.email.split("@")[1] if c.email and "@" in c.email else "")
        out.append({
            "id": c.id, "name": c.name, "industry": c.industry,
            "tier": c.tier, "primary_contact": c.primary_contact,
            "email": c.email, "slack_channel": c.slack_channel,
            "primary_domain": primary_domain,
            "active": c.active, "created_at": c.created_at.isoformat() if c.created_at else None,
            "onboarding_state": c.onboarding_state or "created",
            "detection_count": dr.scalar() or 0,
            "asset_count": ar.scalar() or 0,
            "finding_count": finding_count,
            "critical_count": critical_count,
            "exposure_score": exposure_score, "score_source": score_source,
        })
    return out

@router.get("/{cid}")
async def get_customer(cid: int, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Customer).where(Customer.id == cid))
    c = r.scalar_one_or_none()
    if not c: raise HTTPException(404, "Customer not found")
    # Load assets
    ar = await db.execute(select(CustomerAsset).where(CustomerAsset.customer_id == cid))
    assets = ar.scalars().all()
    # Load detection count
    from sqlalchemy import func as sqlfunc
    from arguswatch.models import Detection, Finding
    dr = await db.execute(
        select(sqlfunc.count(Detection.id)).where(Detection.customer_id == cid)
    )
    det_count = dr.scalar() or 0
    # Finding counts
    fr = await db.execute(select(sqlfunc.count(Finding.id)).where(Finding.customer_id == cid))
    finding_count = fr.scalar() or 0
    cr_r = await db.execute(select(sqlfunc.count(Finding.id)).where(
        Finding.customer_id == cid, Finding.severity == "CRITICAL"))
    critical_count = cr_r.scalar() or 0
    hi_r = await db.execute(select(sqlfunc.count(Finding.id)).where(
        Finding.customer_id == cid, Finding.severity == "HIGH"))
    high_count = hi_r.scalar() or 0
    # Exposure score: MUST match /api/exposure/leaderboard logic exactly
    from arguswatch.models import CustomerExposure, ExposureHistory
    score_source = "none"
    # 1. Try CustomerExposure (per-actor max) -  this is what Exposure page shows
    exp_r = await db.execute(
        select(sqlfunc.max(CustomerExposure.exposure_score)).where(CustomerExposure.customer_id == cid))
    exposure_score = exp_r.scalar() or 0
    if exposure_score: score_source = "actor_exposure"
    # 2. Try ExposureHistory (D1-D5 overall)
    if not exposure_score:
        eh_r = await db.execute(
            select(sqlfunc.max(ExposureHistory.overall_score)).where(ExposureHistory.customer_id == cid))
        exposure_score = eh_r.scalar() or 0
        if exposure_score: score_source = "d1d5_scorer"
    # 3. Fallback: severity-based estimate (capped at 75)
    if not exposure_score and finding_count > 0:
        exposure_score = min(75, round(critical_count * 6 + high_count * 3 + max(0, finding_count - critical_count - high_count) * 0.5, 1))
        score_source = "estimated_from_findings"
    exposure_score = round(exposure_score, 1)
    return {
        "id": c.id, "name": c.name, "industry": c.industry,
        "tier": c.tier, "primary_contact": c.primary_contact,
        "email": c.email, "slack_channel": c.slack_channel,
        "active": c.active, "created_at": c.created_at.isoformat() if c.created_at else None,
        "onboarding_state": c.onboarding_state or "created",
        "detection_count": det_count,
        "asset_count": len(assets),
        "finding_count": finding_count,
        "critical_count": critical_count,
        "exposure_score": exposure_score, "score_source": score_source,
        "recon_status": getattr(c, "recon_status", None),
        "recon_error": getattr(c, "recon_error", None),
        "assets": [{"id": a.id, "asset_type": a.asset_type.value if hasattr(a.asset_type, "value") else a.asset_type,
                    "asset_value": a.asset_value, "criticality": a.criticality,
                    "confidence": getattr(a, "confidence", 1.0),
                    "confidence_sources": getattr(a, "confidence_sources", []),
                    "discovery_source": getattr(a, "discovery_source", None),
                    "ioc_hit_count": getattr(a, "ioc_hit_count", 0),
                    "last_seen_in_ioc": a.last_seen_in_ioc.isoformat() if getattr(a, "last_seen_in_ioc", None) else None,
                    } for a in assets],
    }

@router.post("/", response_model=CustomerOut, status_code=201)
async def create_customer(p: CustomerCreate, db: AsyncSession = Depends(get_db)):
    """Create customer with same validation as onboard endpoint.
    Industry is REQUIRED. Auto-registers domain from email if possible."""
    from datetime import datetime as _dt, timezone
    
    # ── Enforce industry ──
    VALID_INDUSTRIES = {"financial","healthcare","technology","energy","government",
                        "retail","manufacturing","education","legal","media",
                        "telecom","defense","transportation","hospitality","nonprofit"}
    if not p.industry:
        raise HTTPException(400, "industry is required - needed for threat actor targeting (D3). "
                                 f"Valid: {', '.join(sorted(VALID_INDUSTRIES))}")
    if p.industry.lower() not in VALID_INDUSTRIES:
        raise HTTPException(400, f"industry must be one of: {', '.join(sorted(VALID_INDUSTRIES))}")
    
    c = Customer(**p.model_dump())
    c.industry = c.industry.lower()
    c.onboarding_state = "created"
    db.add(c); await db.flush(); await db.refresh(c)
    
    # ── Auto-register domain from email ──
    domain = None
    if p.email and "@" in p.email:
        domain = p.email.split("@")[1].lower()
    
    if domain:
        for atype, aval in [("domain", domain), ("email_domain", domain)]:
            existing = await db.execute(
                select(CustomerAsset).where(
                    CustomerAsset.customer_id == c.id,
                    CustomerAsset.asset_type == atype,
                    CustomerAsset.asset_value == aval,
                )
            )
            if not existing.scalar_one_or_none():
                db.add(CustomerAsset(customer_id=c.id, asset_type=atype,
                                     asset_value=aval, criticality="high",
                                     discovery_source="auto_from_email"))
        # Brand name
        db.add(CustomerAsset(customer_id=c.id, asset_type="brand_name",
                             asset_value=p.name, criticality="high",
                             discovery_source="auto_from_name"))
        c.onboarding_state = "assets_added"
        c.onboarding_updated_at = _dt.utcnow()
    
    await db.flush(); await db.refresh(c)
    return c

@router.patch("/{cid}", response_model=CustomerOut)
async def update_customer(cid: int, p: CustomerUpdate, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Customer).where(Customer.id == cid))
    c = r.scalar_one_or_none()
    if not c: raise HTTPException(404, "Customer not found")
    for k, v in p.model_dump(exclude_unset=True).items(): setattr(c, k, v)
    await db.flush(); await db.refresh(c)
    return c

@router.get("/{cid}/assets", response_model=list[AssetOut])
async def list_assets(cid: int, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(CustomerAsset).where(CustomerAsset.customer_id == cid))
    return r.scalars().all()

@router.post("/{cid}/assets", response_model=AssetOut, status_code=201)
async def create_asset(cid: int, p: AssetCreate, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(Customer).where(Customer.id == cid))
    if not r.scalar_one_or_none(): raise HTTPException(404, "Customer not found")
    a = CustomerAsset(customer_id=cid, **p.model_dump(),
                      confidence=1.0, confidence_sources=["analyst"],
                      discovery_source="analyst")
    db.add(a); await db.flush(); await db.refresh(a)
    # Auto-advance onboarding state
    from datetime import datetime as _dt, timezone
    cr = await db.execute(select(Customer).where(Customer.id == cid))
    cu = cr.scalar_one_or_none()
    if cu and (cu.onboarding_state or "created") == "created":
        cu.onboarding_state = "assets_added"
        cu.onboarding_updated_at = _dt.utcnow()
        await db.flush()
    return a

@router.post("/{cid}/assets/bulk", status_code=201)
async def bulk_create_assets(cid: int, assets: list[AssetCreate], db: AsyncSession = Depends(get_db)):
    """V10: Create multiple assets at once. Skips duplicates (same type+value)."""
    r = await db.execute(select(Customer).where(Customer.id == cid))
    if not r.scalar_one_or_none(): raise HTTPException(404, "Customer not found")
    # Get existing to dedup
    ex_r = await db.execute(select(CustomerAsset).where(CustomerAsset.customer_id == cid))
    existing = {(a.asset_type, a.asset_value) for a in ex_r.scalars().all()}
    created = 0
    for p in assets:
        key = (p.asset_type, p.asset_value)
        if key not in existing:
            db.add(CustomerAsset(customer_id=cid, **p.model_dump(),
                                 discovery_source="bulk_import"))
            existing.add(key)
            created += 1
    await db.flush()
    return {"created": created, "skipped": len(assets) - created}

@router.delete("/{cid}/assets/{asset_id}", status_code=204)
async def delete_asset(cid: int, asset_id: int, db: AsyncSession = Depends(get_db)):
    """V10: Delete a specific customer asset."""
    r = await db.execute(select(CustomerAsset).where(
        CustomerAsset.id == asset_id, CustomerAsset.customer_id == cid))
    a = r.scalar_one_or_none()
    if not a: raise HTTPException(404, "Asset not found")
    await db.delete(a)
    await db.flush()

@router.delete("/{cid}", status_code=200)
async def delete_customer(cid: int, db: AsyncSession = Depends(get_db)):
    """Delete a customer and ALL related data. Uses savepoints so one table failure doesn't break all."""
    cr = await db.execute(select(Customer).where(Customer.id == cid))
    customer = cr.scalar_one_or_none()
    if not customer:
        raise HTTPException(404, "Customer not found")
    name = customer.name
    counts = {}
    
    # Each delete in its own savepoint -  if one fails, others still proceed
    tables = [
        ("campaigns", "DELETE FROM campaigns WHERE id IN (SELECT DISTINCT campaign_id FROM findings WHERE customer_id = :cid AND campaign_id IS NOT NULL)"),
        ("remediations", "DELETE FROM remediations WHERE finding_id IN (SELECT id FROM findings WHERE customer_id = :cid)"),
        ("exposure_history", "DELETE FROM exposure_history WHERE customer_id = :cid"),
        ("customer_exposures", "DELETE FROM customer_exposures WHERE customer_id = :cid"),
        ("darkweb_mentions", "DELETE FROM darkweb_mentions WHERE customer_id = :cid"),
        ("findings", "DELETE FROM findings WHERE customer_id = :cid"),
        ("detections", "DELETE FROM detections WHERE customer_id = :cid"),
        ("customer_assets", "DELETE FROM customer_assets WHERE customer_id = :cid"),
    ]
    
    for label, sql in tables:
        try:
            async with db.begin_nested():
                r = await db.execute(text(sql), {"cid": cid})
                counts[label] = r.rowcount or 0
        except Exception as e:
            counts[label] = f"skip"
    
    # Delete customer row
    try:
        async with db.begin_nested():
            await db.execute(text("DELETE FROM customers WHERE id = :cid"), {"cid": cid})
        await db.commit()
    except Exception as e:
        await db.rollback()
        raise HTTPException(500, f"Delete failed: {str(e)[:100]}")
    
    return {"deleted": name, "id": cid, "related_data_removed": counts}

@router.get("/{cid}/completeness")
async def asset_completeness(cid: int, db: AsyncSession = Depends(get_db)):
    """V10: Return completeness score (0-100) showing which asset categories are filled.
    Low completeness = blind spots in correlation engine.
    """
    CATEGORIES = ["domain","ip","email","keyword","cidr","org_name","github_org",
                  "subdomain","tech_stack","brand_name","exec_name","cloud_asset"]
    r = await db.execute(select(CustomerAsset).where(CustomerAsset.customer_id == cid))
    assets = r.scalars().all()
    filled = set(a.asset_type.value if hasattr(a.asset_type, "value") else a.asset_type for a in assets)
    missing = [c for c in CATEGORIES if c not in filled]
    pct = round(len(filled) / len(CATEGORIES) * 100)
    return {
        "customer_id": cid,
        "completeness_pct": pct,
        "total_assets": len(assets),
        "filled_categories": list(filled),
        "missing_categories": missing,
        "impact": {
            "tech_stack": "tech_stack" not in filled and "Missing: CVE->product matching disabled",
            "brand_name": "brand_name" not in filled and "Missing: typosquat detection disabled",
            "exec_name": "exec_name" not in filled and "Missing: VIP/exec credential leak matching disabled",
            "cloud_asset": "cloud_asset" not in filled and "Missing: cloud exposure correlation disabled",
        }
    }


@router.post("/{cid}/recorrelate")
async def recorrelate_customer(cid: int, db: AsyncSession = Depends(get_db)):
    """GAP 2 FIX: Retroactively route unmatched detections to this customer.
    Finds detections with customer_id=NULL that match this customer's assets.
    Run this after adding new assets to catch previously missed detections."""
    from arguswatch.engine.correlation_engine import route_detection
    from arguswatch.models import Detection, DetectionStatus

    r = await db.execute(select(Customer).where(Customer.id == cid))
    if not r.scalar_one_or_none():
        raise HTTPException(404, "Customer not found")

    # Find ALL unrouted detections (not just NEW - that was the old limitation)
    ur = await db.execute(
        select(Detection).where(
            Detection.customer_id == None,
        ).order_by(Detection.created_at.desc()).limit(500)
    )
    unrouted = ur.scalars().all()
    routed = 0
    for det in unrouted:
        matched = await route_detection(det, db)
        if matched and det.customer_id == cid:
            routed += 1
    await db.commit()
    return {
        "customer_id": cid,
        "scanned": len(unrouted),
        "routed_to_customer": routed,
    }


# ═══════════════════════════════════════════════════════════════════════
# FEATURE 2: ONBOARDING STATE MACHINE
# States: created -> assets_added -> monitoring -> tuning -> production
# ═══════════════════════════════════════════════════════════════════════

ONBOARDING_TRANSITIONS = {
    "created": ["assets_added"],
    "assets_added": ["monitoring"],
    "monitoring": ["tuning"],
    "tuning": ["production"],
    "production": ["tuning"],  # can go back to tuning
}

ONBOARDING_LABELS = {
    "created": "🆕 Created - add assets to begin",
    "assets_added": "📋 Assets Added - enable monitoring",
    "monitoring": "👁️ Monitoring - detections flowing",
    "tuning": "🔧 Tuning - reducing false positives",
    "production": "✅ Production - fully operational",
}


@router.patch("/{cid}/onboarding")
async def advance_onboarding(cid: int, state: str = "", db: AsyncSession = Depends(get_db)):
    """Advance or set onboarding state. If state is empty, auto-advances based on data."""
    from datetime import datetime as _dt, timezone
    r = await db.execute(select(Customer).where(Customer.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404, "Customer not found")

    current = c.onboarding_state or "created"

    if state:
        # Manual transition - validate
        valid_next = ONBOARDING_TRANSITIONS.get(current, [])
        if state not in valid_next and state != current:
            raise HTTPException(400, f"Cannot transition from '{current}' to '{state}'. Valid: {valid_next}")
        c.onboarding_state = state
        c.onboarding_updated_at = _dt.utcnow()
        await db.commit()
        return {"customer_id": cid, "state": state, "label": ONBOARDING_LABELS.get(state, state)}

    # Auto-advance based on data
    from arguswatch.models import CustomerAsset, Detection
    from sqlalchemy import func

    ar = await db.execute(select(func.count(CustomerAsset.id)).where(CustomerAsset.customer_id == cid))
    asset_count = ar.scalar() or 0
    dr = await db.execute(select(func.count(Detection.id)).where(Detection.customer_id == cid))
    det_count = dr.scalar() or 0

    new_state = current
    if current == "created" and asset_count >= 1:
        new_state = "assets_added"
    elif current == "assets_added" and det_count >= 1:
        new_state = "monitoring"
    elif current == "monitoring" and det_count >= 10:
        new_state = "tuning"
    # production requires manual promotion

    if new_state != current:
        c.onboarding_state = new_state
        c.onboarding_updated_at = _dt.utcnow()
        await db.commit()

    return {
        "customer_id": cid,
        "state": new_state,
        "previous": current,
        "auto_advanced": new_state != current,
        "label": ONBOARDING_LABELS.get(new_state, new_state),
        "asset_count": asset_count,
        "detection_count": det_count,
    }


@router.get("/{cid}/onboarding")
async def get_onboarding(cid: int, db: AsyncSession = Depends(get_db)):
    """Get onboarding state with progress data."""
    from arguswatch.models import CustomerAsset, Detection
    from sqlalchemy import func

    r = await db.execute(select(Customer).where(Customer.id == cid))
    c = r.scalar_one_or_none()
    if not c:
        raise HTTPException(404, "Customer not found")

    ar = await db.execute(select(func.count(CustomerAsset.id)).where(CustomerAsset.customer_id == cid))
    asset_count = ar.scalar() or 0
    dr = await db.execute(select(func.count(Detection.id)).where(Detection.customer_id == cid))
    det_count = dr.scalar() or 0

    state = c.onboarding_state or "created"
    states = ["created", "assets_added", "monitoring", "tuning", "production"]
    step_idx = states.index(state) if state in states else 0

    return {
        "customer_id": cid,
        "state": state,
        "label": ONBOARDING_LABELS.get(state, state),
        "step": step_idx + 1,
        "total_steps": len(states),
        "progress_pct": round((step_idx / (len(states) - 1)) * 100) if len(states) > 1 else 0,
        "next_states": ONBOARDING_TRANSITIONS.get(state, []),
        "asset_count": asset_count,
        "detection_count": det_count,
    }
