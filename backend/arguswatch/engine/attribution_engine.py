"""
Attribution Engine V11 - links findings to threat actors.

V11 changes:
- attribute_finding() operates on Finding objects (not Detection)
- CVE→actor lookup uses cve_product_map table (populated by NVD collector)
- IOC→actor lookup uses actor_iocs table (populated by MITRE/OTX collectors)
- Hardcoded CVE_ACTOR_MAP and ACTOR_C2_INDICATORS kept as FALLBACK only
  (they still work when DB tables are empty on fresh deploy)
- attribute_detection_by_id() kept for the API endpoint /api/attribution/{id}
- Duplicate function bug from V9 is fixed - only one attribute_detection exists
"""
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from arguswatch.models import (
    Detection, Finding, ThreatActor, CustomerExposure,
    Customer, ActorIoc, CveProductMap, SeverityLevel
)

logger = logging.getLogger("arguswatch.engine.attribution")

try:
    from arguswatch.config import settings as _attr_settings
    def _autonomous_attribution() -> bool:
        """True when AI_AUTONOMOUS=true - AI can override rule-based attribution."""
        return getattr(_attr_settings, "AI_AUTONOMOUS", False)
except Exception:
    def _autonomous_attribution() -> bool:
        return False

# ── Fallback maps (used when DB tables are empty) ─────────────────────────────
# These are intentionally small - the real data lives in actor_iocs and cve_product_map
CVE_ACTOR_MAP = {
    "CVE-2021-44228": ["Lazarus Group", "APT41", "Hafnium", "Conti"],
    "CVE-2021-26855": ["Hafnium", "ECTIPANDA", "APT27"],
    "CVE-2023-34362": ["Cl0p"],
    "CVE-2023-22515": ["Storm-0062"],
    "CVE-2024-21887": ["UNC5221"],
    "CVE-2024-3400":  ["UTA0218"],
    "CVE-2022-30190": ["Lazarus Group", "TA570"],
    "CVE-2017-0144":  ["Lazarus Group", "WannaCry"],
    "CVE-2021-40444": ["NOBELIUM"],
    "CVE-2023-4966":  ["LockBit 3.0"],
}

ACTOR_C2_PREFIXES = {
    "Lazarus Group": ["185.234.219.", "45.58.112.", "104.168.99."],
    "APT28":         ["95.216.",      "185.220.",   "46.246."],
    "Conti":         ["23.81.246.",   "23.106.160."],
    "LockBit":       ["62.182.82.",   "81.19.135."],
}


async def attribute_finding(finding: Finding, db: AsyncSession) -> list[str]:
    """Main attribution function - operates on a Finding object.
    Returns list of actor names attributed to this finding.
    Sets finding.actor_id and finding.actor_name on the first confident match.
    """
    attributed = set()

    # ── 1. IOC → actor via actor_iocs table (DB-driven) ──────────────────────
    r = await db.execute(
        select(ActorIoc).where(ActorIoc.ioc_value == finding.ioc_value).limit(5)
    )
    actor_ioc_rows = r.scalars().all()
    for ai in actor_ioc_rows:
        attributed.add(ai.actor_name)
        if not finding.actor_id:
            finding.actor_id = ai.actor_id
            finding.actor_name = ai.actor_name

    # ── 2. CVE → actor via cve_product_map table ─────────────────────────────
    if finding.ioc_type == "cve_id":
        cve_upper = finding.ioc_value.upper()
        # First try cve_product_map actors
        cpm_r = await db.execute(
            select(CveProductMap).where(CveProductMap.cve_id == cve_upper).limit(1)
        )
        cpm = cpm_r.scalar_one_or_none()
        if cpm and cpm.actively_exploited:
            # KEV CVE - higher confidence, search actor_iocs for actors exploiting it
            actor_r = await db.execute(
                select(ActorIoc).where(
                    ActorIoc.ioc_value.ilike(f"%{cve_upper}%")
                ).limit(3)
            )
            for ai in actor_r.scalars().all():
                attributed.add(ai.actor_name)
        # Fallback: hardcoded map
        for cve, actors in CVE_ACTOR_MAP.items():
            if cve in cve_upper or cve_upper in cve:
                attributed.update(actors)

    # ── 3. IP prefix → actor (C2 infrastructure) ─────────────────────────────
    if finding.ioc_type in ("ipv4", "ipv6"):
        ip = finding.ioc_value
        # DB-driven: prefix match in actor_iocs
        prefix_3 = ".".join(ip.split(".")[:3]) + "."
        r2 = await db.execute(
            select(ActorIoc).where(
                ActorIoc.ioc_type == "ipv4",
                ActorIoc.ioc_value.like(prefix_3 + "%"),
            ).limit(3)
        )
        for ai in r2.scalars().all():
            attributed.add(ai.actor_name)
            if not finding.actor_id:
                finding.actor_id = ai.actor_id
                finding.actor_name = ai.actor_name
        # Fallback: hardcoded prefixes
        for actor_name, prefixes in ACTOR_C2_PREFIXES.items():
            if any(ip.startswith(p) for p in prefixes):
                attributed.add(actor_name)

    # ── 4. Ransomware feed → actor from metadata ──────────────────────────────
    meta = {}
    # Finding doesn't have metadata_ directly - check source detection
    if finding.ioc_type in ("btc_address", "domain", "ipv4") and finding.all_sources:
        if "ransomfeed" in (finding.all_sources or []):
            # Get metadata from a detection in this finding
            r3 = await db.execute(
                select(Detection).where(
                    Detection.finding_id == finding.id,
                    Detection.source == "ransomfeed",
                ).limit(1)
            )
            det = r3.scalar_one_or_none()
            if det:
                meta = det.metadata_ or {}
                group = meta.get("group") or meta.get("threat_actor", "")
                if group:
                    attributed.add(group)

    # ── 5. Malware hash → actor via DB ────────────────────────────────────────
    if finding.ioc_type in ("sha256", "md5", "sha1"):
        r4 = await db.execute(
            select(ActorIoc).where(
                ActorIoc.ioc_type.in_(["sha256", "md5", "sha1"]),
                ActorIoc.ioc_value == finding.ioc_value,
            ).limit(3)
        )
        for ai in r4.scalars().all():
            attributed.add(ai.actor_name)
            if not finding.actor_id:
                finding.actor_id = ai.actor_id
                finding.actor_name = ai.actor_name

    # ── 6. Sector → actor (weak signal - only if nothing else matched) ────────
    if not attributed and finding.customer_id:
        rc = await db.execute(
            select(Customer).where(Customer.id == finding.customer_id)
        )
        customer = rc.scalar_one_or_none()
        if customer and customer.industry:
            ra = await db.execute(
                select(ThreatActor).where(
                    func.lower(ThreatActor.description).contains(
                        customer.industry.lower()[:15]
                    )
                ).limit(3)
            )
            for actor in ra.scalars().all():
                attributed.add(actor.name)

    # If we found actors but didn't set finding.actor_id yet, set to first DB match
    if attributed and not finding.actor_id:
        for actor_name in list(attributed)[:1]:
            ar = await db.execute(
                select(ThreatActor).where(ThreatActor.name == actor_name).limit(1)
            )
            actor = ar.scalar_one_or_none()
            if actor:
                finding.actor_id = actor.id
                finding.actor_name = actor.name

    # ── Autonomous mode: AI override ─────────────────────────────────────────
    # In autonomous mode with confidence ≥ 0.80, AI can override rule-based pick.
    # In safe mode: AI only fills gaps (when no actor was attributed by rules).
    # V16.4: Also fires when ZERO attribution - AI reasons from feed context + TTPs
    _should_ai_attr = (
        (_autonomous_attribution() and len(attributed) > 1)  # disambiguation
        or (not attributed and finding.customer_id)           # V16.4: zero results fallback
    )
    if _should_ai_attr:
        try:
            from arguswatch.services.ai_pipeline_hooks import hook_attribution_assist, _pipeline_ai_available
            if _pipeline_ai_available():
                _cands_auto = await get_candidate_actors(finding, db)
                if _cands_auto:
                    _ai_pick = await hook_attribution_assist(
                        finding_id=finding.id,
                        ioc_value=finding.ioc_value or "",
                        ioc_type=finding.ioc_type or "",
                        candidate_actors=_cands_auto,
                        finding_context={},
                    )
                    # Autonomous: override if AI confidence ≥ 0.80
                    if (_ai_pick and _ai_pick.get("actor_name")
                            and _ai_pick.get("confidence", 0) >= 0.80):
                        _auto_name = _ai_pick["actor_name"]
                        _ar_auto = await db.execute(
                            select(ThreatActor).where(ThreatActor.name == _auto_name).limit(1)
                        )
                        _actor_auto = _ar_auto.scalar_one_or_none()
                        if _actor_auto:
                            finding.actor_id = _actor_auto.id
                            finding.actor_name = _actor_auto.name
                            finding.ai_attribution_reasoning = _ai_pick.get("narrative", "")
                            old_attributed = list(attributed)[:3]
                            attributed = {_auto_name}
                            logger.info(
                                f"[attribution] autonomous override: {_auto_name} "
                                f"conf={_ai_pick.get('confidence','?')} (was: {old_attributed})"
                            )
        except Exception as _auto_e:
            logger.debug(f"[attribution] autonomous AI override failed (non-fatal): {_auto_e}")

    return list(attributed)


async def get_candidate_actors(finding: Finding, db: AsyncSession) -> list[dict]:
    """
    Return all candidate actors for AI disambiguation - includes full metadata
    (target_sectors, techniques, origin_country) so AI can make an informed pick.
    
    Called by pipeline Step 6 when attribute_finding() returns >1 candidate.
    Also used directly when attribute_finding() returns nothing but sector match exists.
    """
    candidates = {}  # name → dict

    # 1. IOC exact match
    r = await db.execute(
        select(ActorIoc).where(ActorIoc.ioc_value == finding.ioc_value).limit(10)
    )
    for ai in r.scalars().all():
        if ai.actor_name not in candidates:
            candidates[ai.actor_name] = {"name": ai.actor_name, "match_type": "ioc_exact"}

    # 2. CVE actors
    if finding.ioc_type == "cve_id":
        cve_upper = finding.ioc_value.upper()
        for cve, actors in CVE_ACTOR_MAP.items():
            if cve in cve_upper or cve_upper in cve:
                for a in actors:
                    if a not in candidates:
                        candidates[a] = {"name": a, "match_type": "cve_map"}

    # 3. Sector match - fetch ThreatActor rows for full metadata
    if finding.customer_id:
        rc = await db.execute(select(Customer).where(Customer.id == finding.customer_id))
        customer = rc.scalar_one_or_none()
        if customer and customer.industry:
            ra = await db.execute(
                select(ThreatActor).where(
                    func.lower(ThreatActor.description).contains(customer.industry.lower()[:12])
                ).limit(5)
            )
            for actor in ra.scalars().all():
                if actor.name not in candidates:
                    candidates[actor.name] = {"name": actor.name, "match_type": "sector"}

    # Enrich candidates with ThreatActor metadata
    result = []
    for name, base in candidates.items():
        ra = await db.execute(select(ThreatActor).where(ThreatActor.name == name).limit(1))
        actor = ra.scalar_one_or_none()
        if actor:
            result.append({
                "name": actor.name,
                "match_type": base["match_type"],
                "target_sectors": actor.target_sectors or [],
                "techniques": actor.techniques or [],
                "origin_country": actor.origin_country or "",
                "sophistication": actor.sophistication or "",
                "motivation": actor.motivation or "",
                "mitre_id": actor.mitre_id or "",
            })
        else:
            result.append({**base, "target_sectors": [], "techniques": [],
                           "origin_country": "", "sophistication": "", "motivation": "", "mitre_id": ""})
    return result


async def attribute_detection(detection: Detection, db: AsyncSession) -> list[str]:
    """Legacy function - kept for batch pipeline compatibility.
    Creates/finds the associated Finding and calls attribute_finding().
    """
    if detection.finding_id:
        r = await db.execute(
            select(Finding).where(Finding.id == detection.finding_id)
        )
        finding = r.scalar_one_or_none()
        if finding:
            return await attribute_finding(finding, db)

    # No finding yet - attribute the detection directly using same logic
    attributed = set()
    if detection.ioc_type == "cve_id":
        cve_upper = detection.ioc_value.upper()
        for cve, actors in CVE_ACTOR_MAP.items():
            if cve in cve_upper or cve_upper in cve:
                attributed.update(actors)
    if detection.ioc_type in ("ipv4", "ipv6"):
        ip = detection.ioc_value
        for actor_name, prefixes in ACTOR_C2_PREFIXES.items():
            if any(ip.startswith(p) for p in prefixes):
                attributed.add(actor_name)
    if detection.source == "ransomfeed":
        meta = detection.metadata_ or {}
        group = meta.get("group") or meta.get("threat_actor", "")
        if group:
            attributed.add(group)
    if detection.ioc_type in ("sha256", "md5", "sha1"):
        r = await db.execute(
            select(ThreatActor).where(
                func.lower(ThreatActor.description).contains(detection.ioc_value[:12].lower())
            )
        )
        for actor in r.scalars().all():
            attributed.add(actor.name)
    return list(attributed)


async def attribute_detection_by_id(detection_id: int, db: AsyncSession) -> dict:
    """API endpoint helper - returns enriched attribution for a detection."""
    r = await db.execute(select(Detection).where(Detection.id == detection_id))
    det = r.scalar_one_or_none()
    if not det:
        return {"error": "Detection not found"}
    actors_names = await attribute_detection(det, db)
    actor_details = []
    if actors_names:
        r2 = await db.execute(
            select(ThreatActor).where(ThreatActor.name.in_(actors_names))
        )
        actor_details = [
            {"name": a.name, "mitre_id": a.mitre_id, "origin_country": a.origin_country}
            for a in r2.scalars().all()
        ]
        found = {a["name"] for a in actor_details}
        for name in actors_names:
            if name not in found:
                actor_details.append({"name": name, "mitre_id": None, "origin_country": None})
    return {
        "detection_id": detection_id,
        "ioc_value": det.ioc_value,
        "ioc_type": det.ioc_type,
        "attributed_actors": actor_details,
    }


async def update_customer_exposure(
    customer_id: int,
    actor_name: str,
    db: AsyncSession,
    new_detection: bool = False,
    darkweb_hit: bool = False,
):
    """Update or create customer×actor exposure record. Called from pipeline."""
    r = await db.execute(select(ThreatActor).where(ThreatActor.name == actor_name))
    actor = r.scalar_one_or_none()
    if not actor:
        return
    r2 = await db.execute(
        select(CustomerExposure).where(
            CustomerExposure.customer_id == customer_id,
            CustomerExposure.actor_id == actor.id,
        ).limit(1)
    )
    exposure = r2.scalar_one_or_none()
    if not exposure:
        exposure = CustomerExposure(customer_id=customer_id, actor_id=actor.id)
        db.add(exposure)
    if new_detection:
        exposure.detection_count = (exposure.detection_count or 0) + 1
    if darkweb_hit:
        exposure.darkweb_mentions = (exposure.darkweb_mentions or 0) + 1
    await db.flush()


async def run_attribution_pass(db: AsyncSession, limit: int = 200) -> dict:
    """Batch attribution over recent unattributed findings."""
    r = await db.execute(
        select(Finding).where(
            Finding.actor_id == None,
            Finding.customer_id != None,
        ).order_by(Finding.created_at.desc()).limit(limit)
    )
    findings = r.scalars().all()
    stats = {"processed": len(findings), "attributed": 0, "exposure_updates": 0}
    for f in findings:
        actors = await attribute_finding(f, db)
        if actors:
            stats["attributed"] += 1
            for actor_name in actors:
                await update_customer_exposure(f.customer_id, actor_name, db, new_detection=True)
                stats["exposure_updates"] += 1
    await db.flush()
    return stats


from arguswatch.celery_app import celery_app as _celery_app


@_celery_app.task(name="arguswatch.engine.attribution_engine.run_attribution_task")
def run_attribution_task():
    import asyncio
    from arguswatch.database import async_session
    async def _run():
        async with async_session() as db:
            return await run_attribution_pass(db)
    return asyncio.run(_run())
