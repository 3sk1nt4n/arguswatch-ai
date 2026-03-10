"""
Enrichment Feedback - reads VT/AbuseIPDB/OTX results and feeds intelligence
back into the finding.

Called AFTER enrichment completes. Takes enrichment rows -> updates finding:
 - malware_family detected by VT -> attribution lookup
 - VT malicious score > 30 -> severity upgrade to HIGH/CRITICAL
 - AbuseIPDB confidence > 80 -> confidence boost + C2 role flag
 - CPE data from NVD -> additional tech_stack matches (re-run routing for CVEs)
 - abuse_reports count -> source_count bump on the finding

This closes the feedback loop:
  raw IOC -> enrichment -> enrichment tells us MORE about the IOC -> update finding
"""
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from arguswatch.models import (
    Finding, Enrichment, Detection, SeverityLevel, ThreatActor,
    ActorIoc, CveProductMap, CustomerAsset, AssetType, DetectionStatus
)
from arguswatch.config import settings

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


logger = logging.getLogger("arguswatch.engine.enrichment_feedback")

SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _autonomous() -> bool:
    """True when AI_AUTONOMOUS=true in config - AI makes final decisions."""
    return getattr(settings, "AI_AUTONOMOUS", False)


async def process_enrichment_feedback(finding_id: int, db: AsyncSession) -> dict:
    """Read all enrichment results for a finding's detections and update the finding.

    Returns a summary dict of what changed.
    """
    # Get the finding
    r = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = r.scalar_one_or_none()
    if not finding:
        return {"error": "finding not found"}

    # Get all enrichments across all detections of this finding
    enrich_r = await db.execute(
        select(Enrichment)
        .join(Detection, Enrichment.detection_id == Detection.id)
        .where(Detection.finding_id == finding_id)
    )
    enrichments = enrich_r.scalars().all()

    changes = {
        "severity_upgraded": False,
        "confidence_boosted": False,
        "actor_attributed": None,
        "tech_stack_matches": [],
        "vt_malicious": 0,
        "abuse_confidence": 0,
    }

    vt_data = next((e for e in enrichments if e.provider == "virustotal"), None)
    abuse_data = next((e for e in enrichments if e.provider == "abuseipdb"), None)
    otx_data = next((e for e in enrichments if e.provider == "otx"), None)
    nvd_data = next((e for e in enrichments if e.provider == "nvd"), None)

    # ── VirusTotal feedback ───────────────────────────────────────────────────
    if vt_data and vt_data.data:
        malicious = vt_data.data.get("malicious", 0)
        changes["vt_malicious"] = malicious

        # Severity upgrade
        current_rank = SEV_RANK.get(_sev(finding.severity) or "MEDIUM", 2)
        if malicious >= 30 and current_rank < SEV_RANK["CRITICAL"]:
            finding.severity = SeverityLevel.CRITICAL
            changes["severity_upgraded"] = True
        elif malicious >= 10 and current_rank < SEV_RANK["HIGH"]:
            finding.severity = SeverityLevel.HIGH
            changes["severity_upgraded"] = True

        # Confidence boost
        if malicious >= 5:
            finding.confidence = min(0.99, finding.confidence + 0.10)
            changes["confidence_boosted"] = True

        # Malware family -> attribution
        malware_family = vt_data.data.get("popular_threat_name") or vt_data.data.get("malware_family")
        if malware_family:
            actor = await _lookup_actor_by_malware(malware_family, db)
            if actor and not finding.actor_id:
                finding.actor_id = actor.id
                finding.actor_name = actor.name
                changes["actor_attributed"] = actor.name
                logger.info(
                    f"Finding {finding_id} attributed to {actor.name} "
                    f"via VT malware family '{malware_family}'"
                )

    # ── AbuseIPDB feedback ────────────────────────────────────────────────────
    if abuse_data and abuse_data.data:
        abuse_confidence = abuse_data.data.get("abuse_confidence", 0)
        changes["abuse_confidence"] = abuse_confidence

        if abuse_confidence >= 80:
            finding.confidence = min(0.99, finding.confidence + 0.12)
            changes["confidence_boosted"] = True
            # High abuse score + IP = likely C2
            if finding.ioc_type in ("ipv4", "ipv6") and not finding.actor_id:
                # Try to attribute via actor_iocs table
                actor = await _lookup_actor_by_ioc(finding.ioc_value, finding.ioc_type, db)
                if actor:
                    finding.actor_id = actor.id
                    finding.actor_name = actor.name
                    changes["actor_attributed"] = actor.name

    # ── OTX feedback ─────────────────────────────────────────────────────────
    if otx_data and otx_data.data:
        pulse_count = otx_data.data.get("pulse_count", 0)
        if pulse_count >= 5:
            finding.confidence = min(0.99, finding.confidence + 0.08)
            changes["confidence_boosted"] = True

        # OTX can provide malware families too
        malware = otx_data.data.get("malware_families", [])
        if malware and not finding.actor_id:
            for mf in malware[:3]:
                actor = await _lookup_actor_by_malware(mf, db)
                if actor:
                    finding.actor_id = actor.id
                    finding.actor_name = actor.name
                    changes["actor_attributed"] = actor.name
                    break

    # ── NVD / CVE feedback ────────────────────────────────────────────────────
    # If this is a CVE finding, check if the customer has matching tech_stack assets
    if finding.ioc_type == "cve_id" and finding.customer_id and nvd_data:
        affected_products = nvd_data.data.get("affected_products", [])
        if affected_products:
            new_matches = await _match_cve_to_tech_stack(
                finding.customer_id, affected_products, db
            )
            if new_matches:
                changes["tech_stack_matches"] = new_matches
                # If this CVE affects a tech_stack the customer owns, boost severity
                if finding.severity and SEV_RANK.get(_sev(finding.severity), 0) < SEV_RANK["HIGH"]:
                    finding.severity = SeverityLevel.HIGH
                    changes["severity_upgraded"] = True
                logger.info(
                    f"Finding {finding_id} CVE {finding.ioc_value} matches "
                    f"customer tech_stack: {new_matches}"
                )

    # ── Autonomous mode: AI false-positive check ─────────────────────────────
    # In safe mode: FP is flagged in metadata but finding stays open.
    # In autonomous mode: AI auto-closes the finding if confidence > 75%.
    if _autonomous():
        try:
            from arguswatch.services.ai_pipeline_hooks import hook_false_positive_check, _pipeline_ai_available
            if _pipeline_ai_available():
                from arguswatch.models import Customer
                _cctx_fp = {}
                if finding.customer_id:
                    _rc_fp = await db.execute(select(Customer).where(Customer.id == finding.customer_id))
                    _c_fp = _rc_fp.scalar_one_or_none()
                    if _c_fp:
                        _cctx_fp = {
                            "industry": getattr(_c_fp, "industry", ""),
                            "matched_asset": finding.matched_asset or "",
                        }
                _fp_result = await hook_false_positive_check(
                    ioc_type=finding.ioc_type or "",
                    ioc_value=finding.ioc_value or "",
                    source=(finding.all_sources or ["unknown"])[0],
                    enrichment_data={
                        "vt_malicious": changes.get("vt_malicious", 0),
                        "abuse_score": changes.get("abuse_confidence", 0),
                    },
                    customer_context=_cctx_fp,
                )
                if _fp_result and _fp_result.get("is_fp") and _fp_result.get("confidence", 0) > 0.75:
                    finding.ai_false_positive_flag = True
                    finding.ai_false_positive_reason = _fp_result.get("reason", "")
                    finding.status = DetectionStatus.FALSE_POSITIVE
                    finding.resolved_at = __import__("datetime").datetime.utcnow()
                    changes["auto_closed_fp"] = True
                    changes["fp_reason"] = _fp_result.get("reason", "")
                    logger.info(
                        f"[enrichment] autonomous FP auto-close: finding {finding.id} "
                        f"reason={_fp_result.get('reason','')[:60]}"
                    )
                elif _fp_result:
                    # Safe-mode fallback: flag but don't close
                    finding.ai_false_positive_flag = bool(_fp_result.get("is_fp"))
                    finding.ai_false_positive_reason = _fp_result.get("reason", "")
                    changes["fp_flag"] = bool(_fp_result.get("is_fp"))
        except Exception as _fp_e:
            logger.debug(f"[enrichment] AI FP check failed (non-fatal): {_fp_e}")
    else:
        # Safe mode: run FP check but only flag, never auto-close
        try:
            from arguswatch.services.ai_pipeline_hooks import hook_false_positive_check, _pipeline_ai_available
            if _pipeline_ai_available():
                _fp_safe = await hook_false_positive_check(
                    ioc_type=finding.ioc_type or "",
                    ioc_value=finding.ioc_value or "",
                    source=(finding.all_sources or ["unknown"])[0],
                    enrichment_data={
                        "vt_malicious": changes.get("vt_malicious", 0),
                        "abuse_score": changes.get("abuse_confidence", 0),
                    },
                    customer_context={},
                )
                if _fp_safe and _fp_safe.get("is_fp"):
                    finding.ai_false_positive_flag = True
                    finding.ai_false_positive_reason = _fp_safe.get("reason", "")
                    changes["fp_flag"] = True
                    logger.info(
                        f"[enrichment] safe-mode FP flag: finding {finding.id} "
                        f"(not auto-closed, needs analyst review)"
                    )
        except Exception as _fps_e:
            logger.debug(f"[enrichment] safe-mode FP check failed: {_fps_e}")

    await db.flush()
    return changes


async def _lookup_actor_by_malware(malware_family: str, db: AsyncSession):
    """Find threat actor linked to a malware family name via DB."""
    mf_lower = malware_family.lower()
    # Check actor description and aliases for malware family name
    r = await db.execute(
        select(ThreatActor).where(
            func.lower(ThreatActor.description).contains(mf_lower)
        ).limit(1)
    )
    actor = r.scalar_one_or_none()
    if actor:
        return actor
    # Also check actor_iocs for malware hashes associated with this family
    r2 = await db.execute(
        select(ThreatActor)
        .join(ActorIoc, ActorIoc.actor_id == ThreatActor.id)
        .where(func.lower(ActorIoc.ioc_value).contains(mf_lower))
        .limit(1)
    )
    return r2.scalar_one_or_none()


async def _lookup_actor_by_ioc(ioc_value: str, ioc_type: str, db: AsyncSession):
    """Check actor_iocs table for known actor associated with this IOC."""
    r = await db.execute(
        select(ThreatActor)
        .join(ActorIoc, ActorIoc.actor_id == ThreatActor.id)
        .where(ActorIoc.ioc_value == ioc_value)
        .limit(1)
    )
    actor = r.scalar_one_or_none()
    if actor:
        return actor
    # Prefix match for IPs (C2 range matching)
    if ioc_type in ("ipv4", "ipv6"):
        prefix = ".".join(ioc_value.split(".")[:3]) + "."
        r2 = await db.execute(
            select(ThreatActor)
            .join(ActorIoc, ActorIoc.actor_id == ThreatActor.id)
            .where(
                ActorIoc.ioc_type == "ipv4",
                ActorIoc.ioc_value.like(prefix + "%")
            )
            .limit(1)
        )
        return r2.scalar_one_or_none()
    return None


async def _match_cve_to_tech_stack(
    customer_id: int,
    affected_products: list[str],
    db: AsyncSession,
) -> list[str]:
    """Check if any of the CVE's affected products match this customer's tech_stack assets."""
    r = await db.execute(
        select(CustomerAsset).where(
            CustomerAsset.customer_id == customer_id,
            CustomerAsset.asset_type == AssetType.TECH_STACK,
        )
    )
    tech_assets = r.scalars().all()
    matches = []
    for asset in tech_assets:
        asset_product = asset.asset_value.lower().split()[0]  # "FortiOS" from "FortiOS 7.2"
        for affected in affected_products:
            if asset_product in affected.lower() or affected.lower() in asset.asset_value.lower():
                matches.append(f"{asset.asset_value} ← {affected}")
                break
    return matches
