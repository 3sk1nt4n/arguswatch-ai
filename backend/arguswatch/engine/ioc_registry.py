"""
IOC Type Registry -  Single Source of Truth for All Pipeline Stages
===================================================================
REPLACES: 6 hardcoded Python dicts across severity_scorer.py, campaign_detector.py,
          playbooks.py, enrichment_pipeline.py, pattern_matcher.py, dashboard.js

HOW IT WORKS:
  1. On startup, _seed_from_legacy() merges all hardcoded dicts into the DB table
  2. get_registry() returns a cached dict of all active types (refreshes every 60s)
  3. Every pipeline stage calls get_registry() instead of its own hardcoded dict
  4. Admin API allows adding/editing types at runtime -  no redeploy needed

AUTO-CRITICALITY SCORING:
  base_severity is the static default from the registry.
  calculate_dynamic_severity() computes runtime severity from 8 weighted factors:
    F1: Base severity (0.20)         -  what the type normally is
    F2: Kill chain stage (0.15)      -  later stage = more critical
    F3: Enrichment data (0.20)       -  active key, VT score, breach freshness
    F4: Source reliability (0.10)    -  PROVEN vs THEORETICAL
    F5: Temporal freshness (0.05)   -  how recent is the detection
    F6: Industry context (0.10)     -  PII in healthcare = escalate
    F7: MITRE tactic weight (0.10)  -  Impact > Recon
    F8: Exposure confirmed (0.10)   -  confirmed = escalate

  Output: CRITICAL (≥0.80) | HIGH (≥0.60) | MEDIUM (≥0.40) | LOW (≥0.20) | INFO (<0.20)
  SLA auto-adjusts: CRITICAL=2h, HIGH=8h, MEDIUM=48h, LOW=120h, INFO=720h

USAGE:
  from arguswatch.engine.ioc_registry import get_registry, get_type, calculate_dynamic_severity
  
  reg = await get_registry(db)       # cached dict of all types
  t = reg.get("aws_access_key")      # single type entry
  
  sev = calculate_dynamic_severity(
      ioc_type="aws_access_key",
      enrichment={"active": True},
      source_status="PROVEN",
      detection_age_days=0,
      customer_industry="financial",
      exposure_confirmed=True,
      registry_entry=t,
  )
  # Returns: {"severity": "CRITICAL", "sla_hours": 2, "score": 0.94, "factors": {...}}
"""
import logging
import time as _time
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text

logger = logging.getLogger("arguswatch.ioc_registry")

# ══════════════════════════════════════════════════════════════════════
# IN-MEMORY CACHE -  refreshes every 60 seconds
# ══════════════════════════════════════════════════════════════════════

_cache: dict = {}
_cache_time: float = 0
_CACHE_TTL = 60  # seconds


async def get_registry(db: AsyncSession) -> dict:
    """Get the full IOC type registry as a dict keyed by type_name.
    Cached in memory for 60 seconds.
    """
    global _cache, _cache_time
    now = _time.time()
    if _cache and (now - _cache_time) < _CACHE_TTL:
        return _cache

    try:
        r = await db.execute(text(
            "SELECT * FROM ioc_type_registry WHERE active = true ORDER BY type_name"
        ))
        rows = r.mappings().all()
        _cache = {row["type_name"]: dict(row) for row in rows}
        _cache_time = now
        logger.debug(f"IOC registry loaded: {len(_cache)} active types")
    except Exception as e:
        logger.warning(f"IOC registry load failed (using cache): {e}")
        if not _cache:
            # Table might not exist yet -  return empty
            _cache = {}

    return _cache


def get_type_sync(type_name: str) -> dict | None:
    """Synchronous cache-only lookup (no DB call). Use after get_registry() has loaded."""
    return _cache.get(type_name)


def invalidate_cache():
    """Force cache refresh on next get_registry() call."""
    global _cache_time
    _cache_time = 0


# ══════════════════════════════════════════════════════════════════════
# AUTO-CRITICALITY SCORING ENGINE
# ══════════════════════════════════════════════════════════════════════

# Static mappings for factor calculations
_SEV_SCORE = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25, "INFO": 0.1}

_STAGE_SCORE = {
    "persistence": 1.0, "exfiltration": 0.85, "c2": 0.7,
    "exploitation": 0.55, "delivery": 0.4, "recon": 0.25,
}

_TACTIC_SCORE = {
    "Impact": 1.0, "Exfiltration": 0.9, "Lateral Movement": 0.85,
    "Credential Access": 0.8, "Command and Control": 0.7,
    "Persistence": 0.65, "Defense Evasion": 0.6, "Privilege Escalation": 0.6,
    "Collection": 0.55, "Execution": 0.5, "Discovery": 0.4,
    "Initial Access": 0.45, "Resource Development": 0.3, "Reconnaissance": 0.25,
}

_STATUS_SCORE = {"PROVEN": 1.0, "WORKING": 0.7, "THEORETICAL": 0.4}

# Default weights (can be overridden from criticality_weights table)
_DEFAULT_WEIGHTS = {
    "base_severity": 0.20,
    "kill_chain_stage": 0.15,
    "enrichment_data": 0.20,
    "source_reliability": 0.10,
    "temporal_freshness": 0.05,
    "industry_context": 0.10,
    "mitre_tactic": 0.10,
    "exposure_confirmed": 0.10,
}

# Industry + IOC type escalation rules
_INDUSTRY_ESCALATION = {
    ("healthcare", "ssn"): 1.0,
    ("healthcare", "csv_pii_dump"): 1.0,
    ("financial", "visa_card"): 1.0,
    ("financial", "mastercard"): 1.0,
    ("financial", "iban"): 1.0,
    ("financial", "email_password_combo"): 0.9,
    ("technology", "aws_access_key"): 0.9,
    ("technology", "github_pat_classic"): 0.9,
    ("government", "apt_group"): 1.0,
    ("government", "golden_ticket_indicator"): 1.0,
    ("defense", "apt_group"): 1.0,
}


def calculate_dynamic_severity(
    ioc_type: str,
    enrichment: dict | None = None,
    source_status: str = "WORKING",
    detection_age_days: float = 0,
    customer_industry: str = "",
    exposure_confirmed: bool = False,
    registry_entry: dict | None = None,
    weights: dict | None = None,
) -> dict:
    """Calculate runtime severity from 8 weighted factors.

    Returns:
        {
            "severity": "CRITICAL",
            "sla_hours": 2,
            "score": 0.94,
            "factors": {
                "base_severity": {"value": 1.0, "weight": 0.20, "contribution": 0.20},
                ...
            },
            "auto_scored": True,
            "override_reason": "Active key + healthcare industry"
        }
    """
    w = weights or _DEFAULT_WEIGHTS
    enrichment = enrichment or {}
    reg = registry_entry or {}

    factors = {}

    # F1: Base severity from registry
    base_sev = (reg.get("base_severity") or "MEDIUM").upper()
    f1 = _SEV_SCORE.get(base_sev, 0.5)
    factors["base_severity"] = {"value": f1, "weight": w["base_severity"]}

    # F2: Kill chain stage position
    stage = reg.get("kill_chain_stage", "")
    f2 = _STAGE_SCORE.get(stage, 0.3)
    # Apply type-specific multiplier if set
    f2 *= reg.get("kill_chain_weight", 1.0)
    factors["kill_chain_stage"] = {"value": min(f2, 1.0), "weight": w["kill_chain_stage"]}

    # F3: Enrichment data -  the most dynamic factor
    f3 = _score_enrichment(enrichment)
    factors["enrichment_data"] = {"value": f3, "weight": w["enrichment_data"]}

    # F4: Source reliability (PROVEN/WORKING/THEORETICAL)
    f4 = _STATUS_SCORE.get(source_status, 0.5)
    factors["source_reliability"] = {"value": f4, "weight": w["source_reliability"]}

    # F5: Temporal freshness -  decay over time
    if detection_age_days <= 1:
        f5 = 1.0
    elif detection_age_days <= 7:
        f5 = 0.8
    elif detection_age_days <= 30:
        f5 = 0.5
    elif detection_age_days <= 90:
        f5 = 0.3
    else:
        f5 = 0.1
    factors["temporal_freshness"] = {"value": f5, "weight": w["temporal_freshness"]}

    # F6: Industry context -  certain IOC+industry combos escalate
    industry = (customer_industry or "").lower()
    industry_key = (industry, ioc_type)
    f6 = _INDUSTRY_ESCALATION.get(industry_key, 0.5)
    # Also check category-level escalation
    if f6 == 0.5:
        category = (reg.get("category") or "").lower()
        if industry in ("healthcare",) and "pii" in category:
            f6 = 0.9
        elif industry in ("financial",) and "credential" in category:
            f6 = 0.85
        elif industry in ("government", "defense") and "threat intel" in category:
            f6 = 0.9
    factors["industry_context"] = {"value": f6, "weight": w["industry_context"]}

    # F7: MITRE tactic weight
    tactic = reg.get("mitre_tactic", "")
    f7 = _TACTIC_SCORE.get(tactic, 0.4)
    f7 *= reg.get("tactic_weight", 1.0)
    factors["mitre_tactic"] = {"value": min(f7, 1.0), "weight": w["mitre_tactic"]}

    # F8: Exposure confirmed
    f8 = 1.0 if exposure_confirmed else 0.2
    factors["exposure_confirmed"] = {"value": f8, "weight": w["exposure_confirmed"]}

    # ── Calculate weighted score ──
    total_score = sum(f["value"] * f["weight"] for f in factors.values())
    # Add contribution to each factor for transparency
    for f in factors.values():
        f["contribution"] = round(f["value"] * f["weight"], 4)

    # ── Map score -> severity + SLA ──
    if total_score >= 0.80:
        severity, sla = "CRITICAL", 2
    elif total_score >= 0.60:
        severity, sla = "HIGH", 8
    elif total_score >= 0.40:
        severity, sla = "MEDIUM", 48
    elif total_score >= 0.20:
        severity, sla = "LOW", 120
    else:
        severity, sla = "INFO", 720

    # ── Build override reason (explain WHY this severity) ──
    top_factors = sorted(factors.items(), key=lambda x: x[1]["contribution"], reverse=True)[:3]
    reason_parts = [f"{name}={f['value']:.1f}" for name, f in top_factors]
    override_reason = f"Auto-scored: {', '.join(reason_parts)} -> {total_score:.2f}"

    return {
        "severity": severity,
        "sla_hours": sla,
        "score": round(total_score, 4),
        "factors": factors,
        "auto_scored": True,
        "override_reason": override_reason,
    }


def _score_enrichment(enrichment: dict) -> float:
    """Score enrichment data quality. Higher = more confirmed/dangerous."""
    if not enrichment:
        return 0.3  # No enrichment data -  moderate uncertainty

    score = 0.3  # base

    # Active key = maximum enrichment confidence
    if enrichment.get("active") is True:
        return 1.0
    if enrichment.get("active") is False:
        return 0.15  # Revoked key = low risk

    # VT malicious engines
    vt_mal = enrichment.get("vt_malicious") or enrichment.get("malicious", 0)
    if isinstance(vt_mal, (int, float)):
        if vt_mal >= 20:
            score = max(score, 0.95)
        elif vt_mal >= 10:
            score = max(score, 0.8)
        elif vt_mal >= 5:
            score = max(score, 0.65)
        elif vt_mal >= 1:
            score = max(score, 0.5)

    # Abuse confidence
    abuse = enrichment.get("abuse_confidence", 0)
    if isinstance(abuse, (int, float)) and abuse > 80:
        score = max(score, 0.9)

    # Stealer log confirmed
    if enrichment.get("compromised") is True:
        stealer_count = enrichment.get("stealer_count", 0)
        score = max(score, min(0.95, 0.7 + stealer_count * 0.05))

    # Publicly accessible (SaaS misconfig)
    if enrichment.get("publicly_accessible") is True:
        score = max(score, 0.9)

    # Complete AWS key pair
    if enrichment.get("complete_pair") is True:
        score = max(score, 0.95)

    # Token issuer malicious
    if enrichment.get("vt_malicious", 0) > 5:
        score = max(score, 0.8)

    return score


# ══════════════════════════════════════════════════════════════════════
# SEED FROM LEGACY -  merge hardcoded dicts into DB on first startup
# ══════════════════════════════════════════════════════════════════════

async def seed_from_legacy(db: AsyncSession):
    """Populate ioc_type_registry from hardcoded dicts.
    Only inserts types that don't already exist (idempotent).
    Called once during startup.
    """
    # Check if table has data
    try:
        count_r = await db.execute(text("SELECT COUNT(*) FROM ioc_type_registry"))
        count = count_r.scalar() or 0
        if count > 0:
            logger.info(f"IOC registry already has {count} entries -  skipping seed")
            return
    except Exception as e:
        logger.warning(f"IOC registry table may not exist: {e}")
        return

    logger.info("Seeding IOC registry from legacy hardcoded dicts...")

    # Import all legacy dicts
    try:
        from arguswatch.engine.severity_scorer import IOC_SLA_MAP, IOC_MITRE_MAP
        from arguswatch.engine.campaign_detector import IOC_KILL_CHAIN
        from arguswatch.engine.playbooks import get_playbook
    except ImportError as e:
        logger.error(f"Cannot import legacy dicts for seeding: {e}")
        return

    # Merge all type names
    all_types = set(IOC_SLA_MAP.keys()) | set(IOC_MITRE_MAP.keys()) | set(IOC_KILL_CHAIN.keys())

    inserted = 0
    for type_name in sorted(all_types):
        # Severity + SLA
        sla_entry = IOC_SLA_MAP.get(type_name)
        base_severity = sla_entry[0] if sla_entry else "MEDIUM"
        sla_hours = sla_entry[1] if sla_entry else 48
        assignee = sla_entry[2] if sla_entry else "secops"

        # MITRE
        mitre_entry = IOC_MITRE_MAP.get(type_name)
        mitre_tech = mitre_entry[0] if mitre_entry else None
        mitre_tactic = mitre_entry[1] if mitre_entry else None
        mitre_desc = mitre_entry[2] if mitre_entry else None

        # Kill chain
        kc_stage = IOC_KILL_CHAIN.get(type_name)

        # Playbook
        pb = get_playbook(type_name, "")
        pb_key = pb.ioc_type if pb else "generic"

        await db.execute(text("""
            INSERT INTO ioc_type_registry 
                (type_name, base_severity, sla_hours, assignee_role,
                 mitre_technique, mitre_tactic, mitre_description,
                 kill_chain_stage, playbook_key, status)
            VALUES 
                (:type_name, :sev, :sla, :assignee,
                 :mitre_tech, :mitre_tactic, :mitre_desc,
                 :kc_stage, :pb_key, 'WORKING')
            ON CONFLICT (type_name) DO NOTHING
        """), {
            "type_name": type_name, "sev": base_severity, "sla": sla_hours,
            "assignee": assignee, "mitre_tech": mitre_tech,
            "mitre_tactic": mitre_tactic, "mitre_desc": mitre_desc,
            "kc_stage": kc_stage, "pb_key": pb_key,
        })
        inserted += 1

    await db.commit()
    logger.info(f"IOC registry seeded: {inserted} types from legacy dicts")
    invalidate_cache()
