"""
AI Prompt Manager -  Editable system prompts for all 9 AI hooks.
MITRE Auto-Sync -  Keep IOC↔technique mappings current.

PROMPT MANAGEMENT:
  Every AI hook reads its prompt from the ai_prompts DB table.
  Fallback: if no DB row exists, uses the hardcoded default.
  Industry overrides: {"healthcare": "Focus on HIPAA PHI...", "financial": "Focus on PCI DSS..."}
  Admin API: CRUD + test + version history.

MITRE AUTO-SYNC:
  Pulls latest ATT&CK data from MITRE STIX endpoint.
  Compares technique IDs in ioc_type_registry against current ATT&CK.
  Flags deprecated techniques. Suggests new mappings.
  Runs on schedule (weekly) or on-demand via API.

USAGE:
  from arguswatch.engine.ai_prompt_manager import get_prompt, sync_mitre_attack
  
  prompt = await get_prompt("ai_triage", db, industry="healthcare")
  # Returns industry-specific prompt if override exists, else default
  
  sync_result = await sync_mitre_attack(db)
  # Returns {"version": "15.1", "deprecated": [...], "suggestions": [...]}
"""
import logging
import time as _time
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

logger = logging.getLogger("arguswatch.ai_prompt_manager")

# ══════════════════════════════════════════════════════════════════════
# DEFAULT PROMPTS -  used as fallback when DB has no entry
# ══════════════════════════════════════════════════════════════════════

DEFAULT_PROMPTS = {
    "ai_triage": {
        "system_prompt": "You are a SOC triage analyst. Set the severity for this IOC based on evidence. Consider enrichment data, source reliability, and customer industry context. Respond with JSON: {severity, sla_hours, confidence, reasoning}.",
        "temperature": 0.2,
    },
    "false_positive_check": {
        "system_prompt": "You are a senior SOC analyst checking for false positives. Consider: is this IOC in a legitimate context? Is the source reliable? Could this be a test/demo/documentation value? Respond with JSON: {is_fp, confidence, reason}.",
        "temperature": 0.2,
    },
    "investigation_narrative": {
        "system_prompt": "Write a 2-3 sentence investigation narrative for an analyst dashboard. Be specific -  cite the actual IOC value, detection counts, and actor name. Explain the business risk in plain language. State the recommended first action.",
        "temperature": 0.3,
    },
    "attribution": {
        "system_prompt": "You are a threat attribution analyst. Based on the IOC type, source feed, and any enrichment data, identify the most likely threat actor responsible. Consider known TTPs, target sectors, and geographic patterns.",
        "temperature": 0.2,
    },
    "campaign_briefing": {
        "system_prompt": "Write a 2-3 sentence threat campaign briefing for an executive. Explain what's happening, who's behind it, and what business impact to expect. Use plain language, no jargon.",
        "temperature": 0.3,
    },
    "rescore_severity": {
        "system_prompt": "You are a SOC analyst re-assessing finding severity after enrichment and attribution. Consider: has new evidence changed the risk? Is enrichment data confirming or contradicting the initial score?",
        "temperature": 0.2,
    },
    "remediation": {
        "system_prompt": "You are a senior SOC remediation analyst. Write SPECIFIC, actionable remediation steps for this finding. Include exact commands, tool names, and verification steps. Each step should be executable by a junior analyst.",
        "temperature": 0.3,
    },
    "exposure_interpretation": {
        "system_prompt": "You are a cybersecurity risk analyst. Interpret this customer's exposure score using the D1-D5 dimension breakdown. Explain which dimensions drive the risk and what concrete actions would reduce the score.",
        "temperature": 0.3,
    },
    "match_confidence": {
        "system_prompt": "You are a threat intelligence analyst reviewing a match between a threat indicator and a customer. Score the match confidence from 0.0 to 1.0. Consider: is this a direct match or circumstantial? Could it be a false positive?",
        "temperature": 0.2,
    },
}

# ══════════════════════════════════════════════════════════════════════
# PROMPT LOADER -  cached, with DB override and industry specialization
# ══════════════════════════════════════════════════════════════════════

_prompt_cache: dict = {}
_prompt_cache_time: float = 0
_PROMPT_CACHE_TTL = 120  # 2 minutes


async def get_prompt(hook_name: str, db: AsyncSession, industry: str = "") -> dict:
    """Get the system prompt for an AI hook.

    Priority:
      1. DB row with industry override matching customer's industry
      2. DB row default prompt
      3. Hardcoded DEFAULT_PROMPTS fallback

    Returns: {"system_prompt": str, "temperature": float, "max_tokens": int}
    """
    global _prompt_cache, _prompt_cache_time
    now = _time.time()

    # Refresh cache
    if not _prompt_cache or (now - _prompt_cache_time) > _PROMPT_CACHE_TTL:
        try:
            r = await db.execute(text("SELECT * FROM ai_prompts WHERE active = true"))
            rows = r.mappings().all()
            _prompt_cache = {row["hook_name"]: dict(row) for row in rows}
            _prompt_cache_time = now
        except Exception as e:
            logger.debug(f"AI prompts cache refresh failed: {e}")

    # Check DB
    entry = _prompt_cache.get(hook_name)
    if entry:
        prompt_text = entry["system_prompt"]
        # Industry override
        overrides = entry.get("industry_override") or {}
        if isinstance(overrides, dict) and industry.lower() in overrides:
            prompt_text = overrides[industry.lower()]
            logger.debug(f"[prompt] {hook_name}: using {industry} industry override")

        return {
            "system_prompt": prompt_text,
            "temperature": entry.get("temperature", 0.2),
            "max_tokens": entry.get("max_tokens", 2048),
        }

    # Fallback to hardcoded
    default = DEFAULT_PROMPTS.get(hook_name, {})
    return {
        "system_prompt": default.get("system_prompt", f"You are a cybersecurity AI assistant. Hook: {hook_name}"),
        "temperature": default.get("temperature", 0.2),
        "max_tokens": 2048,
    }


async def seed_default_prompts(db: AsyncSession):
    """Seed ai_prompts table with defaults (first run only)."""
    try:
        count_r = await db.execute(text("SELECT COUNT(*) FROM ai_prompts"))
        if (count_r.scalar() or 0) > 0:
            return
    except Exception:
        return

    for hook_name, defaults in DEFAULT_PROMPTS.items():
        try:
            await db.execute(text("""
                INSERT INTO ai_prompts (hook_name, system_prompt, temperature)
                VALUES (:hook, :prompt, :temp)
                ON CONFLICT (hook_name) DO NOTHING
            """), {
                "hook": hook_name,
                "prompt": defaults["system_prompt"],
                "temp": defaults.get("temperature", 0.2),
            })
        except Exception as e:
            logger.debug(f"Prompt seed error for {hook_name}: {e}")
    await db.commit()
    logger.info(f"AI prompts seeded: {len(DEFAULT_PROMPTS)} hooks")


# ══════════════════════════════════════════════════════════════════════
# MITRE ATT&CK AUTO-SYNC
# ══════════════════════════════════════════════════════════════════════

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


async def sync_mitre_attack(db: AsyncSession) -> dict:
    """Pull latest MITRE ATT&CK, compare with ioc_type_registry, flag issues.

    Returns:
        {
            "version": "15.1",
            "total_techniques": 625,
            "deprecated_in_registry": ["T1234", ...],
            "new_techniques": ["T1659", ...],
            "suggestions": [{"ioc_type": "...", "current": "T1552.004", "issue": "deprecated", "suggested": "T1552.006"}],
        }
    """
    import httpx

    result = {
        "version": "unknown", "total_techniques": 0,
        "deprecated_in_registry": [], "suggestions": [],
    }

    # Pull MITRE data
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(MITRE_STIX_URL)
            if r.status_code != 200:
                return {**result, "error": f"MITRE fetch failed: HTTP {r.status_code}"}
            stix_data = r.json()
    except Exception as e:
        return {**result, "error": f"MITRE fetch error: {str(e)[:100]}"}

    # Parse techniques
    techniques = {}  # {technique_id: {name, deprecated, tactics}}
    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_refs = obj.get("external_references", [])
        tech_id = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                break
        if not tech_id:
            continue
        deprecated = obj.get("x_mitre_deprecated", False) or obj.get("revoked", False)
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))
        techniques[tech_id] = {
            "name": obj.get("name", ""),
            "deprecated": deprecated,
            "tactics": tactics,
        }

    # Get version
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            result["version"] = obj.get("x_mitre_version", "unknown")
            break

    result["total_techniques"] = len(techniques)
    active_techniques = {k for k, v in techniques.items() if not v["deprecated"]}
    deprecated_techniques = {k for k, v in techniques.items() if v["deprecated"]}

    # Compare with registry
    try:
        reg_r = await db.execute(text(
            "SELECT type_name, mitre_technique, mitre_tactic FROM ioc_type_registry WHERE active = true AND mitre_technique IS NOT NULL"
        ))
        registry_rows = reg_r.mappings().all()
    except Exception as e:
        return {**result, "error": f"Registry query failed: {e}"}

    for row in registry_rows:
        tech = row["mitre_technique"]
        if not tech:
            continue

        if tech in deprecated_techniques:
            result["deprecated_in_registry"].append(tech)
            # Try to suggest a replacement
            old_name = techniques[tech]["name"]
            # Look for a non-deprecated technique with similar name
            suggested = None
            for active_id in active_techniques:
                if techniques[active_id]["name"].lower() == old_name.lower():
                    suggested = active_id
                    break
            result["suggestions"].append({
                "ioc_type": row["type_name"],
                "current_technique": tech,
                "issue": "deprecated",
                "technique_name": old_name,
                "suggested_replacement": suggested,
            })

        elif tech not in techniques:
            result["suggestions"].append({
                "ioc_type": row["type_name"],
                "current_technique": tech,
                "issue": "not_found_in_attack",
                "technique_name": "unknown",
                "suggested_replacement": None,
            })

    # Log sync
    try:
        await db.execute(text("""
            INSERT INTO mitre_sync_log 
                (attack_version, techniques_total, techniques_deprecated, ioc_types_flagged, details)
            VALUES (:ver, :total, :dep, :flagged, :details)
        """), {
            "ver": result["version"],
            "total": len(techniques),
            "dep": len(deprecated_techniques),
            "flagged": len(result["deprecated_in_registry"]),
            "details": str(result["suggestions"][:10]),
        })
        await db.commit()
    except Exception as e:
        logger.debug(f"MITRE sync log error: {e}")

    logger.info(
        f"MITRE sync: v{result['version']}, {len(techniques)} techniques, "
        f"{len(result['deprecated_in_registry'])} deprecated in registry"
    )
    return result
