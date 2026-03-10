"""
IOC Registry Admin API -  manage IOC types at runtime without redeploy.

Endpoints:
  GET    /api/admin/ioc-types              -> list all (with filters)
  GET    /api/admin/ioc-types/{type_name}  -> get single type
  POST   /api/admin/ioc-types              -> add new type
  PUT    /api/admin/ioc-types/{type_name}  -> update type
  DELETE /api/admin/ioc-types/{type_name}  -> deactivate (soft delete)
  POST   /api/admin/ioc-types/test-regex   -> test regex against sample text
  POST   /api/admin/ioc-types/preview-score-> preview auto-criticality score
  GET    /api/admin/ioc-types/coverage     -> pipeline coverage report
  GET    /api/admin/criticality-weights    -> get scoring weights
  PUT    /api/admin/criticality-weights    -> update scoring weights
"""
import re
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from arguswatch.database import get_db
from arguswatch.engine.ioc_registry import (
    get_registry, invalidate_cache, calculate_dynamic_severity,
)

logger = logging.getLogger("arguswatch.admin.ioc_registry")
router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/ioc-types")
async def list_ioc_types(
    category: str = None,
    severity: str = None,
    active_only: bool = True,
    db: AsyncSession = Depends(get_db),
):
    """List all IOC types with optional filters."""
    registry = await get_registry(db)
    results = list(registry.values())

    if category:
        results = [r for r in results if (r.get("category") or "").lower() == category.lower()]
    if severity:
        results = [r for r in results if (r.get("base_severity") or "").upper() == severity.upper()]

    return {
        "total": len(results),
        "types": results,
    }


@router.get("/ioc-types/coverage")
async def pipeline_coverage(db: AsyncSession = Depends(get_db)):
    """Pipeline coverage report -  which types have which stages configured."""
    registry = await get_registry(db)
    total = len(registry)

    coverage = {
        "total_types": total,
        "severity_mapped": sum(1 for r in registry.values() if r.get("base_severity")),
        "mitre_mapped": sum(1 for r in registry.values() if r.get("mitre_technique")),
        "kill_chain_mapped": sum(1 for r in registry.values() if r.get("kill_chain_stage")),
        "playbook_mapped": sum(1 for r in registry.values() if r.get("playbook_key") and r["playbook_key"] != "generic"),
        "enrichment_mapped": sum(1 for r in registry.values() if r.get("enrichment_source")),
        "regex_defined": sum(1 for r in registry.values() if r.get("regex")),
    }

    # Find gaps
    gaps = []
    for type_name, r in registry.items():
        missing = []
        if not r.get("mitre_technique"):
            missing.append("mitre")
        if not r.get("kill_chain_stage"):
            missing.append("kill_chain")
        if not r.get("playbook_key") or r["playbook_key"] == "generic":
            missing.append("playbook")
        if missing:
            gaps.append({"type": type_name, "severity": r.get("base_severity"), "missing": missing})

    return {**coverage, "gaps": gaps[:20]}


@router.get("/ioc-types/auto-discover")
async def auto_discover(db: AsyncSession = Depends(get_db)):
    """Scan recent detections for IOC types NOT in the registry."""
    registry = await get_registry(db)
    registered = set(registry.keys())
    try:
        r = await db.execute(text("""
            SELECT ioc_type, COUNT(*) as cnt,
                   MIN(ioc_value) as sample_value,
                   MAX(created_at) as latest
            FROM detections
            WHERE ioc_type IS NOT NULL AND ioc_type != ''
              AND created_at > NOW() - INTERVAL '7 days'
            GROUP BY ioc_type ORDER BY cnt DESC LIMIT 50
        """))
        rows = r.mappings().all()
    except Exception as e:
        return {"error": str(e), "suggestions": []}
    suggestions = []
    for row in rows:
        ioc_type = row["ioc_type"]
        if ioc_type not in registered:
            sample = (row.get("sample_value") or "")[:80]
            suggested_regex = _guess_regex(sample, ioc_type)
            suggestions.append({
                "ioc_type": ioc_type, "suggested_type": ioc_type,
                "count": row["cnt"], "sample": sample,
                "latest": str(row.get("latest", "")),
                "suggested_regex": suggested_regex,
            })
    return {"total_registered": len(registered), "unknown_types_found": len(suggestions), "suggestions": suggestions[:20]}


def _guess_regex(sample: str, ioc_type: str) -> str:
    """Attempt to guess a regex pattern from a sample value."""
    if not sample:
        return ""
    if sample.startswith("AKIA"): return r"\bAKIA[0-9A-Z]{16}\b"
    if sample.startswith("ghp_"): return r"\bghp_[A-Za-z0-9]{36}\b"
    if sample.startswith("sk-"): return r"\bsk-[A-Za-z0-9]{20,}\b"
    if "@" in sample and ":" in sample: return r"[\w\.\-\+]+@[\w\.\-]+\.[a-z]{2,}:[^\s]{6,}"
    if sample.startswith("eyJ"): return r"\bey[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b"
    prefix = sample[:4] if len(sample) >= 4 else sample
    if prefix.isalnum(): return f"\\b{re.escape(prefix)}[A-Za-z0-9]{{20,}}\\b"
    return ""


@router.get("/ioc-types/{type_name}")
async def get_ioc_type(type_name: str, db: AsyncSession = Depends(get_db)):
    """Get a single IOC type with full details."""
    registry = await get_registry(db)
    entry = registry.get(type_name)
    if not entry:
        return {"error": f"Type '{type_name}' not found", "available": sorted(registry.keys())[:20]}
    return entry


@router.post("/ioc-types")
async def add_ioc_type(request: Request, db: AsyncSession = Depends(get_db)):
    """Add a new IOC type to the registry. Live immediately -  no redeploy."""
    body = await request.json()
    type_name = body.get("type_name", "").strip().lower()
    if not type_name:
        return {"error": "type_name is required"}
    if not re.match(r'^[a-z][a-z0-9_]{2,60}$', type_name):
        return {"error": "type_name must be lowercase letters/numbers/underscores, 3-60 chars"}

    # Check for duplicate
    registry = await get_registry(db)
    if type_name in registry:
        return {"error": f"Type '{type_name}' already exists. Use PUT to update."}

    # Validate regex if provided
    regex = body.get("regex")
    if regex:
        try:
            re.compile(regex)
        except re.error as e:
            return {"error": f"Invalid regex: {e}"}

    await db.execute(text("""
        INSERT INTO ioc_type_registry 
            (type_name, regex, regex_confidence, category,
             base_severity, sla_hours, assignee_role,
             mitre_technique, mitre_tactic, mitre_description,
             kill_chain_stage, playbook_key, enrichment_source,
             status, source_note, created_by)
        VALUES
            (:type_name, :regex, :confidence, :category,
             :severity, :sla, :assignee,
             :mitre_tech, :mitre_tactic, :mitre_desc,
             :kc_stage, :playbook, :enrichment,
             :status, :note, :created_by)
    """), {
        "type_name": type_name,
        "regex": regex,
        "confidence": body.get("confidence", 0.85),
        "category": body.get("category", ""),
        "severity": body.get("severity", body.get("base_severity", "MEDIUM")),
        "sla": body.get("sla_hours", 48),
        "assignee": body.get("assignee_role", "secops"),
        "mitre_tech": body.get("mitre_technique", ""),
        "mitre_tactic": body.get("mitre_tactic", ""),
        "mitre_desc": body.get("mitre_description", ""),
        "kc_stage": body.get("kill_chain_stage", ""),
        "playbook": body.get("playbook_key", "generic"),
        "enrichment": body.get("enrichment_source", ""),
        "status": body.get("status", "WORKING"),
        "note": body.get("source_note", ""),
        "created_by": "admin_api",
    })
    await db.commit()
    invalidate_cache()

    return {"status": "created", "type_name": type_name, "message": f"IOC type '{type_name}' added. Pipeline will use it immediately."}


@router.put("/ioc-types/{type_name}")
async def update_ioc_type(type_name: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Update an existing IOC type. Changes take effect within 60 seconds (cache TTL)."""
    body = await request.json()
    registry = await get_registry(db)
    if type_name not in registry:
        return {"error": f"Type '{type_name}' not found"}

    # Build dynamic SET clause from provided fields only
    allowed = {
        "regex", "regex_confidence", "category", "base_severity", "sla_hours",
        "assignee_role", "mitre_technique", "mitre_tactic", "mitre_description",
        "kill_chain_stage", "playbook_key", "enrichment_source", "auto_score_enabled",
        "kill_chain_weight", "tactic_weight", "active", "status", "source_note",
    }
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return {"error": "No valid fields to update", "allowed_fields": sorted(allowed)}

    # Validate regex if changing
    if "regex" in updates and updates["regex"]:
        try:
            re.compile(updates["regex"])
        except re.error as e:
            return {"error": f"Invalid regex: {e}"}

    set_parts = [f"{k} = :{k}" for k in updates]
    set_parts.append("updated_at = :now")
    updates["now"] = datetime.utcnow()
    updates["type_name"] = type_name

    await db.execute(text(
        f"UPDATE ioc_type_registry SET {', '.join(set_parts)} WHERE type_name = :type_name"
    ), updates)
    await db.commit()
    invalidate_cache()

    return {"status": "updated", "type_name": type_name, "fields_changed": list(updates.keys())}


@router.delete("/ioc-types/{type_name}")
async def delete_ioc_type(type_name: str, db: AsyncSession = Depends(get_db)):
    """Soft-delete (deactivate) an IOC type. Can be re-enabled via PUT."""
    registry = await get_registry(db)
    if type_name not in registry:
        return {"error": f"Type '{type_name}' not found"}

    await db.execute(text(
        "UPDATE ioc_type_registry SET active = false, updated_at = :now WHERE type_name = :t"
    ), {"t": type_name, "now": datetime.utcnow()})
    await db.commit()
    invalidate_cache()

    return {"status": "deactivated", "type_name": type_name, "note": "PUT with active=true to re-enable"}


@router.post("/ioc-types/test-regex")
async def test_regex(request: Request):
    """Test a regex pattern against sample text. Returns matches found."""
    body = await request.json()
    pattern = body.get("regex", "")
    sample = body.get("sample_text", "")

    if not pattern:
        return {"error": "regex is required"}
    if not sample:
        return {"error": "sample_text is required"}

    try:
        compiled = re.compile(pattern)
        matches = compiled.findall(sample)
        return {
            "regex": pattern,
            "sample_length": len(sample),
            "match_count": len(matches),
            "matches": matches[:20],
            "valid": True,
        }
    except re.error as e:
        return {"regex": pattern, "valid": False, "error": str(e)}


@router.post("/ioc-types/preview-score")
async def preview_score(request: Request, db: AsyncSession = Depends(get_db)):
    """Preview auto-criticality score for a scenario without creating anything."""
    body = await request.json()
    ioc_type = body.get("ioc_type", "")

    registry = await get_registry(db)
    reg_entry = registry.get(ioc_type, {})

    result = calculate_dynamic_severity(
        ioc_type=ioc_type,
        enrichment=body.get("enrichment", {}),
        source_status=body.get("source_status", reg_entry.get("status", "WORKING")),
        detection_age_days=body.get("detection_age_days", 0),
        customer_industry=body.get("customer_industry", ""),
        exposure_confirmed=body.get("exposure_confirmed", False),
        registry_entry=reg_entry,
    )

    result["registry_base_severity"] = reg_entry.get("base_severity", "MEDIUM")
    result["ioc_type"] = ioc_type
    result["in_registry"] = ioc_type in registry

    return result


@router.get("/criticality-weights")
async def get_weights(db: AsyncSession = Depends(get_db)):
    """Get current auto-criticality scoring weights."""
    try:
        r = await db.execute(text("SELECT factor_name, weight, description FROM criticality_weights ORDER BY factor_name"))
        rows = r.mappings().all()
        return {"weights": [dict(r) for r in rows]}
    except Exception:
        from arguswatch.engine.ioc_registry import _DEFAULT_WEIGHTS
        return {"weights": [{"factor_name": k, "weight": v} for k, v in _DEFAULT_WEIGHTS.items()], "source": "defaults"}


@router.put("/criticality-weights")
async def update_weights(request: Request, db: AsyncSession = Depends(get_db)):
    """Update auto-criticality scoring weights. Must sum to ~1.0."""
    body = await request.json()
    weights = body.get("weights", {})

    total = sum(weights.values())
    if abs(total - 1.0) > 0.05:
        return {"error": f"Weights must sum to ~1.0 (got {total:.3f})", "weights": weights}

    for factor, weight in weights.items():
        await db.execute(text(
            "UPDATE criticality_weights SET weight = :w, updated_at = :now WHERE factor_name = :f"
        ), {"f": factor, "w": weight, "now": datetime.utcnow()})
    await db.commit()

    return {"status": "updated", "weights": weights, "sum": round(total, 3)}


# ══════════════════════════════════════════════════════════════════════
# AI PROMPT MANAGEMENT
# ══════════════════════════════════════════════════════════════════════

@router.get("/ai-prompts")
async def list_prompts(db: AsyncSession = Depends(get_db)):
    """List all AI hook prompts with industry overrides."""
    try:
        r = await db.execute(text("SELECT * FROM ai_prompts ORDER BY hook_name"))
        rows = r.mappings().all()
        return {"prompts": [dict(r) for r in rows]}
    except Exception as e:
        # Table might not exist -  return defaults
        from arguswatch.engine.ai_prompt_manager import DEFAULT_PROMPTS
        return {"prompts": [{"hook_name": k, **v, "source": "hardcoded"} for k, v in DEFAULT_PROMPTS.items()]}


@router.get("/ai-prompts/{hook_name}")
async def get_prompt_detail(hook_name: str, db: AsyncSession = Depends(get_db)):
    """Get prompt for a specific hook."""
    from arguswatch.engine.ai_prompt_manager import get_prompt
    result = await get_prompt(hook_name, db)
    return {"hook_name": hook_name, **result}


@router.put("/ai-prompts/{hook_name}")
async def update_prompt(hook_name: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Update an AI hook's system prompt, temperature, or industry overrides.

    Body: {
        "system_prompt": "You are a ...",
        "temperature": 0.2,
        "industry_override": {"healthcare": "Focus on HIPAA PHI...", "financial": "Focus on PCI DSS..."}
    }
    """
    body = await request.json()
    now = datetime.utcnow()

    # Upsert
    prompt_text = body.get("system_prompt")
    temperature = body.get("temperature", 0.2)
    overrides = body.get("industry_override", {})
    import json as _json

    try:
        await db.execute(text("""
            INSERT INTO ai_prompts (hook_name, system_prompt, temperature, industry_override, updated_at, updated_by)
            VALUES (:hook, :prompt, :temp, :overrides, :now, 'admin_api')
            ON CONFLICT (hook_name) DO UPDATE SET
                system_prompt = COALESCE(:prompt, ai_prompts.system_prompt),
                temperature = :temp,
                industry_override = :overrides,
                version = ai_prompts.version + 1,
                updated_at = :now,
                updated_by = 'admin_api'
        """), {
            "hook": hook_name,
            "prompt": prompt_text,
            "temp": temperature,
            "overrides": _json.dumps(overrides),
            "now": now,
        })
        await db.commit()
        from arguswatch.engine.ai_prompt_manager import _prompt_cache
        _prompt_cache.clear()  # Invalidate cache
        return {"status": "updated", "hook_name": hook_name}
    except Exception as e:
        return {"error": str(e)[:200]}


@router.post("/ai-prompts/{hook_name}/test")
async def test_prompt(hook_name: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Test a prompt against a sample IOC without saving."""
    body = await request.json()
    system_prompt = body.get("system_prompt", "")
    sample_ioc = body.get("sample_ioc", "8.8.8.8")
    sample_type = body.get("sample_type", "ipv4")

    try:
        from arguswatch.agent.agent_core import _resolve_provider
        provider = _resolve_provider("auto")

        # Build test message
        test_msg = f"IOC: {sample_ioc}\nType: {sample_type}\nSource: test\nVT: 5/72\nAbuseIPDB: 45%"

        return {
            "hook_name": hook_name,
            "provider": provider,
            "system_prompt_preview": system_prompt[:200] + "..." if len(system_prompt) > 200 else system_prompt,
            "test_input": test_msg,
            "note": "Full test requires running LLM. Use /api/ai/chat to test interactively.",
        }
    except Exception as e:
        return {"error": str(e)[:200]}


# ══════════════════════════════════════════════════════════════════════
# MITRE ATT&CK AUTO-SYNC
# ══════════════════════════════════════════════════════════════════════

@router.post("/mitre-sync")
async def trigger_mitre_sync(db: AsyncSession = Depends(get_db)):
    """Pull latest MITRE ATT&CK data, compare with registry, flag deprecated techniques."""
    from arguswatch.engine.ai_prompt_manager import sync_mitre_attack
    result = await sync_mitre_attack(db)
    return result


@router.get("/mitre-sync/history")
async def mitre_sync_history(db: AsyncSession = Depends(get_db)):
    """Get history of MITRE sync operations."""
    try:
        r = await db.execute(text(
            "SELECT * FROM mitre_sync_log ORDER BY sync_date DESC LIMIT 10"
        ))
        return {"history": [dict(row) for row in r.mappings().all()]}
    except Exception:
        return {"history": [], "note": "No sync history yet. Run POST /api/admin/mitre-sync first."}


# ══════════════════════════════════════════════════════════════════════
# ANALYST OVERRIDE STATS -  feeds prompt evolution decisions
# ══════════════════════════════════════════════════════════════════════

@router.get("/analyst-overrides")
async def analyst_override_stats(db: AsyncSession = Depends(get_db)):
    """Show analyst severity override rates -  which prompts need tuning.

    When override rate is high for an industry/ioc_type, the prompt needs adjusting.
    This is the DATA that drives prompt evolution decisions.
    AI doesn't auto-adjust prompts -  this gives you the signal to decide.
    """
    try:
        # Overall override rate
        total_r = await db.execute(text("SELECT COUNT(*) FROM findings WHERE analyst_override_severity IS NOT NULL"))
        total_overrides = total_r.scalar() or 0
        all_r = await db.execute(text("SELECT COUNT(*) FROM findings WHERE severity IS NOT NULL"))
        total_findings = all_r.scalar() or 0
        overall_rate = (total_overrides / max(total_findings, 1)) * 100

        # By IOC type
        by_type_r = await db.execute(text("""
            SELECT ioc_type, 
                   COUNT(*) as overrides,
                   COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM findings f2 WHERE f2.ioc_type = findings.ioc_type), 0) as rate
            FROM findings WHERE analyst_override_severity IS NOT NULL
            GROUP BY ioc_type ORDER BY overrides DESC LIMIT 15
        """))
        by_type = [dict(r) for r in by_type_r.mappings().all()]

        # Direction: upgrades vs downgrades
        up_r = await db.execute(text("""
            SELECT COUNT(*) FROM findings 
            WHERE analyst_override_severity IS NOT NULL
            AND analyst_override_severity IN ('CRITICAL','HIGH')
            AND severity IN ('MEDIUM','LOW','INFO')
        """))

        return {
            "total_findings": total_findings,
            "total_overrides": total_overrides,
            "overall_override_rate": round(overall_rate, 1),
            "by_ioc_type": by_type,
            "note": "High override rate = prompt needs tuning. Use PUT /api/admin/ai-prompts/{hook} to adjust.",
            "action_needed": overall_rate > 25,
        }
    except Exception as e:
        return {"error": str(e)[:200], "note": "Override tracking columns may not exist yet. Deploy and create findings first."}


# ══════════════════════════════════════════════════════════════════════
# CROSS-CUSTOMER FP -  promote and manage global patterns
# ══════════════════════════════════════════════════════════════════════

@router.get("/global-fp-patterns")
async def list_global_fps(db: AsyncSession = Depends(get_db)):
    """List FP patterns that have been auto-promoted to global (3+ customers marked FP)."""
    try:
        r = await db.execute(text("""
            SELECT ioc_type, ioc_value_pattern, cross_customer_count, auto_close,
                   global_promoted_at, reason, hit_count
            FROM fp_patterns 
            WHERE is_global = true
            ORDER BY cross_customer_count DESC, hit_count DESC LIMIT 50
        """))
        patterns = [dict(row) for row in r.mappings().all()]
        return {"global_patterns": patterns, "total": len(patterns)}
    except Exception as e:
        return {"global_patterns": [], "error": str(e)[:200]}


@router.post("/global-fp-patterns/{pattern_id}/promote")
async def promote_to_global(pattern_id: int, db: AsyncSession = Depends(get_db)):
    """Manually promote an FP pattern to global (MSSP admin decision)."""
    await db.execute(text("""
        UPDATE fp_patterns SET is_global = true, auto_close = true,
            global_promoted_at = NOW(), global_promoted_by = 'admin_manual'
        WHERE id = :pid
    """), {"pid": pattern_id})
    await db.commit()
    return {"status": "promoted", "pattern_id": pattern_id}


# ══════════════════════════════════════════════════════════════════════
# AI MITRE CLASSIFICATION -  the one useful part of "LLM IOC discovery"
# ══════════════════════════════════════════════════════════════════════

@router.post("/ioc-types/ai-classify")
async def ai_classify_ioc_type(request: Request, db: AsyncSession = Depends(get_db)):
    """Ask LLM to suggest MITRE technique, tactic, severity, and kill chain stage for an IOC type.
    
    This is the only part of "LLM-powered IOC discovery" that actually adds value.
    LLMs are good at CLASSIFICATION (what technique is this?).
    LLMs are bad at REGEX WRITING (they hallucinate patterns).
    
    Body: {"type_name": "azure_devops_pat", "sample_values": ["abc123..."]}
    """
    body = await request.json()
    type_name = body.get("type_name", "")
    samples = body.get("sample_values", [])

    try:
        from arguswatch.agent.chat_agent_reliable import reliable_chat
        question = f"""Classify this IOC type for a threat intelligence platform:

IOC Type: {type_name}
Sample values: {', '.join(str(s)[:50] for s in samples[:3])}

Respond with JSON only:
{{
  "mitre_technique": "T1552.004",
  "mitre_tactic": "Credential Access",
  "mitre_description": "One-line description of what this IOC means",
  "suggested_severity": "CRITICAL",
  "suggested_kill_chain": "exfiltration",
  "suggested_playbook": "leaked_api_key",
  "suggested_category": "API Keys",
  "reasoning": "Why this classification"
}}"""
        result = await reliable_chat(question, db)
        answer = result.get("response") or result.get("answer") or ""

        # Try to parse JSON from response
        import json as _json
        try:
            # Extract JSON from response
            import re as _re
            json_match = _re.search(r'\{[^{}]*"mitre_technique"[^{}]*\}', answer, _re.DOTALL)
            if json_match:
                classification = _json.loads(json_match.group())
                return {"status": "classified", "type_name": type_name, "classification": classification}
        except Exception:
            pass

        return {"status": "raw_response", "type_name": type_name, "ai_response": answer[:500]}
    except Exception as e:
        return {"status": "error", "error": str(e)[:200]}
