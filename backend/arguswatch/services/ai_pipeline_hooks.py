"""
AI Pipeline Hooks V13 - AI is the decision-maker.

PHILOSOPHY CHANGE FROM PREVIOUS VERSION:
  Old: rules run first → AI gives "second opinion" → AI can only upgrade
  New: AI runs FIRST on enrichment data → AI sets severity/attribution
       Rules are the FALLBACK when AI is unavailable or low confidence
       AI CAN downgrade, FP-flag, or override any rule

HOOKS (called by ingest_pipeline.py):
  hook_ai_triage          - Step 4: AI decides severity+confidence BEFORE rule lookup
  hook_investigation_narrative - Step 5: AI writes analyst narrative
  hook_attribution_assist - Step 6: AI picks actor from DB candidates
  hook_campaign_narrative - Step 7: AI writes kill chain narrative
  hook_false_positive_check - Step 5: AI flags likely FPs before analyst sees them

All hooks are non-blocking - exceptions fall through to rule-based path.
"""
import logging
import json
from datetime import datetime
from arguswatch.config import settings

logger = logging.getLogger("arguswatch.ai_pipeline")


# ── Redis-backed active provider (shared between FastAPI + Celery) ──
_REDIS_PROVIDER_KEY = "arguswatch:active_provider"

def _get_active_provider_from_redis() -> str:
    """Read active provider from Redis. Falls back to config if Redis unavailable."""
    try:
        import redis
        r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
        val = r.get(_REDIS_PROVIDER_KEY)
        if val:
            return val.decode("utf-8")
    except Exception:
        pass
    return getattr(settings, "AI_ACTIVE_PROVIDER", "ollama")

def _set_active_provider_in_redis(provider: str):
    """Write active provider to Redis. Both FastAPI and Celery see it."""
    try:
        import redis
        r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
        r.set(_REDIS_PROVIDER_KEY, provider)
    except Exception:
        pass
    # Also update in-process as fallback
    settings.AI_ACTIVE_PROVIDER = provider


def _provider() -> str:
    """
    Returns the active AI provider for pipeline operations.

    Priority:
    1. User-selected provider (stored in Redis - shared across all processes)
    2. Auto-fallback: Anthropic → OpenAI → Google → Ollama → none

    Default is "ollama" - local, free, private, always available.
    Users switch providers via the AI switcher in the dashboard top bar.
    """
    selected = _get_active_provider_from_redis()

    if selected == "auto":
        # Auto: use best available (cloud preferred for speed)
        if getattr(settings, "ANTHROPIC_API_KEY", ""):
            return "anthropic"
        if getattr(settings, "OPENAI_API_KEY", ""):
            return "openai"
        if getattr(settings, "GOOGLE_AI_API_KEY", ""):
            return "google"
        if getattr(settings, "OLLAMA_URL", ""):
            return "ollama"
        return "none"

    # Explicit selection - verify it's usable, fallback to ollama
    if selected == "anthropic" and getattr(settings, "ANTHROPIC_API_KEY", ""):
        return "anthropic"
    if selected == "openai" and getattr(settings, "OPENAI_API_KEY", ""):
        return "openai"
    if selected == "google" and getattr(settings, "GOOGLE_AI_API_KEY", ""):
        return "google"
    if selected == "ollama" and getattr(settings, "OLLAMA_URL", ""):
        return "ollama"

    # Selected provider unavailable - fallback to ollama
    if getattr(settings, "OLLAMA_URL", ""):
        return "ollama"
    return "none"


def _pipeline_ai_available() -> bool:
    """True if any AI provider (cloud or local) is configured."""
    return _provider() != "none"


async def _llm_json(system: str, user: str, provider: str | None = None) -> dict:
    """Call LLM, return parsed JSON dict. Raises on failure."""
    prov = provider or _provider()
    if prov == "none":
        raise ValueError("No AI provider configured (set ANTHROPIC_API_KEY, OPENAI_API_KEY, or ensure Ollama is running)")
    import re
    if prov == "anthropic":
        from arguswatch.agent.agent_core import _call_anthropic
        r = await _call_anthropic(
            [{"role": "system", "content": system}, {"role": "user", "content": user}], []
        )
        text = r["text"]
    elif prov == "openai":
        from arguswatch.agent.agent_core import _call_openai
        r = await _call_openai(
            [{"role": "system", "content": system}, {"role": "user", "content": user}], []
        )
        text = r["text"]
    elif prov == "ollama":
        from arguswatch.agent.agent_core import _call_ollama
        r = await _call_ollama(
            [{"role": "system", "content": system}, {"role": "user", "content": user}], []
        )
        text = r["text"]
    elif prov == "google":
        from arguswatch.agent.agent_core import _call_google
        r = await _call_google(
            [{"role": "system", "content": system}, {"role": "user", "content": user}], []
        )
        text = r["text"]
    else:
        raise ValueError(f"Unsupported provider for pipeline: {prov}")

    # Strip markdown fences
    text = re.sub(r'```(?:json)?\s*', '', text).strip().rstrip('`').strip()
    m = re.search(r'\{[\s\S]+\}', text)
    if m:
        return json.loads(m.group(0))
    raise ValueError(f"No JSON in response: {text[:200]}")


async def _llm_text(system: str, user: str, provider: str | None = None) -> str:
    """Call LLM, return plain text."""
    prov = provider or _provider()
    if prov == "anthropic":
        from arguswatch.agent.agent_core import _call_anthropic
        r = await _call_anthropic(
            [{"role": "system", "content": system}, {"role": "user", "content": user}], []
        )
        return r["text"].strip()
    elif prov == "openai":
        from arguswatch.agent.agent_core import _call_openai
        r = await _call_openai(
            [{"role": "system", "content": system}, {"role": "user", "content": user}], []
        )
        return r["text"].strip()
    elif prov == "ollama":
        from arguswatch.agent.agent_core import _call_ollama
        r = await _call_ollama(
            [{"role": "system", "content": system}, {"role": "user", "content": user}], []
        )
        return r["text"].strip()
    elif prov == "google":
        from arguswatch.agent.agent_core import _call_google
        r = await _call_google(
            [{"role": "system", "content": system}, {"role": "user", "content": user}], []
        )
        return r["text"].strip()
    else:
        raise ValueError(f"Unsupported provider for pipeline: {prov}")


# ══════════════════════════════════════════════════════════════════════
# Hook 1: AI TRIAGE - AI sets severity and confidence (not rules)
# Called at Step 4, before enrichment_feedback rule logic
# ══════════════════════════════════════════════════════════════════════

async def hook_ai_triage(
    ioc_type: str,
    ioc_value: str,
    source: str,
    enrichment_data: dict,
    customer_context: dict,
    raw_text: str = "",
) -> dict:
    """
    AI decides severity, confidence, and SLA.
    AI can set any severity - CRITICAL down to INFO.
    V16.4: Now receives raw_text from source Detection for richer context.
    Returns: {severity, sla_hours, confidence, reasoning, provider} or {}
    """
    if not _pipeline_ai_available():
        return {}
    vt = enrichment_data.get("vt_malicious", 0)
    abuse = enrichment_data.get("abuse_score", 0)
    otx = enrichment_data.get("otx_pulses", 0)
    industry = customer_context.get("industry", "unknown")
    matched_asset = customer_context.get("matched_asset", "unknown")

    # V16.4: Build raw source context line
    _raw_line = ""
    if raw_text and len(raw_text.strip()) > 10:
        _raw_line = f"\nRaw source content (first 800 chars): {raw_text[:800]}"

    # RAG: pull related historical findings for context
    _rag_ctx = ""
    try:
        from arguswatch.services.ai_rag_context import build_rag_context
        from arguswatch.database import async_session as _rag_session
        async with _rag_session() as _rag_db:
            _rag_ctx = await build_rag_context(
                ioc_value=ioc_value, ioc_type=ioc_type,
                customer_id=customer_context.get("customer_id"),
                actor_name=None, finding_id=None,
                db=_rag_db, include_actor_intel=False,
            )
    except Exception as _re:
        logger.debug(f"[rag_context] triage context failed: {_re}")

    prompt = f"""You are a SOC triage analyst. Set the severity for this IOC based on evidence.

IOC: {ioc_value}
Type: {ioc_type}
Source feed: {source}
VirusTotal malicious engines: {vt}/72
AbuseIPDB confidence score: {abuse}%
OTX threat pulses: {otx}
Customer industry: {industry}
Matched asset: {matched_asset}{_raw_line}
{f"\n{_rag_ctx}" if _rag_ctx else ""}

Rules for context only:
- VT >= 30 typically CRITICAL, >= 10 typically HIGH
- AbuseIPDB >= 80 typically HIGH for IPs
- Low/no detection with only 1 source = likely LOW or INFO
- If data is insufficient to assess, lean LOW and say why

Respond ONLY with valid JSON, no commentary:
{{"severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "sla_hours": <int>, "confidence": <0.0-1.0>, "reasoning": "<specific evidence-based sentence>"}}"""

    try:
        result = await _llm_json(
            "You are a cybersecurity SOC triage analyst. Respond ONLY with valid JSON.",
            prompt
        )
        # Validate
        if result.get("severity") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            return {}
        result["provider"] = _provider()
        logger.info(f"[ai_triage] {ioc_value[:40]} → {result['severity']} (conf={result.get('confidence','?')}) | {result.get('reasoning','')[:80]}")
        return result
    except Exception as e:
        logger.debug(f"[ai_triage] failed (fallback to rules): {e}")
        return {}


# ══════════════════════════════════════════════════════════════════════
# Hook 2: FALSE POSITIVE CHECK - AI flags before analyst sees it
# ══════════════════════════════════════════════════════════════════════

async def hook_false_positive_check(
    ioc_type: str,
    ioc_value: str,
    source: str,
    enrichment_data: dict,
    customer_context: dict,
) -> dict:
    """
    AI assesses likelihood of false positive.
    Returns: {is_fp: bool, confidence: float, reason: str} or {}
    """
    vt = enrichment_data.get("vt_malicious", 0)
    abuse = enrichment_data.get("abuse_score", 0)

    # Fast path - don't bother AI if evidence is clearly malicious
    if vt >= 20 or abuse >= 80:
        return {"is_fp": False, "confidence": 0.9, "reason": "strong malicious signals"}

    prompt = f"""Is this a false positive threat detection?

IOC: {ioc_value}
Type: {ioc_type}
Source feed: {source}
VT malicious: {vt}/72
AbuseIPDB: {abuse}%
Customer industry: {customer_context.get('industry', 'unknown')}
Matched asset: {customer_context.get('matched_asset', 'none')}

Common FP patterns: CDN IPs, known security scanners (Shodan/Censys), corporate SSO domains,
internal tool URLs, low-reputation IOCs from unreliable feeds.

Respond ONLY with valid JSON:
{{"is_fp": true|false, "confidence": <0.0-1.0>, "reason": "<specific reason>"}}"""

    try:
        result = await _llm_json(
            "You are a SOC analyst reviewing potential false positives. Respond ONLY with valid JSON.",
            prompt
        )
        if "is_fp" not in result:
            return {}
        logger.info(f"[ai_fp_check] {ioc_value[:40]} is_fp={result['is_fp']} conf={result.get('confidence','?')} | {result.get('reason','')[:60]}")
        return result
    except Exception as e:
        logger.debug(f"[ai_fp_check] failed: {e}")
        return {}


# ══════════════════════════════════════════════════════════════════════
# Hook 3: INVESTIGATION NARRATIVE - AI writes the analyst summary
# ══════════════════════════════════════════════════════════════════════

async def hook_investigation_narrative(
    finding_id: int,
    ioc_value: str,
    ioc_type: str,
    enrichment_summary: dict,
    actor_name: str | None,
    customer_name: str | None,
    severity: str | None = None,
) -> str:
    """
    AI writes a 2-3 sentence investigation narrative.
    This is what analysts and executives see in the dashboard.
    Returns narrative string or "" on failure.
    """
    # RAG: pull related findings + actor intel for richer narrative
    _rag_ctx_n = ""
    try:
        from arguswatch.services.ai_rag_context import build_rag_context
        from arguswatch.database import async_session as _rag_session_n
        async with _rag_session_n() as _rag_db_n:
            _rag_ctx_n = await build_rag_context(
                ioc_value=ioc_value, ioc_type=ioc_type,
                customer_id=None, actor_name=actor_name,
                finding_id=finding_id, db=_rag_db_n,
                include_actor_intel=True,
            )
    except Exception as _re_n:
        logger.debug(f"[rag_context] narrative context failed: {_re_n}")

    prompt = f"""Write a 2-3 sentence investigation narrative for an analyst dashboard.

Finding #{finding_id}
IOC: {ioc_value} ({ioc_type})
Customer: {customer_name or 'unknown'}
Severity: {severity or 'unknown'}
Attributed actor: {actor_name or 'unknown'}
VT detections: {enrichment_summary.get('vt_malicious', 'N/A')}/72 engines
AbuseIPDB score: {enrichment_summary.get('abuse_score', 'N/A')}%
{f"\n{_rag_ctx_n}" if _rag_ctx_n else ""}

Write as a senior SOC analyst. Be specific - cite the actual IOC value, detection counts,
and actor name. Explain the business risk in plain language. State the recommended first action."""

    try:
        narrative = await _llm_text(
            "You are a senior SOC analyst writing investigation summaries for executives. Be specific and concise.",
            prompt
        )
        if len(narrative) > 50:
            return narrative
    except Exception as e:
        logger.debug(f"[ai_narrative] failed: {e}")
    return ""


# ══════════════════════════════════════════════════════════════════════
# Hook 4: ATTRIBUTION ASSIST - AI picks actor from DB candidates
# ══════════════════════════════════════════════════════════════════════

async def hook_attribution_assist(
    finding_id: int,
    ioc_value: str,
    ioc_type: str,
    candidate_actors: list[dict],
    finding_context: dict,
) -> dict:
    """
    AI picks the most likely actor from DB candidates.
    If AI confidence > 0.6, its pick overrides SQL ordering.
    Returns: {actor_name, confidence, narrative} or {}
    """
    if not candidate_actors:
        return {}

    actors_text = "\n".join(
        f"- {a.get('name', '?')}: targets {a.get('target_sectors', '?')}, "
        f"techniques {a.get('techniques', '?')}, country {a.get('origin_country', '?')}"
        for a in candidate_actors[:6]
    )

    prompt = f"""Which threat actor is most likely responsible for this finding?

IOC: {ioc_value} ({ioc_type})
Customer industry: {finding_context.get('industry', 'unknown')}
Customer country: {finding_context.get('country', 'unknown')}
Matched asset type: {finding_context.get('asset_type', 'unknown')}

Candidate actors from threat intelligence database:
{actors_text}

If no actor is a confident match, return null for actor_name.

Respond ONLY with valid JSON:
{{"actor_name": "<name or null>", "confidence": <0.0-1.0>, "narrative": "<2 sentence attribution reasoning>"}}"""

    try:
        result = await _llm_json(
            "You are a threat attribution analyst. Respond ONLY with valid JSON.",
            prompt
        )
        if result.get("actor_name") and result.get("confidence", 0) > 0.5:
            logger.info(f"[ai_attribution] finding={finding_id} → {result['actor_name']} conf={result.get('confidence','?')}")
        return result
    except Exception as e:
        logger.debug(f"[ai_attribution] failed: {e}")
        return {}


# ══════════════════════════════════════════════════════════════════════
# Hook 5: CAMPAIGN NARRATIVE
# ══════════════════════════════════════════════════════════════════════

async def hook_campaign_narrative(
    campaign_id: int,
    actor_name: str,
    kill_chain_stage: str,
    finding_count: int,
    ioc_types: list[str],
    customer_name: str | None,
) -> str:
    """AI writes kill chain campaign narrative."""
    prompt = f"""Write a 2-3 sentence threat campaign briefing for an executive.

Actor: {actor_name}
Kill chain stage: {kill_chain_stage}
Findings count: {finding_count}
IOC types: {', '.join(ioc_types)}
Targeted customer: {customer_name or 'unknown'}

Explain what the attacker is doing, how far they've progressed, and the immediate business risk."""

    try:
        return await _llm_text(
            "You are a SOC analyst writing executive threat briefings. Be specific and concise.",
            prompt
        )
    except Exception as e:
        logger.debug(f"[ai_campaign_narrative] failed: {e}")
    return ""


# ══════════════════════════════════════════════════════════════════════
# Kept for backward compat
# ══════════════════════════════════════════════════════════════════════

async def hook_rescore_severity(
    finding_id: int,
    ioc_value: str,
    ioc_type: str,
    current_severity: str,
    enrichment_data: dict,
    actor_name: str | None,
    customer_context: dict,
    cisa_kev: bool = False,
    autonomous: bool = False,
) -> dict:
    """
    Step 6.5 - AI re-scores severity AFTER attribution is known.

    Called between attribution (Step 6) and campaign check (Step 7).
    At this point we have: enrichment numbers + actor identity.
    That combination is richer context than either alone.

    autonomous=True  → AI can set any severity, including DOWNGRADE
    autonomous=False → AI can only UPGRADE (safe default)

    Returns: {severity, sla_hours, confidence, reasoning, changed: bool} or {}
    """
    if not _pipeline_ai_available():
        return {}

    vt = enrichment_data.get("vt_malicious", 0)
    abuse = enrichment_data.get("abuse_score", 0)
    otx = enrichment_data.get("otx_pulses", 0)
    industry = customer_context.get("industry", "unknown")
    customer_name = customer_context.get("name", "unknown")

    kev_line = "⚠️ CISA KEV: YES - actively exploited in the wild" if cisa_kev else "CISA KEV: No"
    actor_line = f"Attributed actor: {actor_name}" if actor_name else "Actor: Not attributed"
    mode_line = "Mode: AUTONOMOUS (may upgrade OR downgrade)" if autonomous else "Mode: SAFE (may upgrade only, not downgrade)"

    # RAG: pull related findings + actor intel
    rag_ctx = ""
    try:
        from arguswatch.services.ai_rag_context import build_rag_context
        from arguswatch.database import async_session as _rs
        async with _rs() as _rdb:
            rag_ctx = await build_rag_context(
                ioc_value=ioc_value, ioc_type=ioc_type,
                customer_id=customer_context.get("customer_id"),
                actor_name=actor_name, finding_id=finding_id,
                db=_rdb, include_actor_intel=True,
            )
    except Exception as _re:
        logger.debug(f"[rescore] RAG context failed: {_re}")

    prompt = f"""You are a SOC analyst re-assessing finding severity after enrichment and attribution.

Finding #{finding_id}
IOC: {ioc_value} ({ioc_type})
Current severity: {current_severity}
{actor_line}
{kev_line}
VT malicious engines: {vt}/72
AbuseIPDB confidence: {abuse}%
OTX threat pulses: {otx}
Customer: {customer_name} (industry: {industry})
{mode_line}
{f"{chr(10)}{rag_ctx}" if rag_ctx else ""}

Re-assess. Is the current severity correct given everything you now know?
Factors that should UPGRADE: known APT actor, CISA KEV, VT ≥ 20, AbuseIPDB ≥ 75, customer in targeted sector
Factors that should DOWNGRADE: VT < 3, AbuseIPDB < 20, CDN/scanner IP, no actor match, single low-confidence feed
{'' if autonomous else "NOTE: In safe mode - only return a higher severity than current, or keep the same."}

Respond ONLY with valid JSON:
{{"severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "sla_hours": <int>, "confidence": <0.0-1.0>, "reasoning": "<specific sentence citing evidence>"}}"""

    try:
        result = await _llm_json(
            "You are a SOC analyst re-assessing threat severity. Respond ONLY with valid JSON.",
            prompt,
        )
        if result.get("severity") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            return {}

        SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        new_sev = result["severity"]
        changed = new_sev != current_severity

        # Safe-mode guard: never downgrade
        if not autonomous:
            if SEV_RANK.get(new_sev, 0) < SEV_RANK.get(current_severity, 2):
                result["severity"] = current_severity
                result["reasoning"] = f"[safe mode: kept {current_severity}] " + result.get("reasoning", "")
                changed = False

        result["changed"] = changed
        result["provider"] = _provider()

        logger.info(
            f"[rescore] finding={finding_id} {current_severity}→{result['severity']} "
            f"changed={changed} conf={result.get('confidence','?')} | "
            f"{result.get('reasoning','')[:80]}"
        )
        return result
    except Exception as e:
        logger.debug(f"[rescore] failed: {e}")
        return {}


async def hook_enrichment_severity(
    finding_id: int,
    ioc_type: str,
    ioc_value: str,
    enrichment_data: dict,
    current_severity: str,
    customer_context: dict,
) -> dict:
    """Backward-compat wrapper → calls hook_ai_triage."""
    return await hook_ai_triage(
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        source=customer_context.get("source", "unknown"),
        enrichment_data=enrichment_data,
        customer_context=customer_context,
    )
