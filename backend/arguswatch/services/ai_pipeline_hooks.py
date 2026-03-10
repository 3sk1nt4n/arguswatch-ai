"""
AI Pipeline Hooks V13 - AI is the decision-maker.

PHILOSOPHY CHANGE FROM PREVIOUS VERSION:
  Old: rules run first -> AI gives "second opinion" -> AI can only upgrade
  New: AI runs FIRST on enrichment data -> AI sets severity/attribution
       Rules are the FALLBACK when AI is unavailable or low confidence
       AI CAN downgrade, FP-flag, or override any rule

HOOKS (called by ingest_pipeline.py):
  hook_ai_triage         - Step 4: AI decides severity+confidence BEFORE rule lookup
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
from arguswatch.utils import sanitize_for_llm

logger = logging.getLogger("arguswatch.ai_pipeline")


# ── DB-backed prompt loader -  reads from cache, NO new DB session ──
async def _load_prompt(hook_name: str, industry: str = "") -> str:
    """Load system prompt from in-memory cache (populated at startup).
    Falls back to hardcoded prompt if cache empty.
    
    CRITICAL: Does NOT open a new DB session. The cache is populated by
    seed_default_prompts() at startup and refreshed by get_prompt() when
    any admin API call loads prompts. Opening a new session here would
    cause pool exhaustion: 9 hooks × 50 findings = 450 sessions.
    """
    try:
        from arguswatch.engine.ai_prompt_manager import _prompt_cache, DEFAULT_PROMPTS
        # Try cache first (populated at startup, refreshed every 2 min by admin API calls)
        entry = _prompt_cache.get(hook_name)
        if entry:
            prompt_text = entry.get("system_prompt", "")
            # Industry override from cached data
            overrides = entry.get("industry_override") or {}
            if isinstance(overrides, dict) and industry.lower() in overrides:
                return overrides[industry.lower()]
            return prompt_text
        # Fallback to hardcoded defaults
        default = DEFAULT_PROMPTS.get(hook_name, {})
        return default.get("system_prompt", "")
    except Exception:
        return ""  # Empty = caller uses its own hardcoded fallback


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
    return _fallback_provider

def _set_active_provider_in_redis(provider: str):
    """Write active provider to Redis. Both FastAPI and Celery see it."""
    global _fallback_provider
    try:
        import redis
        r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
        r.set(_REDIS_PROVIDER_KEY, provider)
    except Exception:
        pass
    # In-process fallback (module-level, not on immutable settings object)
    _fallback_provider = provider

_fallback_provider = "ollama"


def _provider() -> str:
    """
    Returns the active AI provider for pipeline operations.

    Priority:
    1. User-selected provider (stored in Redis - shared across all processes)
    2. Auto-fallback: Anthropic -> OpenAI -> Google -> Ollama -> none

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


_boot_mode = False  # Set True during startup to skip AI calls (too slow for 100+ findings)

def _pipeline_ai_available() -> bool:
    """True if any AI provider (cloud or local) is configured."""
    if _boot_mode:
        return False  # Skip AI during boot - Celery handles it later
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

    # Sanitize adversary-controlled input before LLM prompt
    ioc_value = sanitize_for_llm(ioc_value, max_length=500)
    raw_text = sanitize_for_llm(raw_text, max_length=1000)

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

    # Load system instruction from DB (editable via admin API) with fallback
    _sys_instruction = await _load_prompt("ai_triage", industry=industry)
    if not _sys_instruction:
        _sys_instruction = "You are a SOC triage analyst. Set the severity for this IOC based on evidence."

    prompt = f"""{_sys_instruction}

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
        logger.info(f"[ai_triage] {ioc_value[:40]} -> {result['severity']} (conf={result.get('confidence','?')}) | {result.get('reasoning','')[:80]}")
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
    # Sanitize adversary-controlled input
    ioc_value = sanitize_for_llm(ioc_value, max_length=500)

    vt = enrichment_data.get("vt_malicious", 0)
    abuse = enrichment_data.get("abuse_score", 0)

    # Fast path - don't bother AI if evidence is clearly malicious
    if vt >= 20 or abuse >= 80:
        return {"is_fp": False, "confidence": 0.9, "reason": "strong malicious signals"}

    _sys_fp = await _load_prompt("false_positive_check")
    if not _sys_fp: _sys_fp = "Is this a false positive threat detection?"
    prompt = f"""{_sys_fp}

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
    # Sanitize adversary-controlled input
    ioc_value = sanitize_for_llm(ioc_value, max_length=500)

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

    _sys_narr = await _load_prompt("investigation_narrative")
    if not _sys_narr: _sys_narr = "Write a 2-3 sentence investigation narrative for an analyst dashboard."
    prompt = f"""{_sys_narr}

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

    _sys_attr = await _load_prompt("attribution")
    if not _sys_attr: _sys_attr = "Which threat actor is most likely responsible for this finding?"
    prompt = f"""{_sys_attr}

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
            logger.info(f"[ai_attribution] finding={finding_id} -> {result['actor_name']} conf={result.get('confidence','?')}")
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
    _sys_camp = await _load_prompt("campaign_briefing")
    if not _sys_camp: _sys_camp = "Write a 2-3 sentence threat campaign briefing for an executive."
    prompt = f"""{_sys_camp}

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

    autonomous=True  -> AI can set any severity, including DOWNGRADE
    autonomous=False -> AI can only UPGRADE (safe default)

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

    _sys_rescore = await _load_prompt("rescore_severity")
    if not _sys_rescore: _sys_rescore = "You are a SOC analyst re-assessing finding severity after enrichment and attribution."
    prompt = f"""{_sys_rescore}

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
            f"[rescore] finding={finding_id} {current_severity}->{result['severity']} "
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
    """Backward-compat wrapper -> calls hook_ai_triage."""
    return await hook_ai_triage(
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        source=customer_context.get("source", "unknown"),
        enrichment_data=enrichment_data,
        customer_context=customer_context,
    )


# ══════════════════════════════════════════════════════════════════════
# Hook 5: AI-CUSTOMIZED REMEDIATIONS (v16.4.7)
# Instead of template "Rotate the exposed API key", AI writes:
# "Rotate AKIA0EXAMPLE found in gist.github.com/user/abc for Starbucks"
# ══════════════════════════════════════════════════════════════════════

async def hook_ai_remediation(
    ioc_type: str,
    ioc_value: str,
    source: str,
    customer_name: str,
    customer_industry: str,
    matched_asset: str,
    severity: str,
    playbook_key: str,
    template_steps: list[str],
) -> dict:
    """
    AI generates CUSTOM remediation steps based on finding context.
    Returns: {steps_technical: [...], steps_governance: [...], title: str, ai_generated: True}
    Falls back to empty dict -> caller uses template steps.
    """
    if not _pipeline_ai_available():
        return {}

    # Give AI the template as a starting point + real context
    template_preview = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(template_steps[:4]))

    _sys_remed = await _load_prompt("remediation")
    if not _sys_remed: _sys_remed = "You are a senior SOC remediation analyst. Write SPECIFIC, actionable remediation steps for this finding."
    prompt = f"""{_sys_remed}

FINDING:
  IOC: {ioc_value}
  Type: {ioc_type}
  Source: {source}
  Severity: {severity}
  Customer: {customer_name} (industry: {customer_industry})
  Matched asset: {matched_asset}
  Playbook type: {playbook_key}

TEMPLATE STEPS (generic):
{template_preview}

Write 5-7 SPECIFIC steps that reference the actual IOC value, customer name, source, and matched asset.
Make each step directly actionable -  include the exact IP/domain/key/CVE in the step text.

Respond ONLY with valid JSON:
{{"steps_technical": ["step1", "step2", ...], "steps_governance": ["gov1", "gov2"], "title": "short title with customer name + IOC"}}"""

    try:
        result = await _llm_json(
            "You are a cybersecurity remediation specialist. Respond ONLY with valid JSON.",
            prompt
        )
        if result.get("steps_technical") and len(result["steps_technical"]) >= 3:
            result["ai_generated"] = True
            result["provider"] = _provider()
            logger.info(f"[ai_remediation] Custom steps for {ioc_value[:30]} -> {len(result['steps_technical'])} steps")
            return result
        return {}
    except Exception as e:
        logger.debug(f"[ai_remediation] failed (using template): {e}")
        return {}


# ══════════════════════════════════════════════════════════════════════
# Hook 6: AI EXPOSURE INTERPRETATION (v16.4.7)
# Instead of just "score: 67", AI explains:
# "Primary risk is D1 (leaked credentials). FIN7 targets your sector."
# ══════════════════════════════════════════════════════════════════════

async def hook_ai_exposure_interpretation(
    customer_name: str,
    industry: str,
    overall_score: float,
    d1: float, d2: float, d3: float, d4: float, d5: float,
    finding_count: int,
    critical_count: int,
) -> dict:
    """
    AI interprets exposure score and explains what to prioritize.
    Returns: {interpretation: str, priority_action: str, provider: str} or {}
    """
    if not _pipeline_ai_available():
        return {}

    _sys_exp = await _load_prompt("exposure_interpretation")
    if not _sys_exp: _sys_exp = "You are a cybersecurity risk analyst. Interpret this customer's exposure score."
    prompt = f"""{_sys_exp}

CUSTOMER: {customer_name}
INDUSTRY: {industry}
OVERALL SCORE: {overall_score}/100

DIMENSION BREAKDOWN:
  D1 Direct Exposure: {d1}/100 (weight: 45%) -  confirmed leaked credentials, CVEs, malicious IPs
  D2 Active Exploitation: {d2}/100 (weight: 20%) -  EPSS scores, CISA KEV, VirusTotal detections
  D3 Threat Actor Intent: {d3}/100 (weight: 15%) -  MITRE ATT&CK actors targeting this industry
  D4 Attack Surface: {d4}/100 (weight: 10%) -  exposed ports, services (Shodan)
  D5 Asset Criticality: {d5}/100 (weight: 10%) -  criticality of registered assets

FINDINGS: {finding_count} total, {critical_count} CRITICAL

Write 2-3 sentences explaining:
1. What the biggest risk driver is and why
2. One specific action to reduce the score most effectively

Respond ONLY with valid JSON:
{{"interpretation": "2-3 sentence explanation", "priority_action": "single most impactful action"}}"""

    try:
        result = await _llm_json(
            "You are a cybersecurity risk analyst. Respond ONLY with valid JSON.",
            prompt
        )
        if result.get("interpretation"):
            result["provider"] = _provider()
            result["ai_generated"] = True
            logger.info(f"[ai_exposure] {customer_name} -> {result['interpretation'][:60]}")
            return result
        return {}
    except Exception as e:
        logger.debug(f"[ai_exposure] failed: {e}")
        return {}


# ══════════════════════════════════════════════════════════════════════
# Hook 7: AI MATCH CONFIDENCE (v16.4.7)
# Scores ambiguous matches: "Is 'starbucks' in this paste really about
# the coffee company, or is it a gift card discussion?"
# ══════════════════════════════════════════════════════════════════════

async def hook_ai_match_confidence(
    ioc_type: str,
    ioc_value: str,
    source: str,
    correlation_type: str,
    matched_asset: str,
    customer_name: str,
    customer_industry: str,
    match_proof: str = "",
) -> dict:
    """
    AI assesses whether a rule-based match is a TRUE match or coincidental.
    Returns: {confidence: 0.0-1.0, reasoning: str, is_likely_fp: bool} or {}
    Only called for ambiguous strategies (keyword, brand, tech_stack, context).
    """
    if not _pipeline_ai_available():
        return {}

    _sys_match = await _load_prompt("match_confidence")
    if not _sys_match: _sys_match = "You are a threat intelligence analyst reviewing a match between a threat indicator and a customer."
    prompt = f"""{_sys_match}

MATCH DETAILS:
  IOC: {ioc_value}
  IOC Type: {ioc_type}
  Source feed: {source}
  Match strategy: {correlation_type}
  Matched asset: {matched_asset}
  Customer: {customer_name} (industry: {customer_industry})
  Match proof: {match_proof}

QUESTION: Is this a REAL threat match, or a coincidental/false positive?

Consider:
- Does the IOC context actually relate to this customer's business?
- "starbucks" in a gift card forum = low confidence (not a real threat)
- "starbucks" in a credential dump with @starbucks.com emails = high confidence
- Generic keywords matching in unrelated contexts = low confidence
- CVE matching a product the customer actually runs = high confidence
- Typosquat domain that resolves and has phishing content = high confidence

Respond ONLY with valid JSON:
{{"confidence": <0.0-1.0>, "reasoning": "<1-2 sentences explaining why>", "is_likely_fp": <true/false>}}"""

    try:
        result = await _llm_json(
            "You are a cybersecurity match quality analyst. Respond ONLY with valid JSON.",
            prompt
        )
        if "confidence" in result:
            result["confidence"] = max(0.0, min(1.0, float(result["confidence"])))
            result["provider"] = _provider()
            logger.info(f"[ai_match_conf] {ioc_value[:30]} -> conf={result['confidence']:.2f} fp={result.get('is_likely_fp')} | {result.get('reasoning','')[:60]}")
            return result
        return {}
    except Exception as e:
        logger.debug(f"[ai_match_conf] failed: {e}")
        return {}
