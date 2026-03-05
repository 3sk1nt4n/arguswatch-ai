"""
AI Pipeline Orchestrator V13 - the LLM decides which steps to run and in what order.

This is the "AI in the center" transformation. Instead of a fixed 10-step linear pipeline,
the LLM examines a detection, decides what it needs to know, calls pipeline steps as tools,
examines results, and decides what to do next.

ARCHITECTURE:
  detection arrives
      ↓
  ai_orchestrate_detection(detection_id)
      ↓
  LLM receives: IOC type, value, source, existing data
  LLM decides: which pipeline tools to call
  LLM calls tools → gets real DB results back
  LLM decides: what to call next based on results
  LLM reaches conclusion → writes final assessment
      ↓
  Finding updated with AI decisions + narrative

PIPELINE TOOLS exposed to the orchestrator LLM:
  pipeline_enrich        - run VT/AbuseIPDB/OTX enrichment
  pipeline_route         - match detection to customer
  pipeline_get_candidates- get attribution candidates from DB
  pipeline_set_severity  - AI sets severity + SLA directly
  pipeline_set_actor     - AI attributes to a specific actor
  pipeline_flag_fp       - AI marks as false positive with reason
  pipeline_write_narrative- AI writes investigation narrative
  pipeline_check_campaign - check if part of active campaign
  pipeline_get_context   - get finding's full current state

ENTRY POINTS:
  ai_orchestrate_detection(detection_id)   - full AI-driven pipeline
  ai_triage_only(detection_id)             - fast path: just triage + narrative

FALLBACK:
  If orchestrator fails, the standard linear pipeline (_async_pipeline) still runs.
  AI orchestration is opt-in via settings.AI_ORCHESTRATION_ENABLED (default: True if key set).
"""
import json
import logging
import asyncio
from datetime import datetime
from arguswatch.config import settings
from arguswatch.agent.agent_core import SYSTEM_PROMPT

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


logger = logging.getLogger("arguswatch.ai_orchestrator")


def _orchestration_enabled() -> bool:
    return bool(
        getattr(settings, "ANTHROPIC_API_KEY", "") or
        getattr(settings, "OPENAI_API_KEY", "")
        # Ollama excluded from orchestration - too slow for per-detection calls
        # Use Ollama only for the chat agent, not the pipeline
    )


def _provider() -> str:
    """Orchestrator uses Anthropic or OpenAI only - same exclusion as pipeline hooks.
    Ollama is too slow (120s timeout) for per-detection orchestration calls.
    Returns 'none' if no fast provider is configured."""
    if getattr(settings, "ANTHROPIC_API_KEY", ""):
        return "anthropic"
    if getattr(settings, "OPENAI_API_KEY", ""):
        return "openai"
    return "none"


# ══════════════════════════════════════════════════════════════════════
# PIPELINE TOOL IMPLEMENTATIONS
# Each tool is a real async function that hits the DB or calls APIs
# ══════════════════════════════════════════════════════════════════════

async def _tool_get_context(detection_id: int, finding_id: int | None = None) -> dict:
    """Get current state of detection + finding from DB."""
    from arguswatch.database import async_session
    from arguswatch.models import Detection, Finding, Customer, ThreatActor
    from sqlalchemy import select

    async with async_session() as db:
        r = await db.execute(select(Detection).where(Detection.id == detection_id))
        det = r.scalar_one_or_none()
        if not det:
            return {"error": f"Detection {detection_id} not found"}

        result = {
            "detection_id": detection_id,
            "ioc_value": det.ioc_value,
            "ioc_type": det.ioc_type,
            "source": det.source,
            "severity": _sev(det.severity) or None,
            "status": det.status.value if det.status else None,
            "customer_id": det.customer_id,
            "finding_id": det.finding_id,
            "confidence": det.confidence,
        }

        if det.customer_id:
            rc = await db.execute(select(Customer).where(Customer.id == det.customer_id))
            cust = rc.scalar_one_or_none()
            if cust:
                result["customer_name"] = cust.name
                result["customer_industry"] = getattr(cust, "industry", "")

        if det.finding_id:
            rf = await db.execute(select(Finding).where(Finding.id == det.finding_id))
            f = rf.scalar_one_or_none()
            if f:
                result["finding"] = {
                    "id": f.id,
                    "severity": _sev(f.severity) or None,
                    "actor_name": f.actor_name,
                    "source_count": f.source_count,
                    "ai_severity_decision": getattr(f, "ai_severity_decision", None),
                    "ai_narrative": (getattr(f, "ai_narrative", None) or "")[:200],
                }

        return result


async def _tool_enrich(detection_id: int) -> dict:
    """Run VT/AbuseIPDB/OTX enrichment. Returns enrichment summary."""
    try:
        from arguswatch.services.enrichment_pipeline import enrich_detection
        result = await enrich_detection(detection_id)
        return {
            "enriched": result.get("enrichments", []),
            "vt_malicious": result.get("vt_malicious", 0),
            "abuse_score": result.get("abuse_score", 0),
            "otx_pulses": result.get("otx_pulses", 0),
            "status": "completed",
        }
    except Exception as e:
        return {"status": "failed", "error": str(e)}


async def _tool_route(detection_id: int) -> dict:
    """Match detection to customers via asset correlation."""
    from arguswatch.database import async_session
    from arguswatch.models import Detection
    from arguswatch.engine.correlation_engine import route_detection
    from sqlalchemy import select

    async with async_session() as db:
        r = await db.execute(select(Detection).where(Detection.id == detection_id))
        det = r.scalar_one_or_none()
        if not det:
            return {"error": "not found"}
        matched = await route_detection(det, db)
        await db.commit()
        return {
            "matched_customers": matched or [],
            "correlation_type": det.correlation_type,
            "matched_asset": det.matched_asset,
            "count": len(matched or []),
        }


async def _tool_get_candidates(detection_id: int, finding_id: int | None = None) -> dict:
    """Get attribution candidates from DB with full metadata."""
    from arguswatch.database import async_session
    from arguswatch.models import Detection, Finding
    from arguswatch.engine.attribution_engine import get_candidate_actors
    from sqlalchemy import select

    async with async_session() as db:
        fid = finding_id
        if not fid:
            r = await db.execute(select(Detection).where(Detection.id == detection_id))
            det = r.scalar_one_or_none()
            fid = det.finding_id if det else None

        if not fid:
            return {"candidates": [], "count": 0, "note": "no finding yet"}

        rf = await db.execute(select(Finding).where(Finding.id == fid))
        finding = rf.scalar_one_or_none()
        if not finding:
            return {"candidates": [], "count": 0}

        candidates = await get_candidate_actors(finding, db)
        return {
            "candidates": candidates[:8],
            "count": len(candidates),
            "finding_id": fid,
        }


async def _tool_set_severity(
    finding_id: int,
    severity: str,
    sla_hours: int,
    reasoning: str,
    confidence: float,
) -> dict:
    """AI directly sets severity and SLA on a finding."""
    from arguswatch.database import async_session
    from arguswatch.models import Finding, SeverityLevel
    from sqlalchemy import select

    valid = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    if severity.upper() not in valid:
        return {"error": f"Invalid severity: {severity}. Must be one of {valid}"}

    async with async_session() as db:
        rf = await db.execute(select(Finding).where(Finding.id == finding_id))
        f = rf.scalar_one_or_none()
        if not f:
            return {"error": f"Finding {finding_id} not found"}
        f.severity = SeverityLevel(severity.upper())
        f.sla_hours = sla_hours
        f.confidence = float(confidence)
        f.ai_severity_decision = severity.upper()
        f.ai_severity_reasoning = reasoning
        f.ai_severity_confidence = float(confidence)
        f.ai_provider = _provider()
        await db.commit()
        return {
            "finding_id": finding_id,
            "severity_set": severity.upper(),
            "sla_hours": sla_hours,
            "reasoning": reasoning,
        }


async def _tool_set_actor(
    finding_id: int,
    actor_name: str,
    confidence: float,
    reasoning: str,
) -> dict:
    """AI attributes finding to a specific threat actor."""
    from arguswatch.database import async_session
    from arguswatch.models import Finding, ThreatActor
    from sqlalchemy import select

    async with async_session() as db:
        rf = await db.execute(select(Finding).where(Finding.id == finding_id))
        f = rf.scalar_one_or_none()
        if not f:
            return {"error": f"Finding {finding_id} not found"}

        ra = await db.execute(select(ThreatActor).where(ThreatActor.name == actor_name).limit(1))
        actor = ra.scalar_one_or_none()
        if actor:
            f.actor_id = actor.id
        f.actor_name = actor_name
        f.ai_attribution_reasoning = reasoning
        f.ai_provider = _provider()
        await db.commit()
        return {
            "finding_id": finding_id,
            "actor_set": actor_name,
            "actor_id": actor.id if actor else None,
            "confidence": confidence,
        }


async def _tool_flag_fp(finding_id: int, reason: str, confidence: float) -> dict:
    """AI flags a finding as false positive. Closes it only if autonomous + high confidence."""
    from arguswatch.database import async_session
    from arguswatch.models import Finding, DetectionStatus
    from arguswatch.config import settings as _sfp
    from sqlalchemy import select

    # Hard confidence gate - LLM cannot bypass this regardless of prompt
    if confidence < 0.80:
        return {
            "error": f"Confidence {confidence:.2f} too low to flag FP (minimum 0.80)",
            "finding_id": finding_id,
            "flagged_fp": False,
        }

    async with async_session() as db:
        rf = await db.execute(select(Finding).where(Finding.id == finding_id))
        f = rf.scalar_one_or_none()
        if not f:
            return {"error": f"Finding {finding_id} not found"}

        # Always flag
        f.ai_false_positive_flag = True
        f.ai_false_positive_reason = reason

        # Only auto-close in autonomous mode
        if getattr(_sfp, "AI_AUTONOMOUS", False):
            f.status = DetectionStatus.FALSE_POSITIVE
            f.resolved_at = datetime.utcnow()
            await db.commit()
            return {
                "finding_id": finding_id,
                "flagged_fp": True,
                "auto_closed": True,
                "reason": reason,
                "confidence": confidence,
                "status": "FALSE_POSITIVE",
            }
        else:
            await db.commit()
            return {
                "finding_id": finding_id,
                "flagged_fp": True,
                "auto_closed": False,
                "reason": reason,
                "confidence": confidence,
                "note": "Safe mode: flagged but not closed. Analyst review required.",
            }


async def _tool_write_narrative(
    finding_id: int,
    narrative: str,
) -> dict:
    """Store AI-written investigation narrative on finding."""
    from arguswatch.database import async_session
    from arguswatch.models import Finding
    from sqlalchemy import select

    async with async_session() as db:
        rf = await db.execute(select(Finding).where(Finding.id == finding_id))
        f = rf.scalar_one_or_none()
        if not f:
            return {"error": f"Finding {finding_id} not found"}
        f.ai_narrative = narrative
        f.ai_enriched_at = datetime.utcnow()
        f.ai_provider = _provider()
        await db.commit()
        return {"finding_id": finding_id, "narrative_length": len(narrative), "stored": True}


async def _tool_check_campaign(finding_id: int) -> dict:
    """Check if finding is part of an active campaign."""
    from arguswatch.database import async_session
    from arguswatch.models import Finding
    from arguswatch.engine.campaign_detector import check_and_create_campaign
    from sqlalchemy import select

    async with async_session() as db:
        rf = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = rf.scalar_one_or_none()
        if not finding or not finding.actor_id:
            return {"campaign": None, "note": "no actor attributed yet"}
        campaign = await check_and_create_campaign(finding, db)
        await db.commit()
        if campaign:
            return {
                "campaign_id": campaign.id,
                "campaign_name": campaign.name,
                "kill_chain_stage": campaign.kill_chain_stage,
                "finding_count": campaign.finding_count,
                "status": campaign.status,
            }
        return {"campaign": None}


# ══════════════════════════════════════════════════════════════════════
# TOOL REGISTRY + SCHEMAS for orchestrator LLM
# ══════════════════════════════════════════════════════════════════════

ORCHESTRATOR_TOOLS = {
    "pipeline_get_context":    _tool_get_context,
    "pipeline_enrich":         _tool_enrich,
    "pipeline_route":          _tool_route,
    "pipeline_get_candidates": _tool_get_candidates,
    "pipeline_set_severity":   _tool_set_severity,
    "pipeline_set_actor":      _tool_set_actor,
    "pipeline_flag_fp":        _tool_flag_fp,
    "pipeline_write_narrative":_tool_write_narrative,
    "pipeline_check_campaign": _tool_check_campaign,
}

ORCHESTRATOR_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "pipeline_get_context",
            "description": "Get the current state of a detection and its associated finding from the database. Call this first to understand what you're working with.",
            "parameters": {
                "type": "object",
                "properties": {
                    "detection_id": {"type": "integer"},
                    "finding_id": {"type": "integer"},
                },
                "required": ["detection_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pipeline_enrich",
            "description": "Run VirusTotal, AbuseIPDB, and OTX enrichment on a detection. Returns malicious engine count, abuse score, and pulse count.",
            "parameters": {
                "type": "object",
                "properties": {
                    "detection_id": {"type": "integer"},
                },
                "required": ["detection_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pipeline_route",
            "description": "Match this detection to customer accounts via asset correlation (domain, IP, email, keywords). Run this if customer_id is null.",
            "parameters": {
                "type": "object",
                "properties": {
                    "detection_id": {"type": "integer"},
                },
                "required": ["detection_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pipeline_get_candidates",
            "description": "Get threat actor candidates from the database with full metadata: target sectors, techniques, origin country, MITRE ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "detection_id": {"type": "integer"},
                    "finding_id": {"type": "integer"},
                },
                "required": ["detection_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pipeline_set_severity",
            "description": "Set the severity level, SLA hours, and reasoning on the finding. You are the decision-maker. Set any severity from CRITICAL to INFO.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                    "sla_hours": {"type": "integer", "description": "Hours to remediate: CRITICAL=1-4, HIGH=4-24, MEDIUM=24-72, LOW=72+"},
                    "reasoning": {"type": "string", "description": "Evidence-based reasoning citing specific numbers"},
                    "confidence": {"type": "number", "description": "0.0 to 1.0"},
                },
                "required": ["finding_id", "severity", "sla_hours", "reasoning", "confidence"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pipeline_set_actor",
            "description": "Attribute the finding to a specific threat actor. Only call after reviewing candidates. Be specific about why this actor over others.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer"},
                    "actor_name": {"type": "string"},
                    "confidence": {"type": "number"},
                    "reasoning": {"type": "string"},
                },
                "required": ["finding_id", "actor_name", "confidence", "reasoning"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pipeline_flag_fp",
            "description": "Mark finding as false positive and auto-close it. Only use when confidence > 0.80. Cite specific reason.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer"},
                    "reason": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["finding_id", "reason", "confidence"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pipeline_write_narrative",
            "description": "Write the final investigation narrative that analysts and executives will see. Call this last, after setting severity and actor.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer"},
                    "narrative": {"type": "string", "description": "2-4 sentence specific narrative: what the IOC is, what the evidence shows, who is responsible, what to do first."},
                },
                "required": ["finding_id", "narrative"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pipeline_check_campaign",
            "description": "Check if this finding is part of an active attack campaign. Call after setting actor.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer"},
                },
                "required": ["finding_id"],
            },
        },
    },
]

ORCHESTRATOR_SYSTEM = """You are ArgusWatch AI Pipeline Orchestrator - an autonomous cybersecurity analyst running inside a live threat detection platform.

You receive a detection ID. You have tools to:
1. Get context (what is this IOC, is it already routed to a customer?)
2. Enrich it (real VT/AbuseIPDB/OTX data)
3. Route it to a customer if not already done
4. Get threat actor candidates from the database
5. Set severity based on evidence (you are the decision-maker - not a lookup table)
6. Attribute to the most likely actor with reasoning
7. Flag as false positive if the evidence is clearly benign
8. Write the investigation narrative analysts will see
9. Check for active campaigns

YOUR DECISION LOGIC:
- Always start with pipeline_get_context
- If customer_id is null → call pipeline_route
- If enrichment data is missing → call pipeline_enrich
- Set severity based on actual numbers, not just IOC type
- If multiple actor candidates exist → pick the best fit for the customer's industry
- If VT < 2 and AbuseIPDB < 30 and source is a single low-confidence feed → flag as FP
- Always end with pipeline_write_narrative so analysts see your reasoning

Be efficient. Use 3-8 tool calls total. Do not call the same tool twice."""


# ══════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

async def ai_orchestrate_detection(detection_id: int) -> dict:
    """
    AI-driven pipeline: LLM decides which steps to run and in what order.
    Returns a dict with steps taken, tools called, and final assessment.
    Falls back to None if AI orchestration is disabled/unavailable.
    """
    if not _orchestration_enabled():
        return None

    provider = _provider()
    messages = [
        {"role": "system", "content": ORCHESTRATOR_SYSTEM},
        {"role": "user", "content": f"Process detection ID {detection_id}. Start by getting context, then make all necessary decisions."},
    ]

    tools_called = []
    tool_results = []
    max_iterations = 12

    try:
        if provider == "anthropic":
            from arguswatch.agent.agent_core import _call_anthropic
            _call_llm = lambda msgs: _call_anthropic(msgs, ORCHESTRATOR_SCHEMAS)
            def _append_tool_results(msgs, tc_list, results_list):
                msgs.append({"role": "user", "content": results_list})
        elif provider == "openai":
            from arguswatch.agent.agent_core import _call_openai
            _call_llm = lambda msgs: _call_openai(msgs, ORCHESTRATOR_SCHEMAS)
            def _append_tool_results(msgs, tc_list, results_list):
                pass  # results already appended per-tool below
        else:
            return None

        for iteration in range(max_iterations):
            response = await _call_llm(messages)

            if response["stop_reason"] == "end_turn" or not response["tool_calls"]:
                logger.info(f"[orchestrator] detection={detection_id} complete in {iteration+1} iterations, tools={tools_called}")
                return {
                    "orchestrated": True,
                    "provider": provider,
                    "iterations": iteration + 1,
                    "tools_called": tools_called,
                    "tool_results": tool_results,
                    "final_text": response["text"],
                }

            # Append assistant message
            if provider == "anthropic":
                messages.append({"role": "assistant", "content": response["raw_content"]})
                ant_results = []
            else:
                messages.append({"role": "assistant", **response["raw_message"]})

            # Execute each tool call
            for tc in response["tool_calls"]:
                tool_name = tc["name"]
                tool_args = tc["args"]

                if tool_name not in ORCHESTRATOR_TOOLS:
                    result = {"error": f"Unknown tool: {tool_name}"}
                else:
                    try:
                        result = await ORCHESTRATOR_TOOLS[tool_name](**tool_args)
                        tools_called.append(tool_name)
                        tool_results.append({"tool": tool_name, "args": tool_args, "result": result})
                        logger.info(f"[orchestrator] {tool_name}({tool_args}) → {str(result)[:120]}")
                    except Exception as e:
                        result = {"error": str(e), "tool": tool_name}
                        logger.warning(f"[orchestrator] {tool_name} failed: {e}")

                result_str = json.dumps(result, default=str)[:2000]

                if provider == "anthropic":
                    ant_results.append({
                        "type": "tool_result",
                        "tool_use_id": tc["id"],
                        "content": result_str,
                    })
                else:
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": result_str,
                    })

            if provider == "anthropic" and ant_results:
                messages.append({"role": "user", "content": ant_results})

    except Exception as e:
        logger.error(f"[orchestrator] Fatal error for detection {detection_id}: {e}")
        return None

    return {
        "orchestrated": True,
        "provider": provider,
        "iterations": max_iterations,
        "tools_called": tools_called,
        "note": "max iterations reached",
    }
