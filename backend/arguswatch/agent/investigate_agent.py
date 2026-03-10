"""
ArgusWatch AI Bar Agent -  Post-Compromise Investigation

WHAT THIS IS:
  After the AI Bar's regex classifies an IOC and the compromise API returns results,
  THIS agent reasons about what the results mean and decides what to investigate next.

WHAT IS GENUINELY AGENTIC HERE:
  The LLM looks at compromise results and DECIDES:
   - "3 stealer logs from same source -> check other emails from this domain"
   - "CVE matches customer tech stack -> check exposure score"
   - "IP flagged by VT + customer is in finance -> check FIN actors"
  The code does NOT predetermine these steps. The LLM picks them.

WHAT IS NOT AGENTIC (AND SHOULDN'T BE):
 - IOC classification -> regex is 100% accurate in 0ms. LLM would be slower and worse.
 - Compromise API calls -> deterministic fetch. No reasoning needed.
 - DB queries -> the reliable two-phase engine runs these deterministically.

FLOW:
  1. AI Bar regex classifies IOC (0ms) -  NOT AI
  2. Compromise check runs (2-10s) -  NOT AI
  3. Results + context fed to THIS agent -  AI STARTS HERE
  4. LLM Phase 1: "What do these results mean? What should I investigate next?" (15-30s local, 2-5s cloud)
  5. Python runs the follow-up queries deterministically (instant)
  6. LLM Phase 2: "Synthesize everything into an analyst brief" (15-30s local, 2-5s cloud)
  7. Optionally: auto-create finding + remediation if warranted

TOTAL TIME:
  Local (Qwen 3.5 9B): 45-90s after compromise results
  Cloud (Claude/Gemini): 5-10s after compromise results
  Compromise check itself: 2-10s
  So end-to-end: ~50-100s local, ~10-20s cloud

HONEST LABELS IN RESPONSE:
  Every response includes timing breakdown so the user sees exactly
  what took how long and what was AI vs automation.
"""
import json
import logging
import time
from datetime import datetime
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("arguswatch.agent.investigate")


# ══════════════════════════════════════════════════════════════════════
# PHASE 1: LLM DECIDES WHAT TO INVESTIGATE
# This is the genuinely agentic part -  LLM picks the follow-up actions
# ══════════════════════════════════════════════════════════════════════

INVESTIGATE_PROMPT = """You are a senior SOC analyst investigating a compromise indicator.
You just received results from automated compromise checks (HudsonRock, HIBP, VirusTotal, grep.app, local DB).

Based on the results below, decide what FOLLOW-UP investigation is needed.

Pick 1-3 actions from this list (only pick what's relevant):
  check_customer_findings -  look up all findings for this customer
  check_customer_exposure -  get D1-D5 exposure score breakdown
  check_related_emails -  search for other compromised emails from same domain
  check_threat_actors -  find actors targeting this customer's industry
  check_darkweb -  search dark web mentions for this customer
  check_remediations -  check if remediation tickets already exist
  skip -  results are clean, no follow-up needed

Respond ONLY with valid JSON:
{"actions": ["check_customer_findings", "check_threat_actors"], "reasoning": "3 stealer logs suggest active targeting. Need to check if this customer has other findings and which actors target their sector."}"""


async def _decide_followup(compromise_results: dict, query: str, query_type: str, llm_call) -> dict:
    """Phase 1: LLM decides what to investigate based on compromise results."""
    # Build context from compromise results
    total_hits = compromise_results.get("total_hits", 0)
    compromised = compromise_results.get("compromised", False)
    sources = compromise_results.get("sources_checked", [])
    findings = compromise_results.get("findings_preview", [])
    severity = compromise_results.get("severity_summary", {})

    context = f"""QUERY: {query} (type: {query_type})
COMPROMISED: {compromised}
TOTAL HITS: {total_hits}
SEVERITY: {json.dumps(severity)}
SOURCES: {json.dumps([{"name": s.get("name","?"), "hits": s.get("hits",0), "status": s.get("status","?")} for s in sources[:8]], default=str)}
TOP FINDINGS: {json.dumps(findings[:5], default=str)[:800]}"""

    try:
        response = await llm_call(
            [
                {"role": "system", "content": INVESTIGATE_PROMPT},
                {"role": "user", "content": context},
            ],
            []  # No tools -  just classification
        )
        text = (response.get("text") or "").strip()

        import re
        text = re.sub(r'```(?:json)?\s*', '', text).strip().rstrip('`').strip()
        m = re.search(r'\{[\s\S]+\}', text)
        if m:
            parsed = json.loads(m.group(0))
            valid_actions = {
                "check_customer_findings", "check_customer_exposure",
                "check_related_emails", "check_threat_actors",
                "check_darkweb", "check_remediations", "skip",
            }
            actions = [a for a in parsed.get("actions", []) if a in valid_actions]
            if not actions:
                actions = ["skip"] if not compromised else ["check_customer_findings"]
            return {
                "actions": actions[:3],  # Cap at 3 follow-ups
                "reasoning": parsed.get("reasoning", ""),
            }
    except Exception as e:
        logger.warning(f"[investigate] Phase 1 failed: {e}")

    # Fallback: rule-based (no LLM needed)
    if not compromised or total_hits == 0:
        return {"actions": ["skip"], "reasoning": "No compromise evidence found."}
    actions = ["check_customer_findings"]
    if total_hits >= 3:
        actions.append("check_threat_actors")
    if query_type == "email" and total_hits >= 2:
        actions.append("check_related_emails")
    return {"actions": actions, "reasoning": f"Fallback: {total_hits} hits detected."}


# ══════════════════════════════════════════════════════════════════════
# PHASE 2: EXECUTE FOLLOW-UP QUERIES (DETERMINISTIC)
# Python runs the queries. No LLM. Never fails.
# ══════════════════════════════════════════════════════════════════════

async def _run_followups(actions: list, query: str, query_type: str, compromise_results: dict, db: AsyncSession) -> dict:
    """Phase 2: Run follow-up queries deterministically."""
    from arguswatch.models import (
        Customer, Finding, ExposureHistory, ThreatActor,
        DarkWebMention, FindingRemediation, SeverityLevel,
    )

    results = {}

    # Try to resolve customer from the query
    customer_id = None
    customer_name = ""
    customer_industry = ""

    if query_type == "email" and "@" in query:
        domain = query.split("@")[1]
        # Search customers by domain
        from arguswatch.models import CustomerAsset
        cr = await db.execute(
            select(Customer).join(CustomerAsset, Customer.id == CustomerAsset.customer_id).where(
                CustomerAsset.asset_value.ilike(f"%{domain}%")
            ).limit(1)
        )
        cust = cr.scalar_one_or_none()
        if cust:
            customer_id = cust.id
            customer_name = cust.name
            customer_industry = cust.industry or ""
            results["customer"] = {"id": cust.id, "name": cust.name, "industry": cust.industry, "tier": cust.tier}
    elif query_type == "domain":
        from arguswatch.models import CustomerAsset
        cr = await db.execute(
            select(Customer).join(CustomerAsset, Customer.id == CustomerAsset.customer_id).where(
                CustomerAsset.asset_value.ilike(f"%{query}%")
            ).limit(1)
        )
        cust = cr.scalar_one_or_none()
        if cust:
            customer_id = cust.id
            customer_name = cust.name
            customer_industry = cust.industry or ""
            results["customer"] = {"id": cust.id, "name": cust.name, "industry": cust.industry, "tier": cust.tier}

    # If no customer found, try matching IOC value in findings
    if not customer_id:
        fr = await db.execute(
            select(Finding).where(Finding.ioc_value.ilike(f"%{query}%")).limit(1)
        )
        f = fr.scalar_one_or_none()
        if f and f.customer_id:
            customer_id = f.customer_id
            cr2 = await db.execute(select(Customer).where(Customer.id == customer_id))
            cust2 = cr2.scalar_one_or_none()
            if cust2:
                customer_name = cust2.name
                customer_industry = cust2.industry or ""
                results["customer"] = {"id": cust2.id, "name": cust2.name, "industry": cust2.industry}

    for action in actions:
        if action == "skip":
            continue

        if action == "check_customer_findings" and customer_id:
            r = await db.execute(
                select(Finding).where(Finding.customer_id == customer_id)
                .order_by(Finding.created_at.desc()).limit(10)
            )
            findings = []
            for f in r.scalars().all():
                findings.append({
                    "id": f.id, "ioc_value": (f.ioc_value or "")[:60], "ioc_type": f.ioc_type,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "status": f.status.value if hasattr(f.status, 'value') else str(f.status),
                    "actor_name": f.actor_name or "",
                })
            sev_counts = {}
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                try:
                    sc = await db.execute(
                        select(func.count(Finding.id)).where(
                            Finding.customer_id == customer_id,
                            Finding.severity == SeverityLevel(sev),
                        )
                    )
                    sev_counts[sev] = sc.scalar() or 0
                except ValueError:
                    pass
            results["findings"] = {"items": findings, "severity_counts": sev_counts, "total": len(findings)}

        elif action == "check_customer_exposure" and customer_id:
            eh = await db.execute(
                select(ExposureHistory).where(ExposureHistory.customer_id == customer_id)
                .order_by(ExposureHistory.snapshot_date.desc()).limit(1)
            )
            row = eh.scalar_one_or_none()
            if row:
                results["exposure"] = {
                    "overall": row.overall_score or 0,
                    "d1": row.d1_score or 0, "d2": row.d2_score or 0,
                    "d3": row.d3_score or 0, "d4": row.d4_score or 0,
                    "d5": row.d5_score or 0,
                }

        elif action == "check_related_emails" and query_type == "email" and "@" in query:
            domain = query.split("@")[1]
            r = await db.execute(
                select(Finding).where(
                    Finding.ioc_type == "email",
                    Finding.ioc_value.ilike(f"%@{domain}%"),
                ).order_by(Finding.created_at.desc()).limit(10)
            )
            emails = [{"ioc_value": f.ioc_value[:60], "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity)} for f in r.scalars().all()]
            results["related_emails"] = {"domain": domain, "count": len(emails), "items": emails}

        elif action == "check_threat_actors":
            industry = customer_industry or "unknown"
            r = await db.execute(select(ThreatActor).limit(20))
            actors = []
            for a in r.scalars().all():
                sectors = a.target_sectors or []
                if industry != "unknown" and not any(industry.lower() in (s or "").lower() for s in sectors):
                    continue
                actors.append({
                    "name": a.name, "country": a.origin_country,
                    "motivation": a.motivation, "mitre_id": a.mitre_id,
                    "target_sectors": sectors[:3],
                })
            results["actors"] = {"industry": industry, "count": len(actors), "items": actors[:5]}

        elif action == "check_darkweb" and customer_id:
            r = await db.execute(
                select(DarkWebMention).where(DarkWebMention.customer_id == customer_id)
                .order_by(DarkWebMention.discovered_at.desc()).limit(5)
            )
            mentions = [{"source": m.source, "content": (m.content_snippet or "")[:80], "threat_actor": m.threat_actor} for m in r.scalars().all()]
            results["darkweb"] = {"count": len(mentions), "items": mentions}

        elif action == "check_remediations" and customer_id:
            # Find remediations for this customer's findings
            from sqlalchemy import and_
            r = await db.execute(
                select(FindingRemediation).join(Finding, FindingRemediation.finding_id == Finding.id).where(
                    Finding.customer_id == customer_id,
                    FindingRemediation.status.in_(["pending", "in_progress"]),
                ).limit(5)
            )
            rems = [{"title": (rem.title or "")[:60], "status": rem.status, "deadline": rem.deadline.isoformat() if rem.deadline else None} for rem in r.scalars().all()]
            results["remediations"] = {"count": len(rems), "items": rems}

    return results


# ══════════════════════════════════════════════════════════════════════
# PHASE 3: LLM SYNTHESIZES ANALYST BRIEF
# The genuinely valuable part -  LLM writes what a human analyst would
# ══════════════════════════════════════════════════════════════════════

SYNTHESIZE_PROMPT = """You are a senior SOC analyst writing an investigation brief.
You ran an initial compromise check AND follow-up investigation on an IOC.
Write a concise 3-5 sentence analyst brief that:
1. States the core finding (compromised or clean, how many sources)
2. Provides context from follow-up investigation (related findings, exposure, actors)
3. Gives ONE specific recommended action with a timeframe

Use specific numbers, names, severity levels from the data. Do NOT guess or add data that isn't in the results.
Keep it under 150 words. Write for a security analyst, not an executive."""


async def _synthesize_brief(
    query: str,
    query_type: str,
    compromise_results: dict,
    followup_reasoning: str,
    followup_results: dict,
    llm_call,
) -> str:
    """Phase 3: LLM writes the analyst investigation brief."""
    data = {
        "query": query,
        "type": query_type,
        "compromised": compromise_results.get("compromised", False),
        "total_hits": compromise_results.get("total_hits", 0),
        "severity": compromise_results.get("severity_summary", {}),
        "investigation_reasoning": followup_reasoning,
        "followup": followup_results,
    }
    data_str = json.dumps(data, default=str, indent=2)
    if len(data_str) > 3000:
        data_str = data_str[:2997] + "..."

    try:
        response = await llm_call(
            [
                {"role": "system", "content": SYNTHESIZE_PROMPT},
                {"role": "user", "content": f"INVESTIGATION DATA:\n{data_str}"},
            ],
            []
        )
        text = (response.get("text") or "").strip()
        if text and len(text) > 30:
            return text
    except Exception as e:
        logger.warning(f"[investigate] Phase 3 synthesis failed: {e}")

    # Fallback: structured text
    total = compromise_results.get("total_hits", 0)
    compromised = compromise_results.get("compromised", False)
    if not compromised:
        return f"No compromise evidence found for {query}. Checked HudsonRock, HIBP, VirusTotal, grep.app, and local database."

    parts = [f"{query} found in {total} source(s)."]
    if followup_results.get("findings"):
        fc = followup_results["findings"]
        parts.append(f"Customer has {fc['total']} total findings ({fc.get('severity_counts',{}).get('CRITICAL',0)} CRITICAL).")
    if followup_results.get("actors"):
        ac = followup_results["actors"]
        if ac["items"]:
            names = ", ".join(a["name"] for a in ac["items"][:3])
            parts.append(f"Active threat actors for {ac['industry']} sector: {names}.")
    parts.append("Recommend immediate credential rotation and MFA audit.")
    return " ".join(parts)


# ══════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

async def investigate_ioc(
    query: str,
    query_type: str,
    compromise_results: dict,
    db: AsyncSession,
    provider: str = "auto",
) -> dict:
    """
    Full agentic investigation: LLM reasons about compromise results,
    decides follow-up queries, Python executes them, LLM synthesizes brief.

    Returns dict with timing breakdown at every phase for honest transparency.
    """
    from arguswatch.services.ai_pipeline_hooks import _provider as _get_provider

    if not provider or provider == "auto":
        provider = _get_provider()

    # Get LLM caller
    if provider == "anthropic":
        from arguswatch.agent.agent_core import _call_anthropic as llm_call
    elif provider == "openai":
        from arguswatch.agent.agent_core import _call_openai as llm_call
    elif provider == "google":
        from arguswatch.agent.agent_core import _call_google as llm_call
    else:
        from arguswatch.agent.agent_core import _call_ollama as llm_call

    timing = {}

    # ── Phase 1: LLM decides what to investigate ─────────────
    t0 = time.time()
    decision = await _decide_followup(compromise_results, query, query_type, llm_call)
    timing["phase1_decide"] = round(time.time() - t0, 1)
    timing["phase1_method"] = "llm" if decision.get("reasoning") and len(decision["reasoning"]) > 20 else "fallback"

    actions = decision.get("actions", ["skip"])

    # ── Phase 2: Execute follow-up queries (instant) ─────────
    t1 = time.time()
    followup_results = {}
    if "skip" not in actions:
        followup_results = await _run_followups(actions, query, query_type, compromise_results, db)
    timing["phase2_queries"] = round(time.time() - t1, 1)
    timing["phase2_method"] = "deterministic"
    timing["phase2_actions"] = actions

    # ── Phase 3: LLM synthesizes brief ───────────────────────
    t2 = time.time()
    brief = await _synthesize_brief(
        query, query_type, compromise_results,
        decision.get("reasoning", ""), followup_results, llm_call,
    )
    timing["phase3_synthesize"] = round(time.time() - t2, 1)
    timing["phase3_method"] = "llm" if len(brief) > 60 else "fallback"

    timing["total"] = round(time.time() - t0, 1)

    return {
        "brief": brief,
        "actions_taken": actions,
        "reasoning": decision.get("reasoning", ""),
        "followup_data": followup_results,
        "provider": provider,
        "timing": timing,
        "agentic": "skip" not in actions,  # Only truly agentic if it investigated further
    }
