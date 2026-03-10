"""
ArgusWatch Reliable Chat Agent -  Two-Phase Architecture

WHY THIS EXISTS:
  The tool-calling chat agent (/api/ai/agent-query) depends on Ollama
  reliably using function calling. With qwen2.5:14b/llama3.1:8b, tool
  calling works ~60-70% of the time. The other 30% the LLM ignores
  tools and hallucinates data. Unacceptable for a security platform.

HOW THIS WORKS:
  Phase 1: LLM classifies intent + extracts parameters (JSON only, no tools)
           Small models are GOOD at "what is this question about?" + "extract names"
  Phase 2: Python executes the right DB queries deterministically (never fails)
  Phase 3: LLM summarizes real results into natural language (small models GOOD at this)

RESULT:
 - No dependency on Ollama tool-calling API
 - Queries are deterministic -  same question always hits the same DB path
 - LLM only does what small models are good at: classify + summarize
 - Falls back gracefully: if Phase 1 fails, run ALL queries and let Phase 3 filter
 - 2 LLM calls instead of 3-6 iterative calls = faster + cheaper

ENDPOINTS:
  POST /api/ai/chat  -  the reliable version (this file)
  POST /api/ai/agent-query -  the old tool-calling version (kept for cloud providers)
"""
import json
import logging
import re
from datetime import datetime
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("arguswatch.agent.reliable_chat")


# ══════════════════════════════════════════════════════════════════════
# PHASE 1: INTENT CLASSIFICATION
# Ask LLM: "What is this question about?" -> structured JSON
# This works reliably even with 7B models because it's classification,
# not open-ended tool selection.
# ══════════════════════════════════════════════════════════════════════

INTENT_PROMPT = """You are a query classifier for a cybersecurity threat intelligence platform.
Given a user question, extract the INTENT and PARAMETERS.

INTENTS (pick ONE or TWO most relevant):
  customers    -  asking about customers, clients, tenants, who we monitor
  findings     -  asking about threats, IOCs, vulnerabilities, detections, alerts
  exposure     -  asking about risk scores, exposure scores, D1-D5 dimensions
  actors       -  asking about threat actors, APT groups, attackers, adversaries
  darkweb      -  asking about dark web mentions, ransomware, leaks, pastes
  remediations -  asking about remediation tasks, actions, SLA, deadlines, fixes
  summary      -  asking for an overview, dashboard summary, status report

PARAMETERS to extract (leave empty string if not mentioned):
  customer_name -  specific customer/company name mentioned
  severity      -  specific severity level (CRITICAL, HIGH, MEDIUM, LOW)
  ioc_type      -  specific IOC type (cve_id, domain, ipv4, email, url, etc.)
  actor_name    -  specific threat actor name
  status        -  specific status (pending, in_progress, completed, new, open)
  industry      -  specific industry mentioned
  country       -  specific country mentioned

Respond ONLY with valid JSON, nothing else:
{"intents": ["findings", "customers"], "customer_name": "", "severity": "CRITICAL", "ioc_type": "", "actor_name": "", "status": "", "industry": "", "country": ""}"""


async def _classify_intent(question: str, llm_call) -> dict:
    """Phase 1: Classify the question into intents + extract parameters.
    
    Returns a dict with intents list and extracted parameters.
    Falls back to broad search if LLM response is unparseable.
    """
    try:
        response = await llm_call(
            [
                {"role": "system", "content": INTENT_PROMPT},
                {"role": "user", "content": question},
            ],
            []  # NO tools -  just text completion
        )
        text = response.get("text", "").strip()

        # Strip markdown fences
        text = re.sub(r'```(?:json)?\s*', '', text).strip().rstrip('`').strip()
        m = re.search(r'\{[\s\S]+\}', text)
        if m:
            parsed = json.loads(m.group(0))
            # Validate intents
            valid_intents = {"customers", "findings", "exposure", "actors", "darkweb", "remediations", "summary"}
            intents = [i for i in parsed.get("intents", []) if i in valid_intents]
            if not intents:
                intents = ["summary"]
            parsed["intents"] = intents
            logger.info(f"[reliable_chat] Phase 1: intents={intents} params={json.dumps({k:v for k,v in parsed.items() if v and k != 'intents'})}")
            return parsed
    except Exception as e:
        logger.warning(f"[reliable_chat] Phase 1 classification failed: {e}")

    # Fallback: keyword-based intent detection (no LLM needed)
    return _keyword_fallback(question)


def _keyword_fallback(question: str) -> dict:
    """If LLM fails, use keyword matching. Dumb but reliable."""
    q = question.lower()
    intents = []

    if any(w in q for w in ["customer", "client", "tenant", "who do we", "how many customer"]):
        intents.append("customers")
    if any(w in q for w in ["finding", "threat", "ioc", "cve", "vuln", "alert", "detection", "critical"]):
        intents.append("findings")
    if any(w in q for w in ["exposure", "risk score", "d1", "d2", "d3", "d4", "d5", "score"]):
        intents.append("exposure")
    if any(w in q for w in ["actor", "apt", "attacker", "adversary", "group", "fin7", "lazarus"]):
        intents.append("actors")
    if any(w in q for w in ["dark web", "darkweb", "ransomware", "leak", "paste", "onion"]):
        intents.append("darkweb")
    if any(w in q for w in ["remediat", "playbook", "action", "sla", "deadline", "fix", "patch"]):
        intents.append("remediations")

    if not intents:
        intents = ["summary"]

    # Extract obvious parameters
    severity = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev.lower() in q:
            severity = sev
            break

    logger.info(f"[reliable_chat] Phase 1 FALLBACK: intents={intents}")
    return {
        "intents": intents,
        "customer_name": "",
        "severity": severity,
        "ioc_type": "",
        "actor_name": "",
        "status": "",
        "industry": "",
        "country": "",
    }


# ══════════════════════════════════════════════════════════════════════
# PHASE 2: DETERMINISTIC QUERY EXECUTION
# Python runs the right queries. No LLM involved. Never fails.
# ══════════════════════════════════════════════════════════════════════

async def _execute_queries(intents: dict, db: AsyncSession) -> dict:
    """Phase 2: Execute DB queries based on classified intents.
    
    Returns structured data dict -  real data, not hallucinated.
    """
    from arguswatch.models import (
        Customer, Finding, ExposureHistory, ThreatActor,
        DarkWebMention, FindingRemediation, SeverityLevel,
    )

    results = {}
    params = intents  # convenience alias
    customer_name = (params.get("customer_name") or "").strip()
    severity = (params.get("severity") or "").upper().strip()
    ioc_type = (params.get("ioc_type") or "").strip()
    actor_name = (params.get("actor_name") or "").strip()
    status = (params.get("status") or "").strip()
    industry = (params.get("industry") or "").strip()

    # Resolve customer_id from name if provided
    customer_id = None
    if customer_name:
        cr = await db.execute(
            select(Customer).where(Customer.name.ilike(f"%{customer_name}%")).limit(1)
        )
        cust = cr.scalar_one_or_none()
        if cust:
            customer_id = cust.id
            results["resolved_customer"] = {"id": cust.id, "name": cust.name, "industry": cust.industry, "tier": cust.tier}

    intent_list = params.get("intents", ["summary"])

    # ── CUSTOMERS ────────────────────────────────────────────────
    if "customers" in intent_list or "summary" in intent_list:
        q = select(Customer).where(Customer.active == True)
        if customer_name:
            q = q.where(Customer.name.ilike(f"%{customer_name}%"))
        if industry:
            q = q.where(Customer.industry.ilike(f"%{industry}%"))
        q = q.limit(15)
        r = await db.execute(q)
        customers = []
        for c in r.scalars().all():
            fc = await db.execute(select(func.count(Finding.id)).where(Finding.customer_id == c.id))
            customers.append({
                "id": c.id, "name": c.name, "industry": c.industry,
                "tier": c.tier, "finding_count": fc.scalar() or 0,
            })
        results["customers"] = customers
        results["customer_count"] = len(customers)

    # ── FINDINGS ─────────────────────────────────────────────────
    if "findings" in intent_list or "summary" in intent_list:
        q = select(Finding, Customer.name.label("cust_name")).outerjoin(
            Customer, Finding.customer_id == Customer.id
        )
        if customer_id:
            q = q.where(Finding.customer_id == customer_id)
        if severity:
            try:
                q = q.where(Finding.severity == SeverityLevel(severity))
            except ValueError:
                pass
        if ioc_type:
            q = q.where(Finding.ioc_type == ioc_type)
        q = q.order_by(Finding.created_at.desc()).limit(15)
        r = await db.execute(q)
        findings = []
        for row in r.all():
            f = row[0]  # Finding object
            cname = row[1] or ""  # Customer.name from JOIN
            findings.append({
                "id": f.id,
                "ioc_value": (f.ioc_value or "")[:80],
                "ioc_type": f.ioc_type,
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "customer_name": cname,
                "matched_asset": f.matched_asset or "",
                "actor_name": f.actor_name or "",
                "status": f.status.value if hasattr(f.status, 'value') else str(f.status),
                "ai_severity": f.ai_severity_decision or "",
            })
        results["findings"] = findings
        results["finding_count"] = len(findings)

        # Severity distribution
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            try:
                sc = await db.execute(
                    select(func.count(Finding.id)).where(Finding.severity == SeverityLevel(sev))
                )
                results[f"severity_{sev.lower()}"] = sc.scalar() or 0
            except ValueError:
                pass

    # ── EXPOSURE ─────────────────────────────────────────────────
    if "exposure" in intent_list:
        if customer_id:
            eh = await db.execute(
                select(ExposureHistory).where(ExposureHistory.customer_id == customer_id)
                .order_by(ExposureHistory.snapshot_date.desc()).limit(1)
            )
            row = eh.scalar_one_or_none()
            if row:
                results["exposure"] = {
                    "overall": row.overall_score or 0,
                    "d1_direct_exposure": row.d1_score or 0,
                    "d2_active_exploitation": row.d2_score or 0,
                    "d3_actor_intent": row.d3_score or 0,
                    "d4_attack_surface": row.d4_score or 0,
                    "d5_asset_criticality": row.d5_score or 0,
                    "snapshot_date": row.snapshot_date.isoformat() if row.snapshot_date else None,
                }
            else:
                results["exposure"] = {"note": "No exposure data yet for this customer"}
        else:
            # All customers exposure summary
            r = await db.execute(
                select(ExposureHistory).order_by(ExposureHistory.snapshot_date.desc()).limit(20)
            )
            exposures = []
            seen_customers = set()
            for row in r.scalars().all():
                if row.customer_id in seen_customers:
                    continue
                seen_customers.add(row.customer_id)
                # Get customer name
                _cr = await db.execute(select(Customer.name).where(Customer.id == row.customer_id))
                _cn = _cr.scalar_one_or_none()
                exposures.append({
                    "customer_id": row.customer_id,
                    "customer_name": _cn or f"Customer #{row.customer_id}",
                    "overall": row.overall_score or 0,
                    "d1": row.d1_score or 0, "d2": row.d2_score or 0,
                })
            results["exposures"] = exposures

    # ── ACTORS ───────────────────────────────────────────────────
    if "actors" in intent_list:
        q = select(ThreatActor)
        if actor_name:
            q = q.where(ThreatActor.name.ilike(f"%{actor_name}%"))
        q = q.limit(15)
        r = await db.execute(q)
        actors = []
        for a in r.scalars().all():
            sectors = a.target_sectors or []
            if industry and not any(industry.lower() in (s or "").lower() for s in sectors):
                continue
            actors.append({
                "name": a.name,
                "country": a.origin_country,
                "sophistication": a.sophistication,
                "target_sectors": sectors[:5],
                "mitre_id": a.mitre_id,
                "motivation": a.motivation,
                "techniques_count": len(a.techniques or []),
            })
        results["actors"] = actors

    # ── DARK WEB ─────────────────────────────────────────────────
    if "darkweb" in intent_list:
        q = select(DarkWebMention)
        if customer_id:
            q = q.where(DarkWebMention.customer_id == customer_id)
        q = q.order_by(DarkWebMention.discovered_at.desc()).limit(10)
        r = await db.execute(q)
        mentions = []
        for m in r.scalars().all():
            mentions.append({
                "id": m.id, "source": m.source,
                "content": (m.content_snippet or "")[:120],
                "threat_actor": m.threat_actor,
                "severity": m.severity.value if hasattr(m.severity, 'value') else str(m.severity),
                "triage": m.triage_classification or "",
                "discovered": m.discovered_at.isoformat() if m.discovered_at else None,
            })
        results["darkweb_mentions"] = mentions

    # ── REMEDIATIONS ─────────────────────────────────────────────
    if "remediations" in intent_list:
        q = select(FindingRemediation)
        if status:
            q = q.where(FindingRemediation.status == status)
        q = q.order_by(FindingRemediation.deadline.asc()).limit(15)
        r = await db.execute(q)
        rems = []
        for rem in r.scalars().all():
            rems.append({
                "id": rem.id, "title": (rem.title or "")[:80],
                "status": rem.status, "playbook_key": rem.playbook_key,
                "sla_hours": rem.sla_hours,
                "deadline": rem.deadline.isoformat() if rem.deadline else None,
                "ai_generated": "_ai" in (rem.playbook_key or ""),
            })
        results["remediations"] = rems

        # Status counts
        for st in ["pending", "in_progress", "completed"]:
            sc = await db.execute(
                select(func.count(FindingRemediation.id)).where(FindingRemediation.status == st)
            )
            results[f"remediation_{st}"] = sc.scalar() or 0

    return results


# ══════════════════════════════════════════════════════════════════════
# PHASE 3: LLM SUMMARIZATION
# Feed real data to LLM, ask it to write the answer. 
# Small models are GOOD at this -  it's just text synthesis.
# ══════════════════════════════════════════════════════════════════════

SUMMARIZE_PROMPT = """You are ArgusWatch AI, a cybersecurity threat intelligence analyst.
You have REAL data from the platform database below. Answer the analyst's question using ONLY this data.

RULES:
- Use specific numbers, names, and values from the data
- If the data doesn't contain the answer, say so -  do NOT make up data
- Keep answers concise (under 250 words)
- Be direct and actionable -  this is for security analysts, not executives"""


async def _summarize_results(question: str, query_results: dict, llm_call) -> str:
    """Phase 3: LLM writes a natural language answer from real data.
    
    If LLM fails, returns a formatted text summary (still useful).
    """
    # Trim results to fit in prompt (keep under ~3000 chars)
    data_str = json.dumps(query_results, default=str, indent=2)
    if len(data_str) > 3000:
        data_str = data_str[:2997] + "..."

    try:
        response = await llm_call(
            [
                {"role": "system", "content": SUMMARIZE_PROMPT},
                {"role": "user", "content": f"QUESTION: {question}\n\nPLATFORM DATA:\n{data_str}"},
            ],
            []  # NO tools
        )
        text = (response.get("text") or "").strip()
        if text and len(text) > 20:
            return text
    except Exception as e:
        logger.warning(f"[reliable_chat] Phase 3 summarization failed: {e}")

    # Fallback: structured text answer (no LLM needed)
    return _format_fallback(query_results)


def _format_fallback(results: dict) -> str:
    """If LLM summarization fails, return formatted text. Still useful."""
    parts = []

    if "customers" in results:
        count = results.get("customer_count", len(results["customers"]))
        parts.append(f"Found {count} customer(s).")
        for c in results["customers"][:5]:
            parts.append(f"  • {c['name']} ({c.get('industry','?')}) -  {c.get('finding_count',0)} findings")

    if "findings" in results:
        count = results.get("finding_count", len(results["findings"]))
        parts.append(f"\nFound {count} finding(s).")
        for f in results["findings"][:5]:
            parts.append(f"  • [{f['severity']}] {f['ioc_type']}: {f['ioc_value'][:50]} -> {f.get('customer_name','')}")

    if "exposure" in results and isinstance(results["exposure"], dict):
        e = results["exposure"]
        if "overall" in e:
            parts.append(f"\nExposure score: {e['overall']}/100")
            parts.append(f"  D1={e.get('d1_direct_exposure',0)} D2={e.get('d2_active_exploitation',0)} "
                         f"D3={e.get('d3_actor_intent',0)} D4={e.get('d4_attack_surface',0)} D5={e.get('d5_asset_criticality',0)}")

    if "actors" in results:
        parts.append(f"\nFound {len(results['actors'])} actor(s).")
        for a in results["actors"][:5]:
            parts.append(f"  • {a['name']} ({a.get('country','?')}) -  {a.get('motivation','?')}")

    if "darkweb_mentions" in results:
        parts.append(f"\nFound {len(results['darkweb_mentions'])} dark web mention(s).")
        for m in results["darkweb_mentions"][:3]:
            parts.append(f"  • [{m['severity']}] {m['source']}: {m['content'][:60]}")

    if "remediations" in results:
        pending = results.get("remediation_pending", 0)
        in_prog = results.get("remediation_in_progress", 0)
        done = results.get("remediation_completed", 0)
        parts.append(f"\nRemediations: {pending} pending, {in_prog} in progress, {done} completed")

    return "\n".join(parts) if parts else "No data found matching your query."


# ══════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

async def reliable_chat(question: str, db: AsyncSession, provider: str = "ollama") -> dict:
    """Two-phase reliable chat: classify -> query -> summarize.
    
    Works with ANY LLM, including small local models that can't do tool-calling.
    Falls back gracefully at every phase -  worst case returns raw DB data.
    """
    from arguswatch.services.ai_pipeline_hooks import _provider as _get_provider

    if not provider or provider == "auto":
        provider = _get_provider()

    # Get the right LLM caller (no tools needed -  just text completion)
    if provider == "anthropic":
        from arguswatch.agent.agent_core import _call_anthropic as llm_call
    elif provider == "openai":
        from arguswatch.agent.agent_core import _call_openai as llm_call
    elif provider == "google":
        from arguswatch.agent.agent_core import _call_google as llm_call
    else:
        from arguswatch.agent.agent_core import _call_ollama as llm_call

    # ── Phase 1: Classify intent ─────────────────────────────────
    intents = await _classify_intent(question, llm_call)

    # ── Phase 2: Execute queries (deterministic, no LLM) ─────────
    query_results = await _execute_queries(intents, db)

    # ── Phase 3: Summarize with LLM ──────────────────────────────
    answer = await _summarize_results(question, query_results, llm_call)

    return {
        "answer": answer,
        "intents": intents.get("intents", []),
        "data": query_results,
        "provider": provider,
        "model": getattr(
            __import__("arguswatch.config", fromlist=["settings"]).settings,
            "OLLAMA_MODEL", ""
        ) if provider == "ollama" else provider,
        "method": "reliable_two_phase",
        "phases": {
            "classify": "llm" if intents.get("intents") != ["summary"] else "fallback",
            "query": "deterministic",
            "summarize": "llm" if len(answer) > 50 else "fallback",
        },
    }
