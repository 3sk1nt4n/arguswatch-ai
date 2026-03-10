"""
Chat Agent Tools -  query tools for the AI chat agent.

Unlike the orchestrator's 9 tools (which operate on single detections),
these tools query the database to answer analyst questions.

The AI autonomously picks which tools to call based on the user's question.
"""
import json
import logging
from datetime import datetime

logger = logging.getLogger("arguswatch.agent.chat_tools")

# These get populated at runtime with a db session
_db = None

def set_db(db_session):
    global _db
    _db = db_session


async def tool_search_customers(name: str = "", industry: str = "", limit: int = 10) -> dict:
    """Search customers by name or industry. Returns customer list with finding counts."""
    from arguswatch.models import Customer, Finding
    from sqlalchemy import select, func
    q = select(Customer).where(Customer.active == True)
    if name:
        q = q.where(Customer.name.ilike(f"%{name}%"))
    if industry:
        q = q.where(Customer.industry == industry.lower())
    q = q.limit(min(limit, 20))
    r = await _db.execute(q)
    results = []
    for c in r.scalars().all():
        fc = await _db.execute(select(func.count(Finding.id)).where(Finding.customer_id == c.id))
        results.append({
            "id": c.id, "name": c.name, "industry": c.industry,
            "tier": c.tier, "finding_count": fc.scalar() or 0,
        })
    return {"customers": results, "count": len(results)}


async def tool_search_findings(customer_name: str = "", severity: str = "", ioc_type: str = "", limit: int = 10) -> dict:
    """Search findings by customer, severity, or IOC type."""
    from arguswatch.models import Finding, Customer
    from sqlalchemy import select
    q = select(Finding, Customer.name.label("cust_name")).outerjoin(
        Customer, Finding.customer_id == Customer.id
    )
    if customer_name:
        cq = await _db.execute(select(Customer.id).where(Customer.name.ilike(f"%{customer_name}%")))
        cids = [r[0] for r in cq.all()]
        if cids:
            q = q.where(Finding.customer_id.in_(cids))
    if severity:
        q = q.where(Finding.severity == severity.upper())
    if ioc_type:
        q = q.where(Finding.ioc_type == ioc_type)
    q = q.order_by(Finding.created_at.desc()).limit(min(limit, 20))
    r = await _db.execute(q)
    findings_list = []
    for row in r.all():
        f = row[0]  # Finding object
        cname = row[1] or ""  # Customer.name from JOIN
        findings_list.append({
            "id": f.id, "ioc_value": (f.ioc_value or "")[:80], "ioc_type": f.ioc_type,
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "customer_id": f.customer_id, "customer_name": cname,
            "ai_severity": f.ai_severity_decision, "matched_asset": f.matched_asset,
        })
    return {"findings": findings_list}


async def tool_check_exposure(customer_name: str = "", customer_id: int = 0) -> dict:
    """Get exposure score breakdown (D1-D5) for a customer."""
    from arguswatch.models import Customer, ExposureHistory
    from sqlalchemy import select
    if customer_name and not customer_id:
        cr = await _db.execute(select(Customer).where(Customer.name.ilike(f"%{customer_name}%")).limit(1))
        c = cr.scalar_one_or_none()
        if c: customer_id = c.id
    if not customer_id:
        return {"error": "Customer not found"}
    eh = await _db.execute(
        select(ExposureHistory).where(ExposureHistory.customer_id == customer_id)
        .order_by(ExposureHistory.snapshot_date.desc()).limit(1)
    )
    row = eh.scalar_one_or_none()
    if not row:
        return {"customer_id": customer_id, "overall_score": 0, "note": "No exposure data yet"}
    return {
        "customer_id": customer_id, "overall_score": row.overall_score or 0,
        "d1_direct_exposure": row.d1_score or 0, "d2_active_exploitation": row.d2_score or 0,
        "d3_actor_intent": row.d3_score or 0, "d4_attack_surface": row.d4_score or 0,
        "d5_asset_criticality": row.d5_score or 0,
    }


async def tool_search_actors(name: str = "", target_sector: str = "", country: str = "", limit: int = 10) -> dict:
    """Search threat actors by name, target sector, or country."""
    from arguswatch.models import ThreatActor
    from sqlalchemy import select
    q = select(ThreatActor)
    if name:
        q = q.where(ThreatActor.name.ilike(f"%{name}%"))
    if country:
        q = q.where(ThreatActor.origin_country.ilike(f"%{country}%"))
    q = q.limit(min(limit, 20))
    r = await _db.execute(q)
    actors = []
    for a in r.scalars().all():
        sectors = a.target_sectors or []
        if target_sector and not any(target_sector.lower() in (s or "").lower() for s in sectors):
            continue
        actors.append({
            "name": a.name, "country": a.origin_country, "sophistication": a.sophistication,
            "target_sectors": sectors[:5], "mitre_id": a.mitre_id,
            "techniques_count": len(a.techniques or []),
        })
    return {"actors": actors[:10], "count": len(actors)}


async def tool_search_darkweb(customer_name: str = "", source: str = "", limit: int = 10) -> dict:
    """Search dark web mentions by customer or source."""
    from arguswatch.models import DarkWebMention, Customer as _Cust
    from sqlalchemy import select
    q = select(DarkWebMention)
    if customer_name:
        # Resolve customer_id from name since DarkWebMention only has customer_id
        _cr = await _db.execute(select(_Cust.id).where(_Cust.name.ilike(f"%{customer_name}%")))
        _cids = [r[0] for r in _cr.all()]
        if _cids:
            q = q.where(DarkWebMention.customer_id.in_(_cids))
    if source:
        q = q.where(DarkWebMention.source == source)
    q = q.order_by(DarkWebMention.discovered_at.desc()).limit(min(limit, 15))
    r = await _db.execute(q)
    return {"mentions": [
        {"id": m.id, "source": m.source, "content": (m.content_snippet or "")[:100],
         "customer_id": m.customer_id, "threat_actor": m.threat_actor,
         "severity": m.severity.value if hasattr(m.severity, 'value') else str(m.severity),
         "ai_summary": (m.triage_narrative or "")[:100]}
        for m in r.scalars().all()
    ]}


async def tool_search_remediations(customer_name: str = "", status: str = "", limit: int = 10) -> dict:
    """Search remediation actions by customer or status."""
    from arguswatch.models import FindingRemediation
    from sqlalchemy import select
    q = select(FindingRemediation)
    if status:
        q = q.where(FindingRemediation.status == status)
    q = q.order_by(FindingRemediation.deadline.asc()).limit(min(limit, 15))
    r = await _db.execute(q)
    return {"remediations": [
        {"id": rem.id, "title": (rem.title or "")[:80], "status": rem.status,
         "playbook_key": rem.playbook_key, "sla_hours": rem.sla_hours,
         "deadline": rem.deadline.isoformat() if rem.deadline else None,
         "ai_generated": "_ai" in (rem.playbook_key or "")}
        for rem in r.scalars().all()
    ]}


# Tool registry
CHAT_TOOLS = {
    "search_customers": tool_search_customers,
    "search_findings": tool_search_findings,
    "check_exposure": tool_check_exposure,
    "search_actors": tool_search_actors,
    "search_darkweb": tool_search_darkweb,
    "search_remediations": tool_search_remediations,
}

CHAT_TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "search_customers", "description": "Search customers by name or industry. Returns finding counts.",
        "parameters": {"type": "object", "properties": {
            "name": {"type": "string", "description": "Customer name (partial match)"},
            "industry": {"type": "string", "description": "Filter by industry"},
            "limit": {"type": "integer", "description": "Max results (default 10)"},
        }},
    }},
    {"type": "function", "function": {
        "name": "search_findings", "description": "Search threat findings by customer, severity, or IOC type.",
        "parameters": {"type": "object", "properties": {
            "customer_name": {"type": "string"}, "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
            "ioc_type": {"type": "string"}, "limit": {"type": "integer"},
        }},
    }},
    {"type": "function", "function": {
        "name": "check_exposure", "description": "Get D1-D5 exposure score breakdown for a customer.",
        "parameters": {"type": "object", "properties": {
            "customer_name": {"type": "string"}, "customer_id": {"type": "integer"},
        }},
    }},
    {"type": "function", "function": {
        "name": "search_actors", "description": "Search threat actors by name, target sector, or country of origin.",
        "parameters": {"type": "object", "properties": {
            "name": {"type": "string"}, "target_sector": {"type": "string"}, "country": {"type": "string"},
            "limit": {"type": "integer"},
        }},
    }},
    {"type": "function", "function": {
        "name": "search_darkweb", "description": "Search dark web mentions (ransomware, pastes, leaks) by customer.",
        "parameters": {"type": "object", "properties": {
            "customer_name": {"type": "string"}, "source": {"type": "string"}, "limit": {"type": "integer"},
        }},
    }},
    {"type": "function", "function": {
        "name": "search_remediations", "description": "Search remediation actions by status (pending/in_progress/completed).",
        "parameters": {"type": "object", "properties": {
            "customer_name": {"type": "string"}, "status": {"type": "string", "enum": ["pending", "in_progress", "completed"]},
            "limit": {"type": "integer"},
        }},
    }},
]
