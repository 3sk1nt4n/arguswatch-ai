"""
ArgusWatch RAG Context V13 - lightweight semantic retrieval without a vector database.

TRUE RAG requires: ChromaDB/pgvector + embedding model + indexing pipeline.
This module provides the next best thing using existing PostgreSQL data:

  find_related_findings()   - SQL-based "semantic" retrieval using:
    - Same actor matches
    - Same customer + similar IOC type in last 90 days
    - Same source feed + same IOC type
    - CVE findings in same product family
    - Campaign co-membership

  build_rag_context()       - formats retrieved findings into LLM-ready context string
    - Used by agent tools and pipeline hooks to give LLM historical context
    - Keeps context under 2000 chars to avoid prompt bloat

  get_actor_intelligence()  - pull full actor profile from DB for attribution context
    - Techniques, target sectors, origin country, MITRE ID, known IOCs

When pgvector is available (future), swap find_related_findings() for vector similarity.
"""
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from arguswatch.models import (
    Finding, ThreatActor, ActorIoc, Detection, Campaign,
    DetectionStatus, SeverityLevel
)
from datetime import datetime, timedelta

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


logger = logging.getLogger("arguswatch.rag")


async def find_related_findings(
    ioc_value: str,
    ioc_type: str,
    customer_id: int | None,
    actor_name: str | None,
    finding_id: int | None,
    db: AsyncSession,
    limit: int = 8,
) -> list[dict]:
    """
    Retrieve contextually related findings from DB.
    No vector similarity - uses SQL relevance signals.
    Returns findings ordered by relevance score (most relevant first).
    """
    ninety_days_ago = datetime.utcnow() - timedelta(days=90)
    results = {}  # finding_id → {finding, score}

    def _add(f, score_boost: float, reason: str):
        if f.id == finding_id:
            return  # don't include self
        if f.id not in results:
            results[f.id] = {"finding": f, "score": 0.0, "reasons": []}
        results[f.id]["score"] += score_boost
        results[f.id]["reasons"].append(reason)

    # Signal 1: same actor (strongest signal - 3.0)
    if actor_name:
        r = await db.execute(
            select(Finding).where(
                and_(
                    Finding.actor_name == actor_name,
                    Finding.created_at >= ninety_days_ago,
                    Finding.status != DetectionStatus.FALSE_POSITIVE,
                )
            ).order_by(Finding.created_at.desc()).limit(5)
        )
        for f in r.scalars().all():
            _add(f, 3.0, f"same_actor:{actor_name}")

    # Signal 2: same customer + same IOC type (2.0)
    if customer_id:
        r = await db.execute(
            select(Finding).where(
                and_(
                    Finding.customer_id == customer_id,
                    Finding.ioc_type == ioc_type,
                    Finding.created_at >= ninety_days_ago,
                    Finding.status != DetectionStatus.FALSE_POSITIVE,
                )
            ).order_by(Finding.created_at.desc()).limit(5)
        )
        for f in r.scalars().all():
            _add(f, 2.0, "same_customer_ioc_type")

    # Signal 3: same ioc_value (exact IOC match - very strong, 5.0)
    r = await db.execute(
        select(Finding).where(
            and_(
                Finding.ioc_value == ioc_value,
                Finding.status != DetectionStatus.FALSE_POSITIVE,
            )
        ).order_by(Finding.created_at.desc()).limit(3)
    )
    for f in r.scalars().all():
        _add(f, 5.0, "same_ioc_value")

    # Signal 4: CVE in same product family (for CVE IOC types)
    if ioc_type == "cve_id" and "-" in ioc_value:
        # Match CVE-YEAR- prefix
        cve_prefix = "-".join(ioc_value.upper().split("-")[:2]) + "-"
        r = await db.execute(
            select(Finding).where(
                and_(
                    Finding.ioc_type == "cve_id",
                    Finding.ioc_value.like(cve_prefix + "%"),
                    Finding.created_at >= ninety_days_ago,
                )
            ).order_by(Finding.created_at.desc()).limit(4)
        )
        for f in r.scalars().all():
            _add(f, 1.5, f"same_cve_year:{cve_prefix}")

    # Sort by score, take top N
    sorted_results = sorted(results.values(), key=lambda x: x["score"], reverse=True)[:limit]
    return [
        {
            "finding_id": item["finding"].id,
            "ioc_value": item["finding"].ioc_value,
            "ioc_type": item["finding"].ioc_type,
            "severity": _sev(item["finding"].severity),
            "actor_name": item["finding"].actor_name,
            "status": item["finding"].status.value if item["finding"].status else None,
            "first_seen": item["finding"].first_seen.isoformat() if item["finding"].first_seen else None,
            "relevance_score": round(item["score"], 1),
            "relevance_reasons": item["reasons"],
            "ai_narrative": (getattr(item["finding"], "ai_narrative", None) or "")[:200],
        }
        for item in sorted_results
    ]


async def get_actor_intelligence(actor_name: str, db: AsyncSession) -> dict:
    """Pull full actor profile + recent IOCs for LLM context."""
    r = await db.execute(
        select(ThreatActor).where(ThreatActor.name == actor_name).limit(1)
    )
    actor = r.scalar_one_or_none()
    if not actor:
        return {"name": actor_name, "found": False}

    # Recent known IOCs
    ri = await db.execute(
        select(ActorIoc).where(ActorIoc.actor_name == actor_name).limit(10)
    )
    iocs = [{"type": i.ioc_type, "value": i.ioc_value[:50]} for i in ri.scalars().all()]

    return {
        "name": actor.name,
        "found": True,
        "mitre_id": actor.mitre_id,
        "origin_country": actor.origin_country,
        "motivation": actor.motivation,
        "sophistication": actor.sophistication,
        "target_sectors": actor.target_sectors or [],
        "target_countries": actor.target_countries or [],
        "techniques": (actor.techniques or [])[:8],
        "recent_iocs": iocs,
        "description": (actor.description or "")[:300],
    }


async def build_rag_context(
    ioc_value: str,
    ioc_type: str,
    customer_id: int | None,
    actor_name: str | None,
    finding_id: int | None,
    db: AsyncSession,
    include_actor_intel: bool = True,
) -> str:
    """
    Build LLM-ready context string from DB retrieval.
    Kept under 2000 chars to avoid bloating prompts.
    
    This is the RAG retrieval step - instead of vector similarity,
    we use SQL relevance signals to find related historical findings.
    """
    parts = []

    # Related findings
    related = await find_related_findings(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        customer_id=customer_id,
        actor_name=actor_name,
        finding_id=finding_id,
        db=db,
        limit=5,
    )

    if related:
        parts.append("RELATED HISTORICAL FINDINGS:")
        for f in related[:4]:
            line = (
                f"  • Finding #{f['finding_id']}: {f['ioc_type']} {f['ioc_value'][:30]} "
                f"→ {f['severity']} | actor={f['actor_name'] or 'unknown'} "
                f"| {f['status']} | seen={f['first_seen'][:10] if f['first_seen'] else '?'}"
            )
            if f.get("ai_narrative"):
                line += f"\n    Summary: {f['ai_narrative'][:100]}"
            parts.append(line)

    # Actor intelligence
    if include_actor_intel and actor_name:
        actor = await get_actor_intelligence(actor_name, db)
        if actor.get("found"):
            parts.append(f"\nACTOR INTELLIGENCE: {actor['name']} ({actor.get('mitre_id', '?')})")
            parts.append(f"  Origin: {actor.get('origin_country', '?')} | Motivation: {actor.get('motivation', '?')}")
            if actor.get("target_sectors"):
                parts.append(f"  Targets: {', '.join(str(s) for s in actor['target_sectors'][:4])}")
            if actor.get("techniques"):
                parts.append(f"  Techniques: {', '.join(str(t) for t in actor['techniques'][:4])}")

    context = "\n".join(parts)
    # Hard cap
    if len(context) > 2000:
        context = context[:1997] + "..."
    return context
