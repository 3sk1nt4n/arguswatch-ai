"""
Exposure Narrative Agent - Turns Numbers Into Actions
=======================================================
WHAT: Takes the full factor_breakdown dict from score_customer_actor()
      and produces a 3-paragraph executive narrative:
      1. WHAT CHANGED (score delta + driver)
      2. TOP DRIVER (specific evidence from factors)
      3. IMMEDIATE ACTION (concrete steps with timeframes)

WHY:  A score of 67 HIGH means nothing to a CISO.
      "Your CEO's plaintext credential was found in an active stealer log
      - force password reset within 4 hours" drives action.

WHEN: Called after recalculate_all_exposures() completes.
      Stores narrative in CustomerExposure.score_narrative.
"""

import logging
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from arguswatch.models import CustomerExposure, Customer, ThreatActor

logger = logging.getLogger("arguswatch.agent.exposure_narrative")


async def generate_exposure_narrative(customer_id: int, db: AsyncSession) -> str | None:
    """Generate AI narrative for customer's top exposure.
    Returns narrative string or None if AI unavailable.
    """
    from arguswatch.services.ai_pipeline_hooks import _pipeline_ai_available, _llm_text

    if not _pipeline_ai_available():
        return None

    # Get top exposure with full factor breakdown
    r = await db.execute(
        select(CustomerExposure, ThreatActor, Customer)
        .join(ThreatActor, CustomerExposure.actor_id == ThreatActor.id)
        .join(Customer, CustomerExposure.customer_id == Customer.id)
        .where(CustomerExposure.customer_id == customer_id)
        .order_by(CustomerExposure.exposure_score.desc()).limit(1)
    )
    row = r.one_or_none()
    if not row:
        return None

    exp, actor, customer = row.CustomerExposure, row.ThreatActor, row.Customer
    factors = exp.factor_breakdown or {}
    score = exp.exposure_score or 0

    # Build factor summary for AI
    factor_lines = []
    for key, val in factors.items():
        if isinstance(val, dict):
            pts = val.get("pts", val.get("points", 0))
            detail = val.get("label", val.get("detail", ""))
            if pts > 0:
                factor_lines.append(f"  {key}: +{pts} pts - {detail}")

    factor_text = "\n".join(factor_lines) if factor_lines else "  No significant factors"

    # Get previous score for delta (from exposure history)
    prev_score = 0
    try:
        from arguswatch.models import ExposureHistory
        prev_r = await db.execute(
            select(ExposureHistory.overall_score)
            .where(ExposureHistory.customer_id == customer_id)
            .order_by(ExposureHistory.snapshot_date.desc())
            .offset(1).limit(1)
        )
        prev = prev_r.scalar()
        if prev is not None:
            prev_score = prev
    except Exception:
        pass

    delta = score - prev_score
    delta_str = f"+{delta:.0f}" if delta > 0 else f"{delta:.0f}" if delta < 0 else "unchanged"

    prompt = f"""You are a cybersecurity executive advisor writing for a CISO audience.
Write a 3-paragraph narrative about this customer's exposure score.

Customer: {customer.name}
Industry: {customer.industry or "unknown"}
Current score: {score:.0f}/100 ({_label(score)})
Previous score: {prev_score:.0f}/100 (change: {delta_str})
Top threat actor: {actor.name} (MITRE: {actor.mitre_id or "N/A"})
Sector match: {"YES - actor actively targets this industry" if exp.sector_match else "No direct sector targeting"}

Score breakdown:
{factor_text}

Write exactly 3 paragraphs:
1. WHAT CHANGED - Score movement and primary driver in one sentence.
2. TOP DRIVER - The single most important factor with specific evidence (cite IOC counts, actor names, CVE IDs if present in factors). Explain WHY this matters to this specific industry.
3. IMMEDIATE ACTION - 2-3 concrete steps with specific timeframes (e.g., "within 4 hours", "this weekend", "by next Tuesday"). Be specific, not generic.

Keep it under 200 words total. No headers. No bullet points. Write as prose.
Do NOT say "I recommend" - write as if you ARE the security system reporting to the CISO."""

    try:
        narrative = await _llm_text(
            "You are a cybersecurity executive advisor. Write concise, actionable prose.",
            prompt,
        )
        if narrative and len(narrative) > 50:
            # Store on the exposure record
            exp.score_narrative = narrative
            await db.flush()
            logger.info(f"[exposure_narrative] Generated for {customer.name}: "
                         f"{score:.0f}/100 ({len(narrative)} chars)")
            return narrative
    except Exception as e:
        logger.warning(f"[exposure_narrative] Failed for {customer.name}: {e}")

    return None


async def generate_all_narratives(db: AsyncSession) -> dict:
    """Generate narratives for all active customers. Called after recalculate_all_exposures."""
    r = await db.execute(select(Customer.id).where(Customer.active == True))
    customer_ids = [row[0] for row in r.all()]

    stats = {"generated": 0, "failed": 0, "skipped": 0}
    for cid in customer_ids:
        try:
            result = await generate_exposure_narrative(cid, db)
            if result:
                stats["generated"] += 1
            else:
                stats["skipped"] += 1
        except Exception as e:
            stats["failed"] += 1
            logger.debug(f"[exposure_narrative] Skip {cid}: {e}")

    await db.commit()
    logger.info(f"[exposure_narrative] All: {stats}")
    return stats


def _label(score):
    if score >= 76: return "CRITICAL"
    if score >= 51: return "HIGH"
    if score >= 26: return "MEDIUM"
    if score > 0: return "LOW"
    return "NONE"
