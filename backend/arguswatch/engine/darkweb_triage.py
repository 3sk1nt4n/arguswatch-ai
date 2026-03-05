"""
Dark Web Triage Agent - Autonomous Classification & Action
============================================================
WHAT: When a DarkWebMention with customer_id is inserted, this agent:
      1. Reads full title/metadata
      2. AI classifies: extortion | data_leak | credential_sale | noise
      3. For critical types, auto-creates a CRITICAL Finding with playbook
      4. For noise, flags so it doesn't clutter dashboard

WHY:  insert_darkweb() currently does a plain INSERT and nothing else.
      The Dark Web tab is a dead list. No workflow triggers. No alerts.
      This agent makes dark web mentions actionable.

TRIGGERED BY: Celery task after DarkWebMention insert with customer_id
"""

import logging
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from arguswatch.services.ai_pipeline_hooks import _llm_json, _pipeline_ai_available

logger = logging.getLogger("arguswatch.agent.darkweb_triage")

CLASSIFICATION_TYPES = {
    "pre_encryption_extortion",     # Ransomware group posted BEFORE encryption - urgent
    "post_encryption_data_leak",    # Data already leaked - damage done, need IR
    "data_auction",                 # Data being auctioned - time-sensitive
    "sector_campaign",              # Part of broader sector targeting
    "credential_sale",              # Credentials for sale on darknet
    "likely_noise",                 # False positive, name collision, or irrelevant
}


async def triage_darkweb_mention(mention_id: int, db: AsyncSession) -> dict:
    """Triage a single DarkWebMention - classify and take action.

    Returns: {classification, action, narrative, finding_id?}
    """
    from arguswatch.models import DarkWebMention, Customer, Finding, SeverityLevel, DetectionStatus

    r = await db.execute(select(DarkWebMention).where(DarkWebMention.id == mention_id))
    mention = r.scalar_one_or_none()
    if not mention:
        return {"error": "mention not found"}

    if mention.triaged_at:
        return {"action": "already_triaged", "classification": mention.triage_classification}

    if not mention.customer_id:
        return {"action": "skipped", "reason": "no customer_id"}

    # Get customer context
    cr = await db.execute(select(Customer).where(Customer.id == mention.customer_id))
    customer = cr.scalar_one_or_none()
    cust_name = customer.name if customer else "Unknown"
    cust_industry = customer.industry if customer else "unknown"

    # Build AI prompt
    metadata = mention.metadata_ or {}

    if not _pipeline_ai_available():
        # Rule-based fallback
        classification = "post_encryption_data_leak" if "ransomware" in (mention.mention_type or "").lower() else "credential_sale"
        mention.triage_classification = classification
        mention.triage_action = "create_finding"
        mention.triage_narrative = f"[Rule-based] Dark web mention classified as {classification} (no AI available)"
        mention.triaged_at = datetime.utcnow()
        await db.flush()
        return {"classification": classification, "action": "create_finding", "method": "rules"}

    prompt = f"""You are a dark web analyst triaging a mention for an MSSP customer.

Customer: {cust_name}
Industry: {cust_industry}
Source: {mention.source}
Mention Type: {mention.mention_type}
Title: {mention.title}
Threat Actor: {mention.threat_actor or "Unknown"}
Content snippet: {(mention.content_snippet or "")[:500]}
Metadata: {str(metadata)[:300]}

Classify this mention into exactly ONE of:
- pre_encryption_extortion: Ransomware group posted BEFORE encrypting. Customer may have 24-48 hours.
- post_encryption_data_leak: Data already leaked on dark web. Damage done. Need forensics.
- data_auction: Customer data is being auctioned. Time-sensitive - bidders active.
- sector_campaign: Part of a broader sector targeting (not customer-specific).
- credential_sale: Customer credentials being sold on darknet.
- likely_noise: Name collision, irrelevant mention, or spam.

Also determine the action:
- create_finding: Create a CRITICAL finding with investigation playbook
- notify_customer: Alert customer but don't create finding
- flag_noise: Mark as noise, hide from dashboard
- escalate_ir: Escalate to incident response team immediately

Respond ONLY with valid JSON:
{{"classification": "<type>", "action": "<action>", "urgency_hours": <int>, "narrative": "<2-3 sentence analyst brief explaining what this means and what to do>"}}"""

    try:
        result = await _llm_json(
            "You are a dark web threat analyst. Classify mentions and recommend actions. Respond ONLY with valid JSON.",
            prompt,
        )

        classification = result.get("classification", "likely_noise")
        if classification not in CLASSIFICATION_TYPES:
            classification = "likely_noise"
        action = result.get("action", "notify_customer")
        narrative = result.get("narrative", "")
        urgency = result.get("urgency_hours", 24)

        # Store triage results
        mention.triage_classification = classification
        mention.triage_action = action
        mention.triage_narrative = narrative
        mention.triaged_at = datetime.utcnow()

        response = {
            "classification": classification,
            "action": action,
            "narrative": narrative,
            "urgency_hours": urgency,
        }

        # Auto-create Finding for critical classifications
        if action in ("create_finding", "escalate_ir"):
            severity = SeverityLevel.CRITICAL if classification in (
                "pre_encryption_extortion", "data_auction"
            ) else SeverityLevel.HIGH

            sla = min(urgency, 4) if severity == SeverityLevel.CRITICAL else min(urgency, 24)

            # Check if finding already exists for this IOC
            existing = await db.execute(
                select(Finding).where(
                    Finding.ioc_value == (mention.title or "")[:200],
                    Finding.customer_id == mention.customer_id,
                    Finding.ioc_type == "dark_web_mention",
                ).limit(1)
            )
            if not existing.scalar_one_or_none():
                finding = Finding(
                    ioc_value=(mention.title or "")[:200],
                    ioc_type="dark_web_mention",
                    customer_id=mention.customer_id,
                    severity=severity,
                    status=DetectionStatus.NEW,
                    sla_hours=sla,
                    source_count=1,
                    all_sources=[mention.source],
                    confidence=0.85,
                    actor_name=mention.threat_actor,
                    ai_severity_decision=severity.value,
                    ai_severity_reasoning=f"Dark web triage: {classification}",
                    ai_narrative=narrative,
                    ai_enriched_at=datetime.utcnow(),
                )
                db.add(finding)
                await db.flush()
                response["finding_id"] = finding.id
                logger.info(
                    f"[darkweb_triage] Created {severity.value} finding#{finding.id} "
                    f"for {cust_name}: {classification}"
                )

        await db.flush()
        logger.info(f"[darkweb_triage] mention#{mention_id} → {classification}/{action}")
        return response

    except Exception as e:
        logger.warning(f"[darkweb_triage] Failed for mention#{mention_id}: {e}")
        return {"error": str(e)[:200]}


async def triage_untriaged_mentions(db: AsyncSession, limit: int = 50) -> dict:
    """Batch triage all untriaged DarkWebMentions with customer_id."""
    from arguswatch.models import DarkWebMention

    r = await db.execute(
        select(DarkWebMention).where(
            DarkWebMention.customer_id.isnot(None),
            DarkWebMention.triaged_at.is_(None),
        ).order_by(DarkWebMention.discovered_at.desc()).limit(limit)
    )
    mentions = r.scalars().all()

    stats = {"total": len(mentions), "triaged": 0, "findings_created": 0, "noise": 0, "errors": 0}

    for mention in mentions:
        result = await triage_darkweb_mention(mention.id, db)
        if "error" in result:
            stats["errors"] += 1
        else:
            stats["triaged"] += 1
            if result.get("finding_id"):
                stats["findings_created"] += 1
            if result.get("classification") == "likely_noise":
                stats["noise"] += 1

    await db.flush()
    logger.info(f"[darkweb_triage] Batch: {stats}")
    return stats
