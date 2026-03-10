"""
Sector Campaign Detector - Cross-Customer Threat Correlation
==============================================================
WHAT: Looks across ALL customers for shared IOCs in the past 48 hours.
      When same IOC hits 2+ customers, AI analyzes whether it's a
      coordinated campaign and generates a sector advisory.

WHY:  The entire system is currently per-customer. Zero cross-customer
      visibility. For an MSSP, cross-customer patterns are THE most
      valuable intelligence: "3 healthcare customers hit by the same IP
      in 48 hours" = coordinated sector attack.

TRIGGERED BY: Celery beat task every 6 hours
STORES TO:    SectorAdvisory table
"""

import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, func, and_, text
from sqlalchemy.ext.asyncio import AsyncSession

from arguswatch.models import (
    Finding, Customer, SectorAdvisory, SeverityLevel,
)
from arguswatch.services.ai_pipeline_hooks import _llm_json, _pipeline_ai_available

logger = logging.getLogger("arguswatch.agent.sector_detection")


async def detect_sector_campaigns(db: AsyncSession, hours: int = 48) -> dict:
    """Scan for IOCs that hit multiple customers in the past N hours.

    Steps:
    1. GROUP BY (ioc_value, ioc_type) WHERE COUNT(DISTINCT customer_id) >= 2
    2. For each cluster, gather customer names/industries
    3. AI classifies: coordinated_campaign | shared_infra | mass_exploitation | sector_targeting
    4. Create SectorAdvisory with narrative + recommended actions

    Returns stats dict.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    stats = {"clusters_found": 0, "advisories_created": 0, "already_exists": 0}

    # Find IOCs hitting 2+ customers in window
    cluster_query = (
        select(
            Finding.ioc_value,
            Finding.ioc_type,
            func.count(func.distinct(Finding.customer_id)).label("customer_count"),
        )
        .where(
            and_(
                Finding.customer_id.isnot(None),
                Finding.created_at >= cutoff,
                Finding.status != "FALSE_POSITIVE",
            )
        )
        .group_by(Finding.ioc_value, Finding.ioc_type)
        .having(func.count(func.distinct(Finding.customer_id)) >= 2)
        .order_by(func.count(func.distinct(Finding.customer_id)).desc())
        .limit(20)
    )

    r = await db.execute(cluster_query)
    clusters = r.all()

    if not clusters:
        logger.info("[sector] No cross-customer IOC clusters found")
        return stats

    stats["clusters_found"] = len(clusters)

    for ioc_value, ioc_type, customer_count in clusters:
        # Check if advisory already exists for this IOC in recent window
        existing = await db.execute(
            select(SectorAdvisory).where(
                SectorAdvisory.ioc_value == ioc_value,
                SectorAdvisory.created_at >= cutoff,
            ).limit(1)
        )
        if existing.scalar_one_or_none():
            stats["already_exists"] += 1
            continue

        # Gather affected customers
        affected_r = await db.execute(
            select(
                Finding.customer_id,
                Customer.name,
                Customer.industry,
            )
            .join(Customer, Finding.customer_id == Customer.id)
            .where(
                Finding.ioc_value == ioc_value,
                Finding.ioc_type == ioc_type,
                Finding.created_at >= cutoff,
            ).distinct()
        )
        affected = affected_r.all()

        customer_ids = [a[0] for a in affected]
        customer_names = [a[1] for a in affected if a[1]]
        industries = list({a[2] for a in affected if a[2]})

        # Get source feeds (all_sources is JSON, not ARRAY - use json_array_elements_text)
        try:
            source_r = await db.execute(
                text("""
                    SELECT DISTINCT val FROM (
                        SELECT json_array_elements_text(all_sources) AS val
                        FROM findings
                        WHERE ioc_value = :ioc AND ioc_type = :itype
                          AND created_at >= :cutoff
                    ) sub LIMIT 10
                """),
                {"ioc": ioc_value, "itype": ioc_type, "cutoff": cutoff},
            )
            sources = [s[0] for s in source_r.all() if s[0]]
        except Exception:
            sources = []

        # AI classification
        classification = "mass_exploitation"  # default
        narrative = (
            f"IOC {ioc_value[:50]} ({ioc_type}) detected across "
            f"{customer_count} customers in {', '.join(industries) or 'multiple'} sectors."
        )
        recommended_actions = [f"Block {ioc_value[:80]} across all customer environments"]

        if _pipeline_ai_available():
            try:
                prompt = f"""You are an MSSP threat analyst examining a cross-customer pattern.

The following IOC appeared across multiple customers in {hours} hours:
- IOC: {ioc_value}
- Type: {ioc_type}
- Customer count: {customer_count}
- Industries affected: {', '.join(industries) or 'mixed'}
- Source feeds: {', '.join(sources[:5]) or 'unknown'}

Affected customers (names redacted for advisory): {len(customer_names)} organizations

Classify this pattern:
- coordinated_campaign: Same threat actor targeting multiple orgs deliberately
- shared_infra: IOC is shared infrastructure (CDN, VPN, scanning) - likely FP
- mass_exploitation: Automated mass exploitation (Shodan-driven, worm-like)
- sector_targeting: Deliberate targeting of a specific industry sector

Respond with valid JSON:
{{"classification": "<type>", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "narrative": "<3-sentence sector advisory>", "recommended_actions": ["action1", "action2"], "confidence": <0.0-1.0>}}"""

                result = await _llm_json(
                    "You are an MSSP sector threat analyst. Analyze cross-customer IOC patterns.",
                    prompt,
                )
                classification = result.get("classification", classification)
                narrative = result.get("narrative", narrative)
                recommended_actions = result.get("recommended_actions", recommended_actions)
                sev_str = result.get("severity", "HIGH")
            except Exception as e:
                logger.debug(f"[sector] AI classification failed: {e}")
                sev_str = "HIGH"
        else:
            sev_str = "HIGH"

        try:
            severity = SeverityLevel(sev_str)
        except ValueError:
            severity = SeverityLevel.HIGH

        advisory = SectorAdvisory(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            affected_customer_count=customer_count,
            affected_industries=industries,
            affected_customer_ids=customer_ids,
            severity=severity,
            classification=classification,
            ai_narrative=narrative,
            ai_recommended_actions=recommended_actions,
            window_start=cutoff,
            window_end=datetime.utcnow(),
        )
        db.add(advisory)
        await db.flush()
        stats["advisories_created"] += 1

        logger.warning(
            f"[sector] ADVISORY: {ioc_value[:50]} ({ioc_type}) -> "
            f"{customer_count} customers | {classification} | {severity.value}"
        )

    return stats
