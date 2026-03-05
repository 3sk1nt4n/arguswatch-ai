"""
Finding Manager - merge raw detections into deduplicated findings.

The core idea:
  Detection  = raw IOC row from a single collector. Many per IOC.
  Finding    = the analyst-facing record. One per (ioc_value, ioc_type, customer_id).

When a new detection arrives:
  1. Check if a finding already exists for this (ioc_value, ioc_type, customer_id).
  2. If yes → merge: bump source_count, update last_seen, boost confidence,
               upgrade severity if the new source ranks higher.
  3. If no  → create a new finding from this detection.
  4. Either way, create a FindingSource row for audit trail.
  5. Set detection.finding_id → finding.id.

The pipeline calls get_or_create_finding() after routing and before enrichment.
"""
import logging
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from arguswatch.models import (

    Detection, Finding, FindingSource, SeverityLevel, DetectionStatus
)

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


logger = logging.getLogger("arguswatch.engine.finding_manager")

SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Source credibility weights - higher = more trusted = bigger confidence boost on merge
SOURCE_WEIGHT = {
    "cisa_kev":       1.0,   # CISA KEV = confirmed exploited, maximum trust
    "ransomfeed":     0.95,
    "threatfox":      0.90,
    "malwarebazaar":  0.90,
    "feodo":          0.85,
    "abuse":          0.80,
    "otx":            0.75,
    "urlscan":        0.70,
    "nvd":            0.85,  # CVEs from NVD are authoritative
    "hudsonrock":     0.80,
    "github":         0.65,
    "paste":          0.50,
    "rss":            0.40,
    "telegram":       0.45,
}
DEFAULT_SOURCE_WEIGHT = 0.55


def _source_weight(source: str) -> float:
    for key, w in SOURCE_WEIGHT.items():
        if key in source.lower():
            return w
    return DEFAULT_SOURCE_WEIGHT


def _compute_sla_deadline(severity: SeverityLevel, created_at: datetime) -> datetime:
    """SLA hours by severity - deadline = created_at + sla_hours."""
    hours = {
        SeverityLevel.CRITICAL: 4,
        SeverityLevel.HIGH: 24,
        SeverityLevel.MEDIUM: 72,
        SeverityLevel.LOW: 168,
        SeverityLevel.INFO: 720,
    }.get(severity, 72)
    return created_at + timedelta(hours=hours)


async def get_or_create_finding(
    detection: Detection,
    db: AsyncSession,
) -> tuple[Finding, bool]:
    """Core merge/create function.

    Returns (finding, is_new).
    - is_new=True  → caller should fire pipeline steps (enrich, attribute, action)
    - is_new=False → existing finding updated, no need to re-enrich unless source_count
                     crossed a threshold (2nd, 4th source = re-score)

    Must be called AFTER detection.customer_id is set (i.e., after routing).
    """
    if not detection.customer_id:
        # Unrouted → create unattributed finding (no customer)
        # Still deduplicated by (ioc_value, ioc_type) globally
        r = await db.execute(
            select(Finding).where(
                Finding.ioc_value == detection.ioc_value,
                Finding.ioc_type == detection.ioc_type,
                Finding.customer_id == None,
            ).limit(1)
        )
    else:
        r = await db.execute(
            select(Finding).where(
                Finding.ioc_value == detection.ioc_value,
                Finding.ioc_type == detection.ioc_type,
                Finding.customer_id == detection.customer_id,
            ).limit(1)
        )

    existing = r.scalar_one_or_none()

    if existing:
        # ── MERGE PATH ────────────────────────────────────────────────
        existing.last_seen = datetime.utcnow()
        existing.source_count += 1

        # Track all sources
        sources = list(existing.all_sources or [])
        if detection.source not in sources:
            sources.append(detection.source)
        existing.all_sources = sources

        # Upgrade severity if incoming is higher
        new_sev = _sev(detection.severity) or "MEDIUM"
        old_sev = _sev(existing.severity) or "MEDIUM"
        if SEV_RANK.get(new_sev, 0) > SEV_RANK.get(old_sev, 0):
            existing.severity = detection.severity
            existing.sla_deadline = _compute_sla_deadline(detection.severity, existing.created_at)
            logger.info(
                f"Finding {existing.id} severity upgraded {old_sev}→{new_sev} "
                f"by {detection.source}"
            )

        # Confidence boost: weighted average of source credibilities
        weight = _source_weight(detection.source)
        # Bayesian-style update: blend existing confidence toward 1.0 weighted by source trust
        existing.confidence = min(0.99, existing.confidence + (weight * 0.08))

        # Link detection → finding
        detection.finding_id = existing.id

        # Audit trail
        db.add(FindingSource(
            finding_id=existing.id,
            detection_id=detection.id,
            source=detection.source,
        ))

        await db.flush()

        # Signal whether a re-score is warranted
        rescore_threshold = existing.source_count in (2, 4, 8)
        logger.debug(
            f"Merged detection {detection.id} into finding {existing.id} "
            f"(source {existing.source_count}, conf={existing.confidence:.2f})"
        )
        return existing, False

    else:
        # ── CREATE PATH ───────────────────────────────────────────────
        sev = detection.severity or SeverityLevel.MEDIUM
        now = datetime.utcnow()
        finding = Finding(
            ioc_value=detection.ioc_value,
            ioc_type=detection.ioc_type,
            customer_id=detection.customer_id,
            matched_asset=detection.matched_asset,
            correlation_type=detection.correlation_type,
            severity=sev,
            status=DetectionStatus.NEW,
            sla_hours=detection.sla_hours or 72,
            sla_deadline=_compute_sla_deadline(sev, now),
            source_count=1,
            all_sources=[detection.source],
            confidence=_source_weight(detection.source),
            first_seen=detection.first_seen or now,
            last_seen=detection.last_seen or now,
            created_at=now,
        )
        db.add(finding)
        await db.flush()  # get finding.id

        # Link detection → finding
        detection.finding_id = finding.id

        # Audit trail
        db.add(FindingSource(
            finding_id=finding.id,
            detection_id=detection.id,
            source=detection.source,
        ))

        await db.flush()
        logger.info(
            f"Created finding {finding.id} for {detection.ioc_type}:{detection.ioc_value[:60]} "
            f"customer={detection.customer_id} source={detection.source}"
        )
        return finding, True
