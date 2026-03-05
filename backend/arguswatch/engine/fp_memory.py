"""
FP Memory Engine - False Positive Learning System
====================================================
WHAT: Learns from analyst FALSE_POSITIVE decisions. Stores patterns.
      Next time the same pattern appears, auto-closes or warns.
WHY:  Rule-based FP checks are stateless. The 100th time a CDN IP
      gets flagged, the system still doesn't know it's FP.
      This engine compounds value every week.

FLOW:
  1. Analyst marks detection/finding as FALSE_POSITIVE
     → record_fp_pattern() stores (customer_id, ioc_type, value, reason)
  2. New detection arrives in pipeline
     → check_fp_history() queries fp_patterns for match
     → If match: auto-close if confidence > 0.85, else warn AI triage
  3. AI triage receives FP context
     → Can still override (e.g., VT score jumped from 2 to 31)
"""

import logging
import ipaddress
from datetime import datetime
from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from arguswatch.models import FPPattern

logger = logging.getLogger("arguswatch.fp_memory")


async def record_fp_pattern(
    customer_id: int,
    ioc_type: str,
    ioc_value: str,
    source: str = "",
    reason: str = "",
    created_by: str = "analyst",
    db: AsyncSession = None,
) -> dict:
    """Record a new FP pattern from analyst feedback.

    Called when analyst marks a finding/detection as FALSE_POSITIVE.
    Deduplicates: if same customer + ioc_type + value exists, increments hit_count.
    """
    # Check if pattern already exists
    existing = await db.execute(
        select(FPPattern).where(
            FPPattern.customer_id == customer_id,
            FPPattern.ioc_type == ioc_type,
            FPPattern.ioc_value_pattern == ioc_value,
        ).limit(1)
    )
    fp = existing.scalar_one_or_none()

    if fp:
        fp.hit_count += 1
        fp.last_hit_at = datetime.utcnow()
        # Increase confidence with each confirmation (asymptotic to 0.99)
        fp.confidence = min(0.99, fp.confidence + (1.0 - fp.confidence) * 0.15)
        if reason:
            fp.reason = reason  # Update with latest reason
        logger.info(f"[fp_memory] Updated FP pattern: {ioc_type}:{ioc_value[:40]} "
                     f"hit_count={fp.hit_count} conf={fp.confidence:.2f}")
        await db.flush()
        return {"action": "updated", "hit_count": fp.hit_count, "confidence": fp.confidence}

    # Create new pattern
    # Determine match_type: for IPs, store as CIDR-aware
    match_type = "exact"
    pattern_value = ioc_value
    if ioc_type in ("ipv4",):
        try:
            # If IP, also create a /24 prefix pattern for nearby IPs
            ip = ipaddress.ip_address(ioc_value.strip())
            network = ipaddress.ip_network(f"{ioc_value}/24", strict=False)
            # Only create CIDR pattern if this is the 2nd+ FP from same /24
            existing_cidr = await db.execute(
                select(func.count(FPPattern.id)).where(
                    FPPattern.customer_id == customer_id,
                    FPPattern.ioc_type == "ipv4",
                    FPPattern.ioc_value_pattern.like(f"{str(network.network_address).rsplit('.', 1)[0]}%"),
                )
            )
            cidr_count = existing_cidr.scalar() or 0
            if cidr_count >= 2:
                # 3+ FPs from same /24 → create CIDR pattern
                match_type = "cidr"
                pattern_value = str(network)
                logger.info(f"[fp_memory] Auto-expanded to CIDR pattern: {pattern_value} "
                             f"({cidr_count + 1} FPs from this range)")
        except Exception:
            pass

    db.add(FPPattern(
        customer_id=customer_id,
        ioc_type=ioc_type,
        ioc_value_pattern=pattern_value,
        match_type=match_type,
        source=source,
        reason=reason,
        confidence=0.85,  # First FP starts at 0.85
        created_by=created_by,
    ))
    await db.flush()
    logger.info(f"[fp_memory] New FP pattern: {match_type}:{ioc_type}:{pattern_value[:40]} "
                 f"customer={customer_id} reason={reason[:60]}")
    return {"action": "created", "match_type": match_type, "pattern": pattern_value}


async def check_fp_history(
    customer_id: int,
    ioc_type: str,
    ioc_value: str,
    source: str = "",
    db: AsyncSession = None,
) -> dict | None:
    """Check if a detection matches a known FP pattern.

    Returns dict with FP info if match found, None if no match.
    Called BEFORE AI triage - saves API cost on known FPs.

    Return: {
        "is_fp": True,
        "confidence": 0.92,
        "reason": "CDN IP - analyst confirmed 3x",
        "auto_close": True,  # confidence > 0.85
        "pattern_id": 42,
        "hit_count": 5,
    }
    """
    # 1. Check exact match
    r = await db.execute(
        select(FPPattern).where(
            FPPattern.customer_id == customer_id,
            FPPattern.ioc_type == ioc_type,
            FPPattern.ioc_value_pattern == ioc_value,
            FPPattern.match_type == "exact",
        ).limit(1)
    )
    fp = r.scalar_one_or_none()

    # 2. Check CIDR match for IP types
    if not fp and ioc_type in ("ipv4",):
        try:
            ip = ipaddress.ip_address(ioc_value.strip())
            cidr_r = await db.execute(
                select(FPPattern).where(
                    FPPattern.customer_id == customer_id,
                    FPPattern.ioc_type == ioc_type,
                    FPPattern.match_type == "cidr",
                ).limit(20)
            )
            for cidr_fp in cidr_r.scalars().all():
                try:
                    if ip in ipaddress.ip_network(cidr_fp.ioc_value_pattern, strict=False):
                        fp = cidr_fp
                        break
                except Exception:
                    continue
        except Exception:
            pass

    if not fp:
        return None

    # Update hit tracking
    fp.hit_count += 1
    fp.last_hit_at = datetime.utcnow()
    await db.flush()

    auto_close = fp.confidence >= 0.85

    logger.info(f"[fp_memory] FP match: {ioc_type}:{ioc_value[:40]} → pattern#{fp.id} "
                 f"conf={fp.confidence:.2f} hits={fp.hit_count} auto_close={auto_close}")

    return {
        "is_fp": True,
        "confidence": fp.confidence,
        "reason": fp.reason or f"Matches known FP pattern (confirmed {fp.hit_count}x)",
        "auto_close": auto_close,
        "pattern_id": fp.id,
        "hit_count": fp.hit_count,
    }
