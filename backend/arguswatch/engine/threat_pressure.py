"""
Threat Pressure Engine - Environmental Risk from Unmatched IOCs
================================================================
THE FIX FOR: "Most IOCs never match customers"

CONCEPT:
  50 Feodo C2 IPs don't match any customer directly.
  But they signal: "banking malware activity is HIGH right now."
  If a customer is in the banking sector → their risk increases.

  10 new LockBit ransomware victims in healthcare feeds → 
  healthcare customers get pressure even without direct IOC match.

HOW IT WORKS:
  1. Scan ALL unmatched detections (customer_id=NULL)
  2. Classify by category: c2_botnet, ransomware, phishing, exploit_campaign, credential_theft
  3. Extract targeted sectors from source context (malware families → known targets)
  4. Calculate activity_level per category (IOC volume × recency)
  5. Write to global_threat_activity table
  6. Exposure scorer reads this for environmental pressure factor

SOURCE → CATEGORY MAPPING:
  feodo, threatfox      → c2_botnet
  ransomfeed            → ransomware  
  openphish, urlscan    → phishing
  nvd, cisa_kev         → exploit_campaign
  hudsonrock, paste     → credential_theft

MALWARE FAMILY → SECTOR MAPPING (from real threat intel):
  Emotet, Dridex, Qakbot, TrickBot → financial, retail
  LockBit, BlackCat, Cl0p, Play    → healthcare, manufacturing, education
  APT28, APT29, Sandworm           → government, defense, energy
  Cobalt Strike                    → all sectors (commodity tool)
"""

import logging
import re
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, text

from arguswatch.models import (
    Detection, DarkWebMention, GlobalThreatActivity,
)

logger = logging.getLogger("arguswatch.engine.threat_pressure")

# ═══════════════════════════════════════════════════════════════════════
# SOURCE → CATEGORY CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════

SOURCE_TO_CATEGORY = {
    "feodo": "c2_botnet",
    "threatfox": "c2_botnet",
    "malwarebazaar": "c2_botnet",
    "abuse_ch": "c2_botnet",
    "ransomfeed": "ransomware",
    "openphish": "phishing",
    "urlscan": "phishing",
    "phishtank": "phishing",
    "nvd": "exploit_campaign",
    "cisa_kev": "exploit_campaign",
    "hudsonrock": "credential_theft",
    "paste": "credential_theft",
    "breach": "credential_theft",
    "rss": "general_threat",
    "github": "exploit_campaign",
}

# ═══════════════════════════════════════════════════════════════════════
# MALWARE FAMILY → SECTOR TARGETING (from real threat intel knowledge)
# ═══════════════════════════════════════════════════════════════════════

MALWARE_SECTORS = {
    # Banking trojans
    "emotet":       ["financial", "banking", "retail", "manufacturing"],
    "dridex":       ["financial", "banking"],
    "qakbot":       ["financial", "technology", "healthcare"],
    "trickbot":     ["financial", "healthcare", "education"],
    "icedid":       ["financial", "technology", "retail"],
    "pikabot":      ["financial", "manufacturing"],
    # Ransomware
    "lockbit":      ["healthcare", "manufacturing", "education", "government"],
    "blackcat":     ["healthcare", "technology", "financial"],
    "alphv":        ["healthcare", "technology", "financial"],
    "cl0p":         ["technology", "financial", "government", "education"],
    "play":         ["manufacturing", "technology", "government"],
    "akira":        ["technology", "education", "manufacturing"],
    "medusa":       ["education", "healthcare", "manufacturing"],
    "rhysida":      ["government", "healthcare", "education"],
    "blackbasta":   ["manufacturing", "technology", "financial"],
    "royal":        ["manufacturing", "healthcare"],
    # APTs
    "cobalt strike": ["technology", "financial", "government", "defense", "energy"],
    "cobaltstrike": ["technology", "financial", "government", "defense", "energy"],
    "apt28":        ["government", "defense", "energy", "technology"],
    "apt29":        ["government", "defense", "technology"],
    "sandworm":     ["energy", "government", "critical_infrastructure"],
    "lazarus":      ["financial", "technology", "defense"],
    "turla":        ["government", "defense"],
    # Infostealers
    "redline":      ["technology", "financial", "retail"],
    "raccoon":      ["technology", "financial"],
    "vidar":        ["technology", "financial", "retail"],
    "lumma":        ["technology", "financial"],
}

# Category → default sector mapping (when no specific malware family identified)
CATEGORY_DEFAULT_SECTORS = {
    "c2_botnet":        ["financial", "technology", "retail"],
    "ransomware":       ["healthcare", "manufacturing", "education", "government"],
    "phishing":         ["financial", "technology", "retail", "healthcare"],
    "exploit_campaign": ["technology", "government", "financial"],
    "credential_theft": ["technology", "financial", "healthcare"],
    "general_threat":   [],
}


def _extract_malware_family(raw_text: str, ioc_value: str) -> str | None:
    """Try to extract malware family name from detection raw_text or ioc_value."""
    if not raw_text:
        return None
    combined = (raw_text + " " + (ioc_value or "")).lower()
    for family in MALWARE_SECTORS:
        if family in combined:
            return family
    return None


def _get_sectors_for_malware(family: str | None, category: str) -> list[str]:
    """Get targeted sectors for a malware family or category."""
    if family and family in MALWARE_SECTORS:
        return MALWARE_SECTORS[family]
    return CATEGORY_DEFAULT_SECTORS.get(category, [])


async def calculate_threat_pressure(db: AsyncSession, window_hours: int = 24) -> dict:
    """Calculate global threat activity from ALL unmatched detections.
    
    Scans detections with customer_id=NULL from the last N hours,
    classifies them by category and malware family,
    and produces environmental pressure signals.
    """
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)
    window_start = cutoff
    window_end = datetime.utcnow()
    
    # Load all unmatched detections from the window
    r = await db.execute(
        select(Detection).where(
            Detection.customer_id.is_(None),
            Detection.created_at >= cutoff,
        ).limit(10000)
    )
    unmatched = r.scalars().all()
    
    # Also load dark web mentions
    dw_r = await db.execute(
        select(DarkWebMention).where(
            DarkWebMention.customer_id.is_(None),
            DarkWebMention.discovered_at >= cutoff,
        ).limit(2000)
    )
    dw_unmatched = dw_r.scalars().all()
    
    # ── Aggregate by category + malware family ──
    # Key: (category, malware_family) → {count, sources, sectors, products}
    pressure_map = {}
    
    for det in unmatched:
        source = det.source or "unknown"
        category = SOURCE_TO_CATEGORY.get(source, "general_threat")
        family = _extract_malware_family(det.raw_text, det.ioc_value)
        sectors = _get_sectors_for_malware(family, category)
        
        key = (category, family or "unknown")
        if key not in pressure_map:
            pressure_map[key] = {
                "count": 0, "sources": set(), "sectors": set(),
                "products": set(), "first_seen": det.created_at,
                "last_seen": det.created_at,
            }
        entry = pressure_map[key]
        entry["count"] += 1
        entry["sources"].add(source)
        entry["sectors"].update(sectors)
        if det.created_at < entry["first_seen"]:
            entry["first_seen"] = det.created_at
        if det.created_at > entry["last_seen"]:
            entry["last_seen"] = det.created_at
        
        # Extract affected products from CVE metadata
        if det.ioc_type == "cve_id":
            meta = det.metadata_ or {}
            for p in meta.get("affected_products", []):
                entry["products"].add(p)
    
    # Add dark web mentions as ransomware/credential pressure
    for dw in dw_unmatched:
        mt = dw.mention_type or ""
        category = "ransomware" if "ransomware" in mt else "credential_theft"
        family = _extract_malware_family(dw.content_snippet or dw.title, "")
        sectors = _get_sectors_for_malware(family, category)
        
        key = (category, family or "unknown")
        if key not in pressure_map:
            pressure_map[key] = {
                "count": 0, "sources": set(), "sectors": set(),
                "products": set(), "first_seen": dw.discovered_at,
                "last_seen": dw.discovered_at,
            }
        pressure_map[key]["count"] += 1
        pressure_map[key]["sources"].add(dw.source)
        pressure_map[key]["sectors"].update(sectors)
    
    # ── Calculate activity levels and persist ──
    stats = {"categories": 0, "total_iocs": 0, "max_level": 0.0}
    
    for (category, family), data in pressure_map.items():
        count = data["count"]
        if count < 2:
            continue  # Skip noise
        
        # Activity level: log scale 0-10 based on IOC count
        # 2 IOCs = 1.0, 10 = 3.3, 50 = 5.6, 100 = 6.6, 500 = 9.0, 1000 = 10.0
        import math
        activity = min(10.0, math.log10(max(count, 1)) * 3.3)
        
        # Recency boost: more recent = higher activity
        hours_since = (datetime.utcnow() - data["last_seen"]).total_seconds() / 3600
        if hours_since < 1:
            activity *= 1.3
        elif hours_since < 6:
            activity *= 1.1
        
        # Time decay: reduce activity for older windows
        from arguswatch.utils import time_decay
        age_days = max(0, (datetime.utcnow() - data["last_seen"]).total_seconds() / 86400)
        decay_factor = time_decay(age_days, half_life_days=7.0)  # 7-day half-life for threat pressure
        activity = activity * decay_factor
        
        activity = min(10.0, activity)
        
        # Upsert into global_threat_activity
        existing = await db.execute(
            select(GlobalThreatActivity).where(
                GlobalThreatActivity.category == category,
                GlobalThreatActivity.malware_family == (family if family != "unknown" else None),
            ).limit(1)
        )
        gta = existing.scalar_one_or_none()
        
        if gta:
            gta.activity_level = activity
            gta.ioc_count = count
            gta.sources = sorted(data["sources"])
            gta.targeted_sectors = sorted(data["sectors"])
            gta.affected_products = sorted(data["products"])
            gta.last_seen = data["last_seen"]
            gta.window_start = window_start
            gta.window_end = window_end
            gta.updated_at = datetime.utcnow()
        else:
            db.add(GlobalThreatActivity(
                category=category,
                malware_family=family if family != "unknown" else None,
                activity_level=activity,
                ioc_count=count,
                sources=sorted(data["sources"]),
                targeted_sectors=sorted(data["sectors"]),
                affected_products=sorted(data["products"]),
                first_seen=data["first_seen"],
                last_seen=data["last_seen"],
                window_start=window_start,
                window_end=window_end,
            ))
        
        stats["categories"] += 1
        stats["total_iocs"] += count
        stats["max_level"] = max(stats["max_level"], activity)
    
    await db.flush()
    await db.commit()
    
    logger.info(
        f"Threat pressure: {stats['categories']} categories, "
        f"{stats['total_iocs']} IOCs, max level {stats['max_level']:.1f}"
    )
    return stats


async def get_sector_pressure(sector: str, db: AsyncSession) -> float:
    """Get the environmental threat pressure score for a specific sector.
    
    Returns 0.0-10.0 representing how active threats are against this sector.
    Used by exposure_scorer for the environmental pressure factor.
    """
    sector_lower = sector.lower()
    
    r = await db.execute(
        select(GlobalThreatActivity).where(
            GlobalThreatActivity.activity_level > 0,
        )
    )
    activities = r.scalars().all()
    
    max_pressure = 0.0
    total_weighted = 0.0
    count = 0
    
    for gta in activities:
        sectors = [s.lower() for s in (gta.targeted_sectors or [])]
        if any(sector_lower in s or s in sector_lower for s in sectors):
            # This threat activity targets our sector
            total_weighted += gta.activity_level
            max_pressure = max(max_pressure, gta.activity_level)
            count += 1
    
    if count == 0:
        return 0.0
    
    # Combine: weighted by max pressure (dominant threat) + average (breadth)
    avg_pressure = total_weighted / count
    return min(10.0, (max_pressure * 0.6) + (avg_pressure * 0.4))


async def calculate_probable_exposures(customer_id: int, db: AsyncSession) -> dict:
    """Calculate probable/indirect exposures for a customer.
    
    This handles Problem B: tech stack risk baseline + unknown version exposures.
    
    Types:
    1. tech_risk_baseline: Customer runs historically-targeted software
    2. unknown_version: CVE matches product but version unknown → lower confidence
    3. sector_pressure: Global threat activity targeting customer's sector
    """
    from arguswatch.models import Customer, CustomerAsset, CveProductMap, ProbableExposure
    
    customer = (await db.execute(
        select(Customer).where(Customer.id == customer_id)
    )).scalar_one_or_none()
    if not customer:
        return {"error": "Customer not found"}
    
    # Clear old probable exposures for this customer
    await db.execute(
        text("DELETE FROM probable_exposures WHERE customer_id = :cid"),
        {"cid": customer_id}
    )
    
    stats = {"tech_baseline": 0, "unknown_version": 0, "sector_pressure": 0}
    
    # ── 1. Tech risk baseline ──
    # How many CVEs historically affect products in customer's tech stack?
    assets = (await db.execute(
        select(CustomerAsset).where(
            CustomerAsset.customer_id == customer_id,
            CustomerAsset.asset_type == "tech_stack",
        )
    )).scalars().all()
    
    HISTORICALLY_RISKY = {
        "exchange": ("Microsoft Exchange", 25, 0.8),
        "sharepoint": ("SharePoint", 15, 0.6),
        "fortios": ("FortiOS/FortiGate", 20, 0.9),
        "fortigate": ("FortiOS/FortiGate", 20, 0.9),
        "confluence": ("Atlassian Confluence", 12, 0.7),
        "ivanti": ("Ivanti Connect Secure", 18, 0.85),
        "citrix": ("Citrix NetScaler", 15, 0.75),
        "apache": ("Apache HTTP Server", 20, 0.5),
        "nginx": ("Nginx", 8, 0.3),
        "openssh": ("OpenSSH", 10, 0.4),
        "vmware": ("VMware ESXi/vCenter", 18, 0.8),
        "esxi": ("VMware ESXi", 15, 0.85),
        "panos": ("Palo Alto PAN-OS", 12, 0.7),
        "moveit": ("MOVEit Transfer", 8, 0.9),
        "solarwinds": ("SolarWinds Orion", 5, 0.85),
        "wordpress": ("WordPress", 30, 0.4),
        "php": ("PHP", 25, 0.3),
    }
    
    for asset in assets:
        av_lower = re.split(r"[/:\s]+\d", asset.asset_value.lower())[0].strip()
        av_clean = av_lower.replace("-", "").replace("_", "").replace(" ", "")
        
        for key, (name, cve_count, risk_factor) in HISTORICALLY_RISKY.items():
            if key in av_clean or av_clean in key:
                risk_pts = risk_factor * 10  # 0-10 scale
                db.add(ProbableExposure(
                    customer_id=customer_id,
                    exposure_type="tech_risk_baseline",
                    source_detail=f"{name}: {cve_count} critical CVEs historically",
                    product_name=name,
                    confidence=0.7,
                    risk_points=risk_pts,
                ))
                stats["tech_baseline"] += 1
                break
    
    # ── 2. Sector pressure from global threat activity ──
    if customer.industry:
        sector_pressure = await get_sector_pressure(customer.industry, db)
        if sector_pressure > 1.0:
            db.add(ProbableExposure(
                customer_id=customer_id,
                exposure_type="sector_pressure",
                source_detail=f"Active threats targeting {customer.industry} (pressure: {sector_pressure:.1f}/10)",
                confidence=0.6,
                risk_points=sector_pressure,
            ))
            stats["sector_pressure"] += 1
    
    await db.flush()
    await db.commit()
    
    logger.info(f"Probable exposures [{customer.name}]: {stats}")
    return stats
