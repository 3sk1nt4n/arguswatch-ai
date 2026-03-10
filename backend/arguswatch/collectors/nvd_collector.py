"""NVD CVE Collector - recent high/critical CVEs from NIST NVD (free, no key).

V11: Also populates cve_product_map table from CPE data.
CPE (Common Platform Enumeration) data in NVD tells us exactly which
products/versions are vulnerable - enabling tech_stack correlation.
"""
import httpx, logging, re
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus, CveProductMap
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.nvd")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CVSS_TO_SEV = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
}


def _parse_cpe(cpe_uri: str) -> tuple[str, str] | tuple[None, None]:
    """Parse CPE 2.3 URI to extract product name and vendor.
    
    CPE format: cpe:2.3:a:vendor:product:version:...
    Example: cpe:2.3:a:fortinet:fortios:7.2.0 -> ("FortiOS", "Fortinet")
    """
    parts = cpe_uri.split(":")
    if len(parts) < 5:
        return None, None
    vendor = parts[3].replace("_", " ").title()
    product = parts[4].replace("_", " ").title()
    if product == "*" or product == "-":
        return None, None
    return product, vendor


def _extract_version_range(config_node: dict) -> str:
    """Extract version range string from NVD CPE match data."""
    ranges = []
    for match in config_node.get("cpeMatch", []):
        vi = match.get("versionStartIncluding", "")
        ve = match.get("versionEndExcluding", "")
        vei = match.get("versionEndIncluding", "")
        if ve:
            ranges.append(f"< {ve}")
        elif vei:
            ranges.append(f"<= {vei}")
        elif vi:
            ranges.append(f">= {vi}")
    return ", ".join(ranges[:3]) if ranges else ""


def _extract_cpe_data(cve: dict) -> list[dict]:
    """Extract all product entries from a CVE's configurations block."""
    products = []
    seen = set()
    configurations = cve.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            version_range = _extract_version_range(node)
            for match in node.get("cpeMatch", []):
                cpe_uri = match.get("criteria", "")
                if not cpe_uri or not match.get("vulnerable", False):
                    continue
                product, vendor = _parse_cpe(cpe_uri)
                if not product:
                    continue
                key = f"{vendor}:{product}"
                if key in seen:
                    continue
                seen.add(key)
                products.append({
                    "product_name": product,
                    "vendor": vendor,
                    "version_range": version_range,
                })
    return products[:20]  # Cap at 20 products per CVE to avoid noise


async def run_collection() -> dict:
    now = datetime.utcnow()
    since = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000")
    until = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    params = {
        "pubStartDate": since, "pubEndDate": until,
        "cvssV3Severity": "HIGH", "resultsPerPage": 100,
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(NVD_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.error(f"NVD error: {e}")
        return {"error": str(e)}

    vulns = data.get("vulnerabilities", [])
    stats = {
        "total": len(vulns), "new": 0, "skipped": 0,
        "cpe_products_added": 0, "cpe_skipped": 0,
    }

    async with async_session() as db:
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            # ── Parse CVSS once - used by both detection and cpe_product_map ──
            metrics = cve.get("metrics", {})
            cvss_v3 = (
                metrics.get("cvssMetricV31", [{}]) or
                metrics.get("cvssMetricV3", [{}])
            )
            base_score = 0.0
            severity_str = "HIGH"
            if cvss_v3:
                cvss_data = cvss_v3[0].get("cvssData", {})
                base_score = cvss_data.get("baseScore", 0.0)
                severity_str = cvss_data.get("baseSeverity", "HIGH")

            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                ""
            )

            # ── CVE detection ──────────────────────────────────────────────
            r = await db.execute(
                select(Detection).where(
                    Detection.ioc_value == cve_id,
                    Detection.source == "nvd",
                )
            )
            if r.scalar_one_or_none():
                stats["skipped"] += 1
                # Still update cve_product_map below even for known CVEs
            else:
                affected_products = _extract_product_names_from_desc(desc)
                db.add(Detection(
                    source="nvd", ioc_type="cve_id", ioc_value=cve_id,
                    raw_text=desc[:500],
                    severity=CVSS_TO_SEV.get(severity_str, SeverityLevel.HIGH),
                    sla_hours=48, status=DetectionStatus.NEW, confidence=0.95,
                    metadata_={
                        "cvss_score": base_score,
                        "cvss_severity": severity_str,
                        "published": cve.get("published", ""),
                        "affected_products": _extract_product_names_from_desc(desc),
                    },
                ))
                stats["new"] += 1

            # ── cve_product_map population (uses same base_score/severity_str) ──
            cpe_products = _extract_cpe_data(cve)

            for product_data in cpe_products:
                # Check if already in map
                existing_r = await db.execute(
                    select(CveProductMap).where(
                        CveProductMap.cve_id == cve_id,
                        CveProductMap.product_name == product_data["product_name"],
                    ).limit(1)
                )
                if existing_r.scalar_one_or_none():
                    stats["cpe_skipped"] += 1
                    continue
                db.add(CveProductMap(
                    cve_id=cve_id,
                    product_name=product_data["product_name"],
                    vendor=product_data["vendor"],
                    version_range=product_data["version_range"],
                    cvss_score=base_score,
                    severity=severity_str,
                    actively_exploited=False,  # CISA KEV will flip this
                    source="nvd",
                ))
                stats["cpe_products_added"] += 1

        await db.commit()
        await trigger_pipeline_for_new(db)

        # ── Batch EPSS enrichment for new CVEs ──────────────────────────
        # FIRST.org EPSS API: free, no auth, returns exploitation probability
        if stats["new"] > 0:
            await _enrich_epss(db)

    logger.info(f"NVD ingest: {stats}")
    return stats


async def _enrich_epss(db):
    """Fetch EPSS scores from FIRST.org for CVE detections missing EPSS data.
    
    EPSS (Exploit Prediction Scoring System) gives the probability that a CVE
    will be exploited in the wild within the next 30 days. Scale: 0.0 to 1.0.
    Scores > 0.5 = high risk. Scores > 0.9 = very likely to be exploited.
    
    API: https://api.first.org/data/v1/epss?cve=CVE-2024-1234,CVE-2024-5678
    Free, no key required, batch up to 100 CVEs per request.
    """
    try:
        # Find CVE detections without EPSS data (check metadata)
        r = await db.execute(
            select(Detection).where(
                Detection.ioc_type == "cve_id",
                Detection.source == "nvd",
            ).order_by(Detection.created_at.desc()).limit(200)
        )
        detections = r.scalars().all()
        
        # Filter to those without EPSS
        needs_epss = []
        for det in detections:
            meta = det.metadata_ or {}
            if not meta.get("epss_score"):
                needs_epss.append(det)
        
        if not needs_epss:
            return
        
        # Batch in groups of 100 (API limit)
        enriched = 0
        for i in range(0, len(needs_epss), 100):
            batch = needs_epss[i:i+100]
            cve_list = ",".join(d.ioc_value for d in batch)
            
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(
                        f"https://api.first.org/data/v1/epss?cve={cve_list}"
                    )
                    if resp.status_code != 200:
                        logger.warning(f"EPSS API returned {resp.status_code}")
                        continue
                    
                    epss_data = resp.json().get("data", [])
                    epss_map = {e["cve"]: e for e in epss_data}
                    
                    for det in batch:
                        epss_entry = epss_map.get(det.ioc_value)
                        if epss_entry:
                            meta = dict(det.metadata_ or {})
                            meta["epss_score"] = float(epss_entry.get("epss", 0))
                            meta["epss_percentile"] = float(epss_entry.get("percentile", 0))
                            det.metadata_ = meta
                            enriched += 1
            except Exception as e:
                logger.warning(f"EPSS batch fetch failed: {e}")
        
        if enriched:
            await db.commit()
            logger.info(f"EPSS: enriched {enriched} CVEs with exploitation probability")
    except Exception as e:
        logger.warning(f"EPSS enrichment failed: {e}")


def _extract_product_names_from_desc(desc: str) -> list[str]:
    """Fallback: extract likely product names from CVE description text.
    Used when CPE configuration data is unavailable.
    """
    # Common product name patterns in CVE descriptions
    products = []
    known_products = [
        "FortiOS", "FortiGate", "Exchange", "SharePoint", "Confluence",
        "Jira", "Apache", "Nginx", "OpenSSL", "VMware", "ESXi",
        "vCenter", "Ivanti", "Citrix", "Pulse Secure", "SolarWinds",
        "MOVEit", "GoAnywhere", "PaperCut", "Cisco", "Juniper",
        "Palo Alto", "PAN-OS", "Windows", "Chrome", "Firefox",
    ]
    desc_lower = desc.lower()
    for product in known_products:
        if product.lower() in desc_lower:
            products.append(product)
    return products[:5]


@celery_app.task(name="arguswatch.collectors.nvd_collector.collect_nvd")
def collect_nvd():
    import asyncio
    async def _wrapped():
        async with record_collector_run("nvd") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
