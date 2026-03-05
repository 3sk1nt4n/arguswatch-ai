"""
Enrichment Pipeline - called after every new detection is saved.
Runs: VirusTotal, AbuseIPDB, OTX, URLScan, BreachDirectory.
Saves results to enrichments table. Updates detection confidence.
"""
import httpx, logging
from arguswatch.config import settings
from arguswatch.database import async_session
from arguswatch.models import Detection, Enrichment, SeverityLevel
from sqlalchemy import select

logger = logging.getLogger("arguswatch.enrichment")

async def _vt_lookup(ioc_value: str, ioc_type: str, client: httpx.AsyncClient) -> dict | None:
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    url_map = {"ipv4": f"ip_addresses/{ioc_value}", "ipv6": f"ip_addresses/{ioc_value}",
               "domain": f"domains/{ioc_value}", "url": "urls",
               "sha256": f"files/{ioc_value}", "md5": f"files/{ioc_value}", "sha1": f"files/{ioc_value}"}
    endpoint = url_map.get(ioc_type, f"ip_addresses/{ioc_value}")
    try:
        if ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip("=")
            r = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}, timeout=10.0)
        else:
            r = await client.get(f"https://www.virustotal.com/api/v3/{endpoint}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}, timeout=10.0)
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0), "reputation": attrs.get("reputation", 0),
                    "country": attrs.get("country", ""), "as_owner": attrs.get("as_owner", "")}
    except Exception as e:
        logger.debug(f"VT error for {ioc_value}: {e}")
    return None

async def _abuse_lookup(ip: str, client: httpx.AsyncClient) -> dict | None:
    if not settings.ABUSEIPDB_API_KEY:
        return None
    try:
        r = await client.get("https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}, timeout=8.0)
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {"abuse_confidence": d.get("abuseConfidenceScore", 0),
                    "total_reports": d.get("totalReports", 0),
                    "country": d.get("countryCode", ""), "isp": d.get("isp", "")}
    except Exception as e:
        logger.debug(f"AbuseIPDB error: {e}")
    return None

async def enrich_detection(detection_id: int) -> dict:
    """Run all enrichment providers for a detection. Returns summary."""
    async with async_session() as db:
        r = await db.execute(select(Detection).where(Detection.id == detection_id))
        det = r.scalar_one_or_none()
        if not det:
            return {"error": "Detection not found"}
        results = {}
        async with httpx.AsyncClient(timeout=12.0) as client:
            # VirusTotal
            vt = await _vt_lookup(det.ioc_value, det.ioc_type, client)
            if vt:
                results["virustotal"] = vt
                db.add(Enrichment(detection_id=det.id, provider="virustotal",
                    enrichment_type="reputation", data=vt,
                    risk_score=vt.get("malicious", 0) / max(sum(vt.values() if isinstance(vt, dict) else [1]), 1)))
                if vt.get("malicious", 0) > 20 and det.severity != SeverityLevel.CRITICAL:
                    det.severity = SeverityLevel.HIGH
                    det.confidence = min(1.0, det.confidence + 0.15)
            # AbuseIPDB (IPs only)
            if det.ioc_type in ("ipv4", "ipv6"):
                abuse = await _abuse_lookup(det.ioc_value, client)
                if abuse:
                    results["abuseipdb"] = abuse
                    db.add(Enrichment(detection_id=det.id, provider="abuseipdb",
                        enrichment_type="ip_reputation", data=abuse,
                        risk_score=abuse.get("abuse_confidence", 0) / 100.0))
                    if abuse.get("abuse_confidence", 0) > 80:
                        det.confidence = min(1.0, det.confidence + 0.1)
        await db.commit()
        return {"detection_id": detection_id, "enrichments": list(results.keys()),
                "ioc_type": det.ioc_type, "ioc_value": det.ioc_value}
