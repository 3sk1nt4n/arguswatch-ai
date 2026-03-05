"""PhishTank + URLhaus Collector - phishing URLs + malicious URL feeds.
PhishTank: community phishing database (free, optional key).
URLhaus: abuse.ch malicious URL feed (zero auth).
"""
import httpx, logging, asyncio, csv, io
from datetime import datetime
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus, CustomerAsset, Customer
from arguswatch.config import settings
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.phishtank_urlhaus")

PHISHTANK_FEED = "https://data.phishtank.com/data/online-valid.csv"
URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text_online/"


async def _fetch_phishtank(client: httpx.AsyncClient) -> list[dict]:
    """Fetch PhishTank online-valid feed."""
    try:
        headers = {"User-Agent": "phishtank/ArgusWatch"}
        key = getattr(settings, "PHISHTANK_API_KEY", "") or ""
        if key:
            headers["phishtank-key"] = key
        resp = await client.get(PHISHTANK_FEED, headers=headers, timeout=30.0)
        if resp.status_code != 200:
            logger.debug(f"PhishTank: HTTP {resp.status_code}")
            return []
        reader = csv.DictReader(io.StringIO(resp.text))
        results = []
        for row in reader:
            url = row.get("url", "")
            if url and row.get("verified", "").lower() == "yes":
                results.append({
                    "url": url,
                    "target": row.get("target", ""),
                    "submission_time": row.get("submission_time", ""),
                    "phish_id": row.get("phish_id", ""),
                })
        return results[:500]  # Cap at 500 per run
    except Exception as e:
        logger.warning(f"PhishTank fetch error: {e}")
        return []


async def _fetch_urlhaus(client: httpx.AsyncClient) -> list[str]:
    """Fetch URLhaus online malicious URL feed."""
    try:
        resp = await client.get(URLHAUS_FEED, timeout=20.0,
                                headers={"User-Agent": "ArgusWatch/8.0"})
        if resp.status_code != 200:
            return []
        urls = [line.strip() for line in resp.text.splitlines()
                if line.strip() and not line.startswith("#")]
        return urls[:1000]
    except Exception as e:
        logger.warning(f"URLhaus fetch error: {e}")
        return []


def _matches_customer(url: str, target: str, customer_assets: list) -> tuple[bool, str]:
    """Check if a phishing URL targets a customer's brand/domain."""
    url_lower = url.lower()
    target_lower = target.lower() if target else ""
    for asset in customer_assets:
        val = asset.asset_value.lower()
        if val in url_lower or (target_lower and val in target_lower):
            return True, asset.asset_value
    return False, ""


async def run_collection() -> dict:
    stats = {"phishtank_checked": 0, "urlhaus_checked": 0, "new": 0, "skipped": 0}

    async with async_session() as db:
        r = await db.execute(select(Customer).where(Customer.active == True))
        customers = r.scalars().all()

        # Gather all customer domain/keyword assets
        customer_assets_map = {}
        for customer in customers:
            ra = await db.execute(select(CustomerAsset).where(
                CustomerAsset.customer_id == customer.id,
                CustomerAsset.asset_type.in_(["domain", "keyword", "email_pattern"])))
            customer_assets_map[customer.id] = ra.scalars().all()

        async with httpx.AsyncClient(timeout=30.0) as client:
            # ── PhishTank ──
            phish_urls = await _fetch_phishtank(client)
            stats["phishtank_checked"] = len(phish_urls)
            for item in phish_urls:
                url = item["url"]
                for customer in customers:
                    assets = customer_assets_map.get(customer.id, [])
                    matched, matched_asset = _matches_customer(url, item.get("target", ""), assets)
                    if not matched:
                        continue
                    det_key = f"phishtank-{item.get('phish_id','')}-{customer.id}"
                    rd = await db.execute(select(Detection).where(Detection.ioc_value == det_key))
                    if rd.scalar_one_or_none():
                        stats["skipped"] += 1
                        continue
                    db.add(Detection(
                        source="phishtank",
                        ioc_type="url",
                        ioc_value=det_key,
                        customer_id=customer.id,
                        matched_asset=matched_asset,
                        raw_text=f"PhishTank verified phish: {url[:200]} (target: {item.get('target','unknown')})",
                        severity=SeverityLevel.HIGH,
                        sla_hours=8,
                        status=DetectionStatus.NEW,
                        confidence=0.95,
                        metadata_={
                            "url": url,
                            "target": item.get("target", ""),
                            "phish_id": item.get("phish_id", ""),
                            "submission_time": item.get("submission_time", ""),
                            "verified": True,
                        },
                    ))
                    stats["new"] += 1

            # ── URLhaus ──
            urlhaus_urls = await _fetch_urlhaus(client)
            stats["urlhaus_checked"] = len(urlhaus_urls)
            for url in urlhaus_urls:
                for customer in customers:
                    assets = customer_assets_map.get(customer.id, [])
                    matched, matched_asset = _matches_customer(url, "", assets)
                    if not matched:
                        continue
                    det_key = f"urlhaus-{hash(url)}-{customer.id}"
                    rd = await db.execute(select(Detection).where(Detection.ioc_value == det_key))
                    if rd.scalar_one_or_none():
                        stats["skipped"] += 1
                        continue
                    db.add(Detection(
                        source="urlhaus",
                        ioc_type="url",
                        ioc_value=det_key,
                        customer_id=customer.id,
                        matched_asset=matched_asset,
                        raw_text=f"URLhaus active malware URL: {url[:200]}",
                        severity=SeverityLevel.HIGH,
                        sla_hours=4,
                        status=DetectionStatus.NEW,
                        confidence=0.88,
                        metadata_={"url": url},
                    ))
                    stats["new"] += 1

        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"PhishTank/URLhaus ingest: {stats}")
    return stats


@celery_app.task(name="arguswatch.collectors.phishtank_urlhaus.collect_phishtank_urlhaus")
def collect_phishtank_urlhaus():
    async def _wrapped():
        async with record_collector_run("phishtank_urlhaus") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
