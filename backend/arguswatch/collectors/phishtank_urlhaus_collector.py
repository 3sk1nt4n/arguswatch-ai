"""PhishTank + URLhaus - community phishing and malicious URL feeds.
PhishTank: community-verified phishing URLs.
URLhaus: abuse.ch malicious URL database.
Both zero auth, free feeds.
"""
import httpx, logging, asyncio, csv, io
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus, CustomerAsset
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run
from sqlalchemy import select

logger = logging.getLogger("arguswatch.collectors.phishtank_urlhaus")

PHISHTANK_CSV = "http://data.phishtank.com/data/online-valid.csv.bz2"
URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"

async def fetch_phishtank(client: httpx.AsyncClient) -> list[dict]:
    """PhishTank verified phishing URLs - no auth required."""
    results = []
    try:
        # Use the public daily CSV dump (bz2 - decompress)
        # Actually use their JSON API directly for recent
        resp = await client.get(
            "https://openphish.com/feed.txt",  # OpenPhish is easier/public
            timeout=20.0, headers={"User-Agent": "ArgusWatch/8.0"})
        if resp.status_code == 200:
            for line in resp.text.splitlines()[:100]:
                line = line.strip()
                if line.startswith("http"):
                    results.append({"url": line, "source": "openphish", "verified": True})
    except Exception as e:
        logger.debug(f"OpenPhish error: {e}")

    # Also try PhishTank JSON API (no auth for public feed)
    try:
        resp = await client.get(
            "http://data.phishtank.com/data/online-valid.json",
            timeout=30.0, headers={"User-Agent": "ArgusWatch/8.0"},
            follow_redirects=True)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[:50]:
                results.append({
                    "url": entry.get("url", ""),
                    "source": "phishtank",
                    "target": entry.get("target", ""),
                    "verified": entry.get("verified") == "yes",
                })
    except Exception as e:
        logger.debug(f"PhishTank error: {e}")

    return results

async def fetch_urlhaus(client: httpx.AsyncClient) -> list[dict]:
    """URLhaus recent malicious URLs - zero auth CSV."""
    results = []
    try:
        resp = await client.get(URLHAUS_CSV, timeout=20.0,
            headers={"User-Agent": "ArgusWatch/8.0"})
        if resp.status_code != 200:
            return []
        # Parse CSV (skip comment lines starting with #)
        lines = [l for l in resp.text.splitlines() if l and not l.startswith("#")]
        reader = csv.DictReader(lines)
        for row in list(reader)[:50]:
            url = row.get("url", "")
            tags = row.get("tags", "")
            threat = row.get("threat", "")
            if url:
                results.append({
                    "url": url,
                    "source": "urlhaus",
                    "threat_type": threat,
                    "tags": tags,
                    "verified": True,
                })
    except Exception as e:
        logger.debug(f"URLhaus error: {e}")
    return results

async def run_collection() -> dict:
    stats = {"phishtank": 0, "urlhaus": 0, "new": 0, "skipped": 0}

    async with async_session() as db:
        # Get customer domains to check for brand matches
        r = await db.execute(select(CustomerAsset).where(
            CustomerAsset.asset_type == "domain"))
        customer_domains = [(a.customer_id, a.asset_value.lower()) for a in r.scalars().all()]

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            # PhishTank
            pt_results = await fetch_phishtank(client)
            stats["phishtank"] = len(pt_results)

            # URLhaus
            uh_results = await fetch_urlhaus(client)
            stats["urlhaus"] = len(uh_results)

            all_results = pt_results + uh_results

            for item in all_results:
                url = item.get("url", "")
                if not url:
                    continue
                src = item["source"]

                # Check dedup
                r2 = await db.execute(select(Detection).where(
                    Detection.ioc_value == url[:200], Detection.source == src))
                if r2.scalar_one_or_none():
                    stats["skipped"] += 1
                    continue

                # Check if any customer domain appears in the URL
                matched_customer = None
                for cid, domain in customer_domains:
                    if domain in url.lower():
                        matched_customer = cid
                        break

                threat_type = item.get("threat_type", item.get("target", "phishing"))
                tags = item.get("tags", "")

                db.add(Detection(
                    source=src, ioc_type="url",
                    ioc_value=url[:200],
                    raw_text=f"{src}: {url} [{threat_type}] {tags}",
                    severity=SeverityLevel.HIGH, sla_hours=8,
                    status=DetectionStatus.NEW, confidence=0.85,
                    customer_id=matched_customer,
                    metadata_={"threat_type": threat_type, "tags": tags,
                               "verified": item.get("verified", False)},
                ))
                stats["new"] += 1

        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"PhishTank/URLhaus ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.phishtank_urlhaus_collector.collect_phishtank_urlhaus")
def collect_phishtank_urlhaus():
    async def _wrapped():
        async with record_collector_run("phishtank") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
