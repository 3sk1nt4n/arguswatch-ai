"""RSS Collector - Krebs, US-CERT, VX-Underground, DarkFeed, Pulsedive threat feeds."""
import httpx, logging
from datetime import datetime
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.rss")

RSS_FEEDS = [
    {"name": "krebs",   "url": "https://krebsonsecurity.com/feed/", "severity": SeverityLevel.HIGH},
    {"name": "uscert",  "url": "https://www.cisa.gov/uscert/ncas/alerts.xml", "severity": SeverityLevel.HIGH},
    {"name": "sans",    "url": "https://isc.sans.edu/rssfeed.xml", "severity": SeverityLevel.MEDIUM},
]

async def _parse_rss(url: str) -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": "ArgusWatch/8.0"}) as client:
            r = await client.get(url)
            if r.status_code != 200: return []
        import xml.etree.ElementTree as ET
        root = ET.fromstring(r.text)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        items = []
        for item in (root.findall(".//item") or root.findall(".//atom:entry", ns))[:20]:
            title_el = item.find("title") or item.find("atom:title", ns)
            link_el = item.find("link") or item.find("atom:link", ns)
            desc_el = item.find("description") or item.find("atom:summary", ns)
            title = title_el.text if title_el is not None else ""
            link = link_el.text or link_el.get("href", "") if link_el is not None else ""
            desc = desc_el.text if desc_el is not None else ""
            if title or link:
                items.append({"title": title, "link": link, "desc": desc})
        return items
    except Exception as e:
        logger.debug(f"RSS parse error {url}: {e}")
        return []

async def run_collection() -> dict:
    stats = {"feeds": 0, "new": 0, "skipped": 0}
    async with async_session() as db:
        for feed in RSS_FEEDS:
            items = await _parse_rss(feed["url"])
            stats["feeds"] += 1
            for item in items:
                val = item.get("link", "") or item.get("title", "")
                if not val: continue
                r = await db.execute(select(Detection).where(
                    Detection.ioc_value == val, Detection.source == feed["name"]))
                if r.scalar_one_or_none():
                    stats["skipped"] += 1; continue
                db.add(Detection(
                    source=feed["name"], ioc_type="threat_report_url", ioc_value=val[:500],
                    raw_text=item.get("title", "")[:300],
                    severity=feed["severity"], sla_hours=24,
                    status=DetectionStatus.NEW, confidence=0.80,
                    metadata_={"title": item.get("title",""), "desc": item.get("desc","")[:300]},
                ))
                stats["new"] += 1
        await db.commit()
    return stats

@celery_app.task(name="arguswatch.collectors.rss_collector.collect_rss")
def collect_rss():
    import asyncio
    async def _wrapped():
        async with record_collector_run("rss") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
