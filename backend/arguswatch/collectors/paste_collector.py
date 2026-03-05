"""Paste Sites Collector - 3 sources: Pastebin, Rentry, ControlC.
Note: Ghostbin (dead since 2023) and Pastes.io removed.
"""
import httpx, logging, re
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus
from arguswatch.engine.pattern_matcher import scan_text
from arguswatch.engine.severity_scorer import score as score_ioc
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.paste")

PASTE_SOURCES = [
    {"name": "pastebin",   "url": "https://scrape.pastebin.com/api_scraping.php?limit=100", "type": "json"},
    {"name": "rentry",     "url": "https://rentry.co/recent", "type": "html"},
    {"name": "controlc",   "url": "https://controlc.com/index.php?act=posts", "type": "html"},
]

async def _fetch_pastes_json(url: str) -> list[dict]:
    """Fetch JSON paste list (Pastebin scrape API)."""
    try:
        async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": "ArgusWatch/8.0"}) as client:
            r = await client.get(url)
            if r.status_code != 200: return []
            return r.json() if r.text.startswith("[") else []
    except Exception as e:
        logger.debug(f"JSON paste fetch error: {e}")
        return []

async def _fetch_paste_content(paste_url: str) -> str:
    """Fetch raw content of a single paste."""
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True,
                                      headers={"User-Agent": "ArgusWatch/8.0"}) as client:
            r = await client.get(paste_url)
            return r.text[:50000] if r.status_code == 200 else ""
    except Exception:
        return ""

async def run_collection(customer_domains: list[str] | None = None) -> dict:
    stats = {"sources_checked": 0, "pastes_scanned": 0, "iocs_found": 0, "new": 0}
    # Pastebin scrape API (requires pro account, graceful fallback)
    pastes_json = await _fetch_pastes_json("https://scrape.pastebin.com/api_scraping.php?limit=100")
    async with async_session() as db:
        if pastes_json:
            stats["sources_checked"] += 1
            for paste in pastes_json[:50]:
                full_url = paste.get("full_url") or f"https://pastebin.com/raw/{paste.get('key','')}"
                content = await _fetch_paste_content(full_url)
                if not content: continue
                stats["pastes_scanned"] += 1
                # Scan per customer domain for boosted confidence
                for domain in (customer_domains or [""]):
                    matches = scan_text(content, customer_domain=domain)
                    for m in matches:
                        if m.confidence < 0.85: continue
                        stats["iocs_found"] += 1
                        r = await db.execute(select(Detection).where(
                            Detection.ioc_value == m.value, Detection.source == "pastebin"))
                        if r.scalar_one_or_none(): continue
                        scored = score_ioc(m.category, m.ioc_type, confidence=m.confidence)
                        db.add(Detection(
                            source="pastebin", ioc_type=m.ioc_type, ioc_value=m.value,
                            raw_text=m.context, severity=getattr(SeverityLevel, scored.severity),
                            sla_hours=scored.sla_hours, status=DetectionStatus.NEW,
                            confidence=m.confidence,
                            metadata_={"paste_url": full_url, "category": m.category,
                                       "paste_key": paste.get("key"), "assignee": scored.assignee_role},
                        ))
                        stats["new"] += 1
        await db.commit()
        await trigger_pipeline_for_new(db)
    return stats

@celery_app.task(name="arguswatch.collectors.paste_collector.collect_pastes")
def collect_pastes():
    import asyncio
    async def _wrapped():
        async with record_collector_run("paste") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
