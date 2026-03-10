"""Dark Search Collector - Ahmia + IntelX clearnet dark web indexes.
No Tor required. Automated - not manual like IAMPilot treats it.
Searches for customer asset mentions across dark web content.

Note: DarkSearch.io removed (unreliable/offline since mid-2024).
Ahmia.fi is the primary free source. IntelX requires API key.
"""
import httpx, logging, asyncio
from arguswatch.config import settings
from arguswatch.database import async_session
from arguswatch.models import DarkWebMention, SeverityLevel, CustomerAsset, Customer
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run
from sqlalchemy import select

logger = logging.getLogger("arguswatch.collectors.darksearch")

async def search_ahmia(term: str, client: httpx.AsyncClient) -> list[dict]:
    """Ahmia.fi - clearnet Tor search index."""
    try:
        resp = await client.get("https://ahmia.fi/search/", params={"q": term},
            headers={"User-Agent": "ArgusWatch/7.0"}, timeout=15.0)
        if resp.status_code != 200: return []
        from html.parser import HTMLParser
        class ResultParser(HTMLParser):
            def __init__(self):
                super().__init__(); self.results = []; self._in_result = False; self._title = ""
            def handle_starttag(self, tag, attrs):
                if tag == "li":
                    d = dict(attrs)
                    if "result" in d.get("class",""):
                        self._in_result = True
            def handle_endtag(self, tag):
                if tag == "li": self._in_result = False; self._title = ""
            def handle_data(self, data):
                if self._in_result and data.strip():
                    self._title = data.strip()[:200]
                    if self._title: self.results.append({"title": self._title, "source": "ahmia"})
        p = ResultParser(); p.feed(resp.text)
        return p.results[:10]
    except Exception as e:
        logger.debug(f"Ahmia error: {e}"); return []

async def search_darksearch(term: str, api_key: str, client: httpx.AsyncClient) -> list[dict]:
    """DarkSearch.io - DEPRECATED, offline since mid-2024. Returns empty."""
    logger.debug("DarkSearch.io deprecated - skipping (use Ahmia + IntelX)")
    return []

async def search_intelx(term: str, api_key: str, client: httpx.AsyncClient) -> list[dict]:
    """IntelX - dark web + paste search."""
    if not api_key: return []
    try:
        # Search init
        r1 = await client.post("https://2.intelx.io/intelligent/search",
            headers={"x-key": api_key},
            json={"term": term, "buckets": [], "lookuplevel": 0, "maxresults": 10,
                  "timeout": 0, "datefrom": "", "dateto": "", "sort": 4, "media": 0, "terminate": []},
            timeout=15.0)
        if r1.status_code not in (200, 201): return []
        search_id = r1.json().get("id","")
        if not search_id: return []
        # Fetch results
        import asyncio; await asyncio.sleep(2)
        r2 = await client.get(f"https://2.intelx.io/intelligent/search/result",
            headers={"x-key": api_key},
            params={"id": search_id, "limit": 10}, timeout=15.0)
        if r2.status_code != 200: return []
        records = r2.json().get("records", []) or []
        return [{"title": rec.get("name","")[:200], "url": "", "source": "intelx",
                 "date": rec.get("date","")} for rec in records[:10]]
    except Exception as e:
        logger.debug(f"IntelX error: {e}"); return []

async def run_collection() -> dict:
    darksearch_key = getattr(settings, "DARKSEARCH_API_KEY", "") or ""
    intelx_key = getattr(settings, "INTELX_API_KEY", "") or ""
    stats = {"assets_checked": 0, "hits": 0, "new": 0, "skipped": 0}

    async with async_session() as db:
        r = await db.execute(select(CustomerAsset).where(
            CustomerAsset.asset_type.in_(["domain", "org_name", "keyword"])))
        assets = r.scalars().all()
        r2 = await db.execute(select(Customer))
        customers = {c.id: c for c in r2.scalars().all()}

        async with httpx.AsyncClient(timeout=20.0) as client:
            for asset in assets[:20]:  # cap to avoid hammering
                val = asset.asset_value
                stats["assets_checked"] += 1
                results = []
                results += await search_ahmia(val, client)
                results += await search_darksearch(val, darksearch_key, client)
                results += await search_intelx(val, intelx_key, client)

                for res in results:
                    title = res.get("title","")
                    if not title or val.lower() not in title.lower(): continue
                    # Check duplicate
                    r3 = await db.execute(select(DarkWebMention).where(
                        DarkWebMention.title == title[:499],
                        DarkWebMention.source == res["source"]))
                    if r3.scalar_one_or_none():
                        stats["skipped"] += 1; continue
                    stats["hits"] += 1
                    db.add(DarkWebMention(
                        source=res["source"], mention_type="dark_web_mention",
                        title=title[:499], url=res.get("url","")[:500],
                        customer_id=asset.customer_id,
                        threat_actor="", severity=SeverityLevel.HIGH,
                        metadata_={"search_term": val, "asset_type": asset.asset_type,
                                   "date": res.get("date","")},
                    ))
                    stats["new"] += 1

        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"DarkSearch ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.darksearch_collector.collect_darksearch")
def collect_darksearch():
    async def _wrapped():
        async with record_collector_run("darksearch") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
