"""RansomFeed Collector - live ransomware victim leaks (free, no key)."""
import httpx, logging
from datetime import datetime
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import DarkWebMention, SeverityLevel
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.ransomfeed")

RANSOMFEED_URL = "https://ransomfeed.it/api/v2/posts/?limit=100&ordering=-published"

async def run_collection() -> dict:
    try:
        async with httpx.AsyncClient(timeout=30.0, headers={"User-Agent": "ArgusWatch/7.0"}) as client:
            resp = await client.get(RANSOMFEED_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.warning(f"RansomFeed fetch error: {e}")
        return {"error": str(e)}
    posts = data.get("results", data) if isinstance(data, dict) else data
    stats = {"total": len(posts), "new": 0, "skipped": 0}
    async with async_session() as db:
        for post in posts:
            url = post.get("post_url") or post.get("url") or ""
            title = post.get("victim") or post.get("title") or ""
            actor = post.get("group_name") or post.get("actor") or ""
            if not title: continue
            r = await db.execute(select(DarkWebMention).where(DarkWebMention.url == url, DarkWebMention.source == "ransomfeed"))
            if r.scalar_one_or_none():
                stats["skipped"] += 1; continue
            published = None
            try:
                ts = post.get("published") or post.get("date")
                if ts: published = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception: pass
            db.add(DarkWebMention(
                source="ransomfeed", mention_type="ransomware_leak",
                title=title[:499], url=url, threat_actor=actor,
                content_snippet=post.get("description", "")[:1000],
                severity=SeverityLevel.CRITICAL, published_at=published,
                metadata_={"sector": post.get("sector", ""), "country": post.get("country", ""),
                           "data_size": post.get("data_size", ""), "group": actor},
            ))
            stats["new"] += 1
        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"RansomFeed ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.ransomfeed_collector.collect_ransomfeed")
def collect_ransomfeed():
    import asyncio
    async def _wrapped():
        async with record_collector_run("ransomfeed") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
