"""GitHub Secret Leak Collector - searches for exposed credentials in public repos."""
import httpx, logging, re
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus
from arguswatch.config import settings
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.github")
GH_SEARCH = "https://api.github.com/search/code"

SECRET_QUERIES = [
    ("AKIAIOSFODNN7EXAMPLE OR AKIA extension:env OR extension:yml", "aws_access_key"),
    ("ghp_ extension:txt OR extension:env", "github_pat"),
    ("xoxb- extension:env OR extension:config", "slack_token"),
    ("BEGIN RSA PRIVATE KEY extension:pem OR extension:key", "private_key"),
]

async def run_collection() -> dict:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"
    stats = {"queries": 0, "new": 0, "skipped": 0}
    async with async_session() as db:
        async with httpx.AsyncClient(timeout=20.0, headers=headers) as client:
            for query, ioc_type in SECRET_QUERIES[:2]:  # conservative: 2 queries
                try:
                    resp = await client.get(GH_SEARCH, params={"q": query, "per_page": 20})
                    if resp.status_code in (403, 429, 422):
                        logger.info(f"GitHub rate limit or auth required for: {query[:30]}")
                        continue
                    resp.raise_for_status()
                    data = resp.json()
                    stats["queries"] += 1
                except Exception as e:
                    logger.warning(f"GitHub query error: {e}"); continue
                for item in data.get("items", []):
                    repo_url = item.get("html_url", "")
                    if not repo_url: continue
                    r = await db.execute(select(Detection).where(Detection.ioc_value == repo_url, Detection.source == "github"))
                    if r.scalar_one_or_none():
                        stats["skipped"] += 1; continue
                    db.add(Detection(
                        source="github", ioc_type=ioc_type, ioc_value=repo_url,
                        raw_text=f"Possible {ioc_type} leak in: {item.get('repository', {}).get('full_name', '')}",
                        severity=SeverityLevel.CRITICAL, sla_hours=4,
                        status=DetectionStatus.NEW, confidence=0.7,
                        metadata_={"repo": item.get("repository", {}).get("full_name", ""),
                                   "file": item.get("name", ""), "query": query[:100]},
                    ))
                    stats["new"] += 1
        await db.commit()
    return stats

@celery_app.task(name="arguswatch.collectors.github_collector.collect_github")
def collect_github():
    import asyncio
    async def _wrapped():
        async with record_collector_run("github") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
