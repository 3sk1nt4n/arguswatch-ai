"""Grep.app - search all public GitHub in real-time.
Zero auth. Faster than GitHub's own search for exposed secrets.
"""
import httpx, logging, asyncio
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus, CustomerAsset
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run
from arguswatch.engine.severity_scorer import score as score_ioc
from sqlalchemy import select

logger = logging.getLogger("arguswatch.collectors.grep")

GREP_BASE = "https://grep.app/api/search"

SEARCH_TEMPLATES = [
    "{domain} password",
    "{domain} api_key",
    "{domain} secret",
    "{domain} token",
    "{email_domain} credentials",
]

async def grep_search(query: str, client: httpx.AsyncClient) -> list[dict]:
    try:
        resp = await client.get(GREP_BASE, params={"q": query, "regexp": "false"},
            headers={"User-Agent": "ArgusWatch/8.0"}, timeout=15.0)
        if resp.status_code != 200:
            return []
        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])
        results = []
        for h in hits[:5]:
            repo = h.get("repo", {}).get("raw", "")
            file_path = h.get("path", {}).get("raw", "")
            snippet = h.get("content", {}).get("snippet", "")
            results.append({
                "repo": repo,
                "file": file_path,
                "url": f"https://github.com/{repo}/blob/HEAD/{file_path}",
                "snippet": snippet[:300],
            })
        return results
    except Exception as e:
        logger.debug(f"Grep.app error: {e}")
        return []

async def run_collection() -> dict:
    stats = {"searched": 0, "new": 0, "skipped": 0}

    async with async_session() as db:
        r = await db.execute(select(CustomerAsset).where(
            CustomerAsset.asset_type.in_(["domain", "email_pattern", "keyword"])))
        assets = r.scalars().all()

        async with httpx.AsyncClient(timeout=20.0) as client:
            seen_repos = set()
            for asset in assets[:10]:  # Rate limit
                val = asset.asset_value.replace("@", "").strip(".")
                for template in SEARCH_TEMPLATES[:2]:
                    query = template.format(domain=val, email_domain=val)
                    results = await grep_search(query, client)
                    for res in results:
                        repo = res["repo"]
                        if repo in seen_repos:
                            continue
                        seen_repos.add(repo)
                        ioc_val = f"grep:{repo}:{res['file']}"[:200]
                        r2 = await db.execute(select(Detection).where(
                            Detection.ioc_value == ioc_val, Detection.source == "grep"))
                        if r2.scalar_one_or_none():
                            stats["skipped"] += 1
                            continue
                        stats["searched"] += 1
                        db.add(Detection(
                            source="grep", ioc_type="infra_code_leaks",
                            ioc_value=ioc_val,
                            raw_text=f"Grep.app: {val} found in {repo}/{res['file']}\n{res['snippet']}",
                            severity=SeverityLevel.HIGH, sla_hours=2,
                            status=DetectionStatus.NEW, confidence=0.80,
                            customer_id=asset.customer_id,
                            matched_asset=asset.asset_value,
                            metadata_={"repo": repo, "file": res["file"],
                                       "url": res["url"], "query": query},
                        ))
                        stats["new"] += 1

        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"Grep.app ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.grep_collector.collect_grep")
def collect_grep():
    async def _wrapped():
        async with record_collector_run("grep") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
