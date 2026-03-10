"""VX-Underground + DarkFeed Collector.
VX-Underground: malware source, threat actor profiles, campaign docs.
DarkFeed: ransomware group tracking (free tier).
Both zero/free auth.
"""
import httpx, logging, asyncio, re, feedparser
from datetime import datetime
from sqlalchemy import select
from arguswatch.database import async_session
from arguswatch.models import Detection, DarkWebMention, SeverityLevel, DetectionStatus, CustomerAsset, Customer
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run

logger = logging.getLogger("arguswatch.collectors.vxug_darkfeed")

VXUG_SAMPLES_RSS = "https://vx-underground.org/samples.rss"
VXUG_PAPERS_RSS = "https://vx-underground.org/papers.rss"
DARKFEED_RSS = "https://darkfeed.io/feed/"

# Known ransomware groups to track for customer mentions
RANSOMWARE_GROUPS = [
    "lockbit", "alphv", "blackcat", "clop", "akira", "play", "black basta",
    "ransomhouse", "revil", "conti", "darkside", "hive", "noname057",
    "killnet", "rhysida", "medusa", "bianlian", "hunters international",
    "8base", "qilin", "meow", "dragonforce",
]


async def _fetch_rss(url: str, client: httpx.AsyncClient) -> list[dict]:
    try:
        resp = await client.get(url, timeout=20.0, headers={"User-Agent": "ArgusWatch/8.0"})
        if resp.status_code != 200:
            return []
        feed = feedparser.parse(resp.text)
        items = []
        for entry in feed.entries[:30]:
            items.append({
                "title": entry.get("title", ""),
                "summary": entry.get("summary", entry.get("description", ""))[:500],
                "link": entry.get("link", ""),
                "published": entry.get("published", ""),
            })
        return items
    except Exception as e:
        logger.debug(f"RSS fetch error ({url}): {e}")
        return []


def _customer_mentioned(text: str, customer_assets: list) -> tuple[bool, str]:
    text_lower = text.lower()
    for asset in customer_assets:
        val = asset.asset_value.lower()
        if val in text_lower:
            return True, asset.asset_value
    return False, ""


def _extract_ransomware_group(text: str) -> str:
    text_lower = text.lower()
    for group in RANSOMWARE_GROUPS:
        if group in text_lower:
            return group.title()
    return ""


async def run_collection() -> dict:
    stats = {"vxug_items": 0, "darkfeed_items": 0, "new": 0, "skipped": 0}

    async with async_session() as db:
        r = await db.execute(select(Customer).where(Customer.active == True))
        customers = r.scalars().all()

        customer_assets_map = {}
        for customer in customers:
            ra = await db.execute(select(CustomerAsset).where(
                CustomerAsset.customer_id == customer.id))
            customer_assets_map[customer.id] = ra.scalars().all()

        async with httpx.AsyncClient(timeout=25.0) as client:
            # ── VX-Underground ──
            vx_items = await _fetch_rss(VXUG_SAMPLES_RSS, client)
            vx_items += await _fetch_rss(VXUG_PAPERS_RSS, client)
            stats["vxug_items"] = len(vx_items)

            for item in vx_items:
                full_text = f"{item['title']} {item['summary']}"
                group = _extract_ransomware_group(full_text)

                for customer in customers:
                    assets = customer_assets_map.get(customer.id, [])
                    # Match if customer name is mentioned OR ransomware targets their sector
                    matched, matched_asset = _customer_mentioned(full_text, assets)
                    if not matched and not group:
                        continue

                    det_key = f"vxug-{hash(item['link']+str(customer.id))}"
                    rd = await db.execute(select(Detection).where(Detection.ioc_value == det_key))
                    if rd.scalar_one_or_none():
                        stats["skipped"] += 1
                        continue

                    sev = SeverityLevel.HIGH if matched else SeverityLevel.MEDIUM
                    db.add(Detection(
                        source="vx_underground",
                        ioc_type="threat_actor_intel",
                        ioc_value=det_key,
                        customer_id=customer.id if matched else None,
                        matched_asset=matched_asset or "",
                        raw_text=f"VX-Underground: {item['title'][:200]}",
                        severity=sev,
                        sla_hours=24,
                        status=DetectionStatus.NEW,
                        confidence=0.68,
                        metadata_={
                            "title": item["title"],
                            "summary": item["summary"][:300],
                            "link": item["link"],
                            "group": group,
                            "published": item["published"],
                        },
                    ))
                    stats["new"] += 1
                    if matched:
                        break  # Only add once per article

            # ── DarkFeed ──
            darkfeed_items = await _fetch_rss(DARKFEED_RSS, client)
            stats["darkfeed_items"] = len(darkfeed_items)

            for item in darkfeed_items:
                full_text = f"{item['title']} {item['summary']}"
                group = _extract_ransomware_group(full_text)

                for customer in customers:
                    assets = customer_assets_map.get(customer.id, [])
                    matched, matched_asset = _customer_mentioned(full_text, assets)
                    if not matched:
                        continue

                    det_key = f"darkfeed-{hash(item['link']+str(customer.id))}"
                    rd = await db.execute(select(Detection).where(Detection.ioc_value == det_key))
                    if rd.scalar_one_or_none():
                        stats["skipped"] += 1
                        continue

                    # Add as both Detection and DarkWebMention
                    db.add(Detection(
                        source="darkfeed",
                        ioc_type="threat_actor_intel",
                        ioc_value=det_key,
                        customer_id=customer.id,
                        matched_asset=matched_asset,
                        raw_text=f"DarkFeed [{group or 'ransomware'}]: {item['title'][:200]}",
                        severity=SeverityLevel.HIGH,
                        sla_hours=4,
                        status=DetectionStatus.NEW,
                        confidence=0.78,
                        metadata_={
                            "title": item["title"],
                            "group": group,
                            "link": item["link"],
                            "published": item["published"],
                        },
                    ))

                    db.add(DarkWebMention(
                        source="darkfeed",
                        mention_type="ransomware_leak",
                        title=item["title"][:499],
                        url=item["link"][:500],
                        customer_id=customer.id,
                        threat_actor=group,
                        severity=SeverityLevel.HIGH,
                        metadata_={"published": item["published"]},
                    ))
                    stats["new"] += 1

        await db.commit()
        await trigger_pipeline_for_new(db)
    logger.info(f"VX-Underground/DarkFeed ingest: {stats}")
    return stats


@celery_app.task(name="arguswatch.collectors.vxug_darkfeed.collect_vxug_darkfeed")
def collect_vxug_darkfeed():
    async def _wrapped():
        async with record_collector_run("vxug_darkfeed") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
