"""Telegram Collector - MTProto real-time monitoring via Telethon.
Requires TELEGRAM_API_ID + TELEGRAM_API_HASH in .env.
Degrades gracefully when credentials absent - logs info, returns empty.
Target channels configured in TELEGRAM_CHANNELS env var (comma-separated).
"""
import asyncio, logging, os
from datetime import datetime, timedelta
from arguswatch.config import settings
from arguswatch.database import async_session
from arguswatch.models import Detection, SeverityLevel, DetectionStatus
from arguswatch.engine.pattern_matcher import scan_text
from arguswatch.engine.severity_scorer import score as score_ioc
from arguswatch.celery_app import celery_app
from arguswatch.collectors._pipeline_hook import trigger_pipeline_for_new, record_collector_run
from sqlalchemy import select

logger = logging.getLogger("arguswatch.collectors.telegram")

# Default high-value public intel channels
DEFAULT_CHANNELS = [
    "darkwebinformer", "ransomwaretracker", "breachdetector",
    "cybersecuritynews", "hacknews", "leakbase",
]

async def run_collection() -> dict:
    api_id = getattr(settings, "TELEGRAM_API_ID", "") or os.getenv("TELEGRAM_API_ID", "")
    api_hash = getattr(settings, "TELEGRAM_API_HASH", "") or os.getenv("TELEGRAM_API_HASH", "")
    if not api_id or not api_hash:
        logger.info("Telegram: TELEGRAM_API_ID/HASH not set - skipping (add to .env to activate)")
        return {"skipped": "no_credentials", "note": "Add TELEGRAM_API_ID and TELEGRAM_API_HASH to .env"}
    try:
        from telethon import TelegramClient
        from telethon.errors import SessionPasswordNeededError
    except ImportError:
        return {"skipped": "telethon_not_installed", "note": "pip install telethon"}

    channels_env = os.getenv("TELEGRAM_CHANNELS", "")
    channels = [c.strip() for c in channels_env.split(",")] if channels_env else DEFAULT_CHANNELS
    stats = {"channels_checked": 0, "messages_scanned": 0, "iocs_found": 0, "new": 0, "skipped": 0}
    since = datetime.utcnow() - timedelta(hours=2)

    try:
        client = TelegramClient("arguswatch_session", int(api_id), api_hash)
        await client.start()
        async with async_session() as db:
            for channel in channels:
                try:
                    entity = await client.get_entity(channel)
                    stats["channels_checked"] += 1
                    async for msg in client.iter_messages(entity, limit=50, offset_date=since):
                        if not msg.text: continue
                        stats["messages_scanned"] += 1
                        matches = scan_text(msg.text)
                        for m in matches:
                            if m.confidence < 0.75: continue
                            stats["iocs_found"] += 1
                            r = await db.execute(select(Detection).where(
                                Detection.ioc_value == m.value, Detection.source == "telegram"))
                            if r.scalar_one_or_none():
                                stats["skipped"] += 1; continue
                            s = score_ioc(m.category, m.ioc_type, confidence=m.confidence)
                            db.add(Detection(
                                source="telegram", ioc_type=m.ioc_type, ioc_value=m.value,
                                raw_text=m.context[:500],
                                severity=getattr(SeverityLevel, s.severity),
                                sla_hours=s.sla_hours, status=DetectionStatus.NEW,
                                confidence=m.confidence,
                                metadata_={"channel": channel, "message_id": msg.id,
                                           "date": msg.date.isoformat() if msg.date else "",
                                           "category": m.category},
                            ))
                            stats["new"] += 1
                except Exception as e:
                    logger.warning(f"Telegram channel {channel} error: {e}")
            await db.commit()
            await trigger_pipeline_for_new(db)
        await client.disconnect()
    except Exception as e:
        logger.error(f"Telegram collector error: {e}")
        return {"error": str(e)}
    logger.info(f"Telegram ingest: {stats}")
    return stats

@celery_app.task(name="arguswatch.collectors.telegram_collector.collect_telegram")
def collect_telegram():
    async def _wrapped():
        async with record_collector_run("telegram") as ctx:
            result = await run_collection()
            ctx["stats"] = result
        return result
    return asyncio.run(_wrapped())
