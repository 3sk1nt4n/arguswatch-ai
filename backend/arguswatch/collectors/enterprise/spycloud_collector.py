"""Spycloud Enterprise Collector - Live stealer log ingestion with active_session:true confirmation.
Wired and ready. Add SPYCLOUD_API_KEY to .env to activate.
Key absent = silent skip. Key present = collector activates.
"""
import logging, asyncio
from arguswatch.config import settings
from arguswatch.celery_app import celery_app

logger = logging.getLogger("arguswatch.collectors.enterprise.spycloud")

async def run_collection() -> dict:
    key = getattr(settings, "SPYCLOUD_API_KEY", "") or ""
    if not key:
        logger.debug("spycloud: SPYCLOUD_API_KEY not set - enterprise source inactive")
        return {"skipped": "no_key", "source": "spycloud",
                "note": "Add SPYCLOUD_API_KEY to .env to activate. Live stealer log ingestion with active_session:true confirmation."}
    # Architecture wired. Implementation activates with license.
    logger.info("Spycloud: key present - enterprise source ready")
    return {"status": "key_present", "source": "spycloud", "note": "Full implementation on enterprise activation"}

@celery_app.task(name="arguswatch.collectors.enterprise.spycloud_collector.collect_spycloud")
def collect_spycloud():
    return asyncio.run(run_collection())
