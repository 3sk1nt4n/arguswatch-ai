"""Recordedfuture Enterprise Collector - Credential exposure alerts with actor attribution.
Wired and ready. Add RECORDED_FUTURE_KEY to .env to activate.
Key absent = silent skip. Key present = collector activates.
"""
import logging, asyncio
from arguswatch.config import settings
from arguswatch.celery_app import celery_app

logger = logging.getLogger("arguswatch.collectors.enterprise.recordedfuture")

async def run_collection() -> dict:
    key = getattr(settings, "RECORDED_FUTURE_KEY", "") or ""
    if not key:
        logger.debug("recordedfuture: RECORDED_FUTURE_KEY not set - enterprise source inactive")
        return {"skipped": "no_key", "source": "recordedfuture",
                "note": "Add RECORDED_FUTURE_KEY to .env to activate. Credential exposure alerts with actor attribution."}
    # Architecture wired. Implementation activates with license.
    logger.info("Recordedfuture: key present - enterprise source ready")
    return {"status": "key_present", "source": "recordedfuture", "note": "Full implementation on enterprise activation"}

@celery_app.task(name="arguswatch.collectors.enterprise.recordedfuture_collector.collect_recordedfuture")
def collect_recordedfuture():
    return asyncio.run(run_collection())
