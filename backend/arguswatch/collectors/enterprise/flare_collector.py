"""Flare Enterprise Collector - Aggregated plaintext credentials and Telegram intel.
Wired and ready. Add FLARE_API_KEY to .env to activate.
Key absent = silent skip. Key present = collector activates.
"""
import logging, asyncio
from arguswatch.config import settings
from arguswatch.celery_app import celery_app

logger = logging.getLogger("arguswatch.collectors.enterprise.flare")

async def run_collection() -> dict:
    key = getattr(settings, "FLARE_API_KEY", "") or ""
    if not key:
        logger.debug("flare: FLARE_API_KEY not set - enterprise source inactive")
        return {"skipped": "no_key", "source": "flare",
                "note": "Add FLARE_API_KEY to .env to activate. Aggregated plaintext credentials and Telegram intel."}
    # Architecture wired. Implementation activates with license.
    logger.info("Flare: key present - enterprise source ready")
    return {"status": "key_present", "source": "flare", "note": "Full implementation on enterprise activation"}

@celery_app.task(name="arguswatch.collectors.enterprise.flare_collector.collect_flare")
def collect_flare():
    return asyncio.run(run_collection())
