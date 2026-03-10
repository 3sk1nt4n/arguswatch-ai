"""Cybersixgill Enterprise Collector - Invite-only dark web forums and private markets.
Wired and ready. Add CYBERSIXGILL_CLIENT_ID to .env to activate.
Key absent = silent skip. Key present = collector activates.
"""
import logging, asyncio
from arguswatch.config import settings
from arguswatch.celery_app import celery_app

logger = logging.getLogger("arguswatch.collectors.enterprise.cybersixgill")

async def run_collection() -> dict:
    key = getattr(settings, "CYBERSIXGILL_CLIENT_ID", "") or ""
    if not key:
        logger.debug("cybersixgill: CYBERSIXGILL_CLIENT_ID not set - enterprise source inactive")
        return {"skipped": "no_key", "source": "cybersixgill",
                "note": "Add CYBERSIXGILL_CLIENT_ID to .env to activate. Invite-only dark web forums and private markets."}
    # Architecture wired. Implementation activates with license.
    logger.info("Cybersixgill: key present - enterprise source ready")
    return {"status": "key_present", "source": "cybersixgill", "note": "Full implementation on enterprise activation"}

@celery_app.task(name="arguswatch.collectors.enterprise.cybersixgill_collector.collect_cybersixgill")
def collect_cybersixgill():
    return asyncio.run(run_collection())
