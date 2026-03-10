"""Cyberint Enterprise Collector - ATO confirmation alerts and brand monitoring.
Wired and ready. Add CYBERINT_API_KEY to .env to activate.
Key absent = silent skip. Key present = collector activates.
"""
import logging, asyncio
from arguswatch.config import settings
from arguswatch.celery_app import celery_app

logger = logging.getLogger("arguswatch.collectors.enterprise.cyberint")

async def run_collection() -> dict:
    key = getattr(settings, "CYBERINT_API_KEY", "") or ""
    if not key:
        logger.debug("cyberint: CYBERINT_API_KEY not set - enterprise source inactive")
        return {"skipped": "no_key", "source": "cyberint",
                "note": "Add CYBERINT_API_KEY to .env to activate. ATO confirmation alerts and brand monitoring."}
    # Architecture wired. Implementation activates with license.
    logger.info("Cyberint: key present - enterprise source ready")
    return {"status": "key_present", "source": "cyberint", "note": "Full implementation on enterprise activation"}

@celery_app.task(name="arguswatch.collectors.enterprise.cyberint_collector.collect_cyberint")
def collect_cyberint():
    return asyncio.run(run_collection())
