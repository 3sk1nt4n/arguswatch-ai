"""crowdstrike enterprise collector - key-activated stub."""
import logging
from arguswatch.config import settings
logger = logging.getLogger("arguswatch.collectors.enterprise.crowdstrike")

async def run_collection() -> dict:
    return {"status": "inactive", "reason": "crowdstrike: enterprise license required - add key to .env to activate"}
