"""cyware_taxii enterprise collector - key-activated stub."""
import logging
from arguswatch.config import settings
logger = logging.getLogger("arguswatch.collectors.enterprise.cyware_taxii")

async def run_collection() -> dict:
    return {"status": "inactive", "reason": "cyware_taxii: enterprise license required - add key to .env to activate"}
