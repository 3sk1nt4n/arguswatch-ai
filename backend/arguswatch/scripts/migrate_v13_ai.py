"""
V13 AI migration - adds AI columns to findings and campaigns tables.
Safe to run multiple times (uses IF NOT EXISTS).
"""
import asyncio, logging
from arguswatch.database import async_session
from sqlalchemy import text

logger = logging.getLogger("migrate_v13_ai")

FINDING_COLS = [
    ("ai_severity_decision",    "VARCHAR(20)"),
    ("ai_severity_reasoning",   "TEXT"),
    ("ai_severity_confidence",  "FLOAT"),
    ("ai_rescore_decision",     "VARCHAR(20)"),
    ("ai_rescore_reasoning",    "TEXT"),
    ("ai_rescore_confidence",   "FLOAT"),
    ("ai_narrative",            "TEXT"),
    ("ai_attribution_reasoning","TEXT"),
    ("ai_false_positive_flag",  "BOOLEAN DEFAULT FALSE"),
    ("ai_false_positive_reason","TEXT"),
    ("ai_enriched_at",          "TIMESTAMP"),
    ("ai_provider",             "VARCHAR(50)"),
]

CAMPAIGN_COLS = [
    ("ai_narrative", "TEXT"),
]

async def migrate():
    async with async_session() as db:
        for col, typ in FINDING_COLS:
            try:
                await db.execute(text(f"ALTER TABLE findings ADD COLUMN IF NOT EXISTS {col} {typ}"))
                logger.info(f"findings.{col} OK")
            except Exception as e:
                logger.warning(f"findings.{col}: {e}")

        for col, typ in CAMPAIGN_COLS:
            try:
                await db.execute(text(f"ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS {col} {typ}"))
                logger.info(f"campaigns.{col} OK")
            except Exception as e:
                logger.warning(f"campaigns.{col}: {e}")

        await db.commit()
        print("✓ V13 AI migration complete")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(migrate())
