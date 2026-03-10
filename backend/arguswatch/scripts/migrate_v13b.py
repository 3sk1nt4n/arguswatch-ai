"""
V13b migration - adds onboarding state + asset confidence columns.
Safe to run multiple times (uses IF NOT EXISTS).
"""
import asyncio, logging
from arguswatch.database import async_session
from sqlalchemy import text

logger = logging.getLogger("migrate_v13b")

CUSTOMER_COLS = [
    ("onboarding_state",       "VARCHAR(30) DEFAULT 'created'"),
    ("onboarding_updated_at",  "TIMESTAMP"),
]

ASSET_COLS = [
    ("confidence",             "FLOAT DEFAULT 1.0"),
    ("confidence_sources",     "JSONB DEFAULT '[]'"),
    ("discovery_source",       "VARCHAR(100)"),
    ("last_seen_in_ioc",       "TIMESTAMP"),
    ("ioc_hit_count",          "INTEGER DEFAULT 0"),
]

async def migrate():
    async with async_session() as db:
        for col, typ in CUSTOMER_COLS:
            try:
                await db.execute(text(f"ALTER TABLE customers ADD COLUMN IF NOT EXISTS {col} {typ}"))
                logger.info(f"customers.{col} OK")
            except Exception as e:
                logger.warning(f"customers.{col}: {e}")

        for col, typ in ASSET_COLS:
            try:
                await db.execute(text(f"ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS {col} {typ}"))
                logger.info(f"customer_assets.{col} OK")
            except Exception as e:
                logger.warning(f"customer_assets.{col}: {e}")

        await db.commit()
        logger.info("V13b migration complete")


def main():
    logging.basicConfig(level=logging.INFO)
    asyncio.run(migrate())


if __name__ == "__main__":
    main()
