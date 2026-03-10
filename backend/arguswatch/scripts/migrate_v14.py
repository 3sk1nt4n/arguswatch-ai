"""Run V14 migrations - 3-class IOC model tables."""
import asyncio, logging
from arguswatch.database import async_session
from sqlalchemy import text

logger = logging.getLogger("migrate_v14")

MIGRATIONS = [
    # Global threat activity
    """CREATE TABLE IF NOT EXISTS global_threat_activity (
        id SERIAL PRIMARY KEY,
        malware_family VARCHAR(255),
        category VARCHAR(100) NOT NULL,
        targeted_sectors JSONB DEFAULT '[]',
        affected_products JSONB DEFAULT '[]',
        activity_level FLOAT DEFAULT 0.0,
        ioc_count INTEGER DEFAULT 0,
        sources JSONB DEFAULT '[]',
        first_seen TIMESTAMP DEFAULT NOW(),
        last_seen TIMESTAMP DEFAULT NOW(),
        window_start TIMESTAMP,
        window_end TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    )""",
    "CREATE INDEX IF NOT EXISTS ix_gta_category ON global_threat_activity(category)",
    "CREATE INDEX IF NOT EXISTS ix_gta_malware ON global_threat_activity(malware_family)",
    # Probable exposures
    """CREATE TABLE IF NOT EXISTS probable_exposures (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
        exposure_type VARCHAR(50) NOT NULL,
        source_detail VARCHAR(500),
        product_name VARCHAR(255),
        cve_id VARCHAR(30),
        confidence FLOAT DEFAULT 0.5,
        risk_points FLOAT DEFAULT 0.0,
        last_calculated TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
    )""",
    "CREATE INDEX IF NOT EXISTS ix_pe_customer ON probable_exposures(customer_id)",
    "CREATE INDEX IF NOT EXISTS ix_pe_type ON probable_exposures(exposure_type)",
    # New columns
    "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS tech_risk_baseline FLOAT DEFAULT 0.0",
    "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS manual_entry BOOLEAN DEFAULT false",
]

async def run():
    async with async_session() as db:
        for sql in MIGRATIONS:
            try:
                await db.execute(text(sql))
            except Exception as e:
                logger.debug(f"Migration skip: {e}")
        await db.commit()
    print("[migrate_v14] Done - global_threat_activity + probable_exposures created")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
