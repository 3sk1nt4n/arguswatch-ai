"""Run V15 migrations - eTLD+1 normalization, feed confidence, product aliases, EDR telemetry."""
import asyncio, logging, os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

logger = logging.getLogger("migrate_v15")

async def run():
    from arguswatch.database import async_session
    sql_path = os.path.join(os.path.dirname(__file__), "../../initdb/06_migrate_v15.sql")
    if not os.path.exists(sql_path):
        # Try alternate location
        for p in ["/app/initdb/06_migrate_v15.sql", "initdb/06_migrate_v15.sql"]:
            if os.path.exists(p):
                sql_path = p
                break

    # Run individual statements from the SQL file
    migrations = [
        "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS normalized_domain VARCHAR(255)",
        "CREATE INDEX IF NOT EXISTS ix_ca_normdomain ON customer_assets(normalized_domain)",
        "ALTER TABLE detections ADD COLUMN IF NOT EXISTS normalized_domain VARCHAR(255)",
        "CREATE INDEX IF NOT EXISTS ix_det_normdomain ON detections(normalized_domain)",
        "ALTER TABLE detections ADD COLUMN IF NOT EXISTS feed_confidence FLOAT DEFAULT 0.7",
        "ALTER TABLE detections ADD COLUMN IF NOT EXISTS feed_freshness_ts TIMESTAMP",
        "ALTER TABLE detections ADD COLUMN IF NOT EXISTS normalized_score FLOAT",
        "ALTER TABLE detections ADD COLUMN IF NOT EXISTS match_proof JSONB",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS match_proof JSONB",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS enrichment_narrative TEXT",
        "ALTER TABLE collector_runs ADD COLUMN IF NOT EXISTS iocs_inserted INTEGER DEFAULT 0",
        "ALTER TABLE collector_runs ADD COLUMN IF NOT EXISTS duration_seconds FLOAT",
        "ALTER TABLE collector_runs ADD COLUMN IF NOT EXISTS error_detail TEXT",
        """CREATE TABLE IF NOT EXISTS product_aliases (
            id SERIAL PRIMARY KEY,
            alias VARCHAR(255) NOT NULL UNIQUE,
            canonical VARCHAR(255) NOT NULL,
            vendor VARCHAR(255))""",
        """CREATE TABLE IF NOT EXISTS edr_telemetry (
            id SERIAL PRIMARY KEY,
            customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
            hostname VARCHAR(255),
            file_path VARCHAR(1000),
            hash_sha256 VARCHAR(64),
            hash_md5 VARCHAR(32),
            process_name VARCHAR(255),
            seen_at TIMESTAMP DEFAULT NOW(),
            source VARCHAR(100) DEFAULT 'edr_agent',
            metadata JSONB DEFAULT '{}',
            created_at TIMESTAMP DEFAULT NOW())""",
        "CREATE INDEX IF NOT EXISTS ix_edr_hash256 ON edr_telemetry(hash_sha256)",
        "CREATE INDEX IF NOT EXISTS ix_edr_hash_md5 ON edr_telemetry(hash_md5)",
        "CREATE INDEX IF NOT EXISTS ix_edr_customer ON edr_telemetry(customer_id)",
    ]

    async with async_session() as db:
        for sql in migrations:
            try:
                await db.execute(text(sql))
            except Exception as e:
                logger.debug(f"Migration skip: {e}")
        await db.commit()
    print("[migrate_v15] Done - normalized_domain, feed_confidence, product_aliases, edr_telemetry")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
