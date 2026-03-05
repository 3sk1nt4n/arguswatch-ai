"""V16.4 Migration - fixes AssetType enum gap, adds match_proof and manual_entry columns,
plus all Agentic AI tables (FP Memory, Sector Advisories, Dark Web Triage).

Run: python -m arguswatch.scripts.migrate_v16_4
Or applied automatically via initdb/08_migrate_v16_4.sql on fresh deploy.
"""
import asyncio
from sqlalchemy import text
from arguswatch.database import async_session


async def migrate():
    async with async_session() as db:
        # Expand assettype enum
        for val in ("aws_account", "azure_tenant", "gcp_project", "internal_domain"):
            try:
                exists = await db.execute(text(
                    "SELECT 1 FROM pg_enum WHERE enumlabel = :v "
                    "AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'assettype')"
                ), {"v": val})
                if not exists.scalar():
                    await db.execute(text(f"ALTER TYPE assettype ADD VALUE '{val}'"))
                    print(f"  Added assettype value: {val}")
            except Exception as e:
                print(f"  Enum {val}: {e}")

        await db.commit()

        # Add columns + tables (separate transaction - enum ADD VALUE requires commit first)
        async with async_session() as db2:
            ddl_statements = [
                # Bug fix columns
                "ALTER TABLE detections ADD COLUMN IF NOT EXISTS match_proof JSONB DEFAULT '{}'",
                "ALTER TABLE customer_assets ADD COLUMN IF NOT EXISTS manual_entry BOOLEAN DEFAULT FALSE",
                # Agentic AI: Dark Web Triage
                "ALTER TABLE darkweb_mentions ADD COLUMN IF NOT EXISTS triage_classification VARCHAR(50)",
                "ALTER TABLE darkweb_mentions ADD COLUMN IF NOT EXISTS triage_action VARCHAR(50)",
                "ALTER TABLE darkweb_mentions ADD COLUMN IF NOT EXISTS triage_narrative TEXT",
                "ALTER TABLE darkweb_mentions ADD COLUMN IF NOT EXISTS triaged_at TIMESTAMP",
                # Agentic AI: Exposure Narrative
                "ALTER TABLE customer_exposure ADD COLUMN IF NOT EXISTS score_narrative TEXT",
                # Agentic AI: FP Memory
                """CREATE TABLE IF NOT EXISTS fp_patterns (
                    id SERIAL PRIMARY KEY,
                    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
                    ioc_type VARCHAR(50) NOT NULL,
                    ioc_value_pattern TEXT NOT NULL,
                    match_type VARCHAR(20) DEFAULT 'exact',
                    source VARCHAR(100),
                    reason TEXT,
                    confidence FLOAT DEFAULT 0.9,
                    hit_count INTEGER DEFAULT 1,
                    last_hit_at TIMESTAMP,
                    created_by VARCHAR(100) DEFAULT 'analyst',
                    created_at TIMESTAMP DEFAULT NOW()
                )""",
                "CREATE INDEX IF NOT EXISTS ix_fp_customer_type ON fp_patterns(customer_id, ioc_type)",
                # Agentic AI: Sector Advisories
                """CREATE TABLE IF NOT EXISTS sector_advisories (
                    id SERIAL PRIMARY KEY,
                    ioc_value TEXT NOT NULL,
                    ioc_type VARCHAR(50) NOT NULL,
                    affected_customer_count INTEGER DEFAULT 0,
                    affected_industries JSONB DEFAULT '[]',
                    affected_customer_ids JSONB DEFAULT '[]',
                    severity severitylevel DEFAULT 'HIGH',
                    classification VARCHAR(50),
                    ai_narrative TEXT,
                    ai_recommended_actions JSONB DEFAULT '[]',
                    status VARCHAR(30) DEFAULT 'active',
                    window_start TIMESTAMP,
                    window_end TIMESTAMP,
                    created_at TIMESTAMP DEFAULT NOW()
                )""",
                "CREATE INDEX IF NOT EXISTS ix_sector_adv_created ON sector_advisories(created_at)",
            ]
            for stmt in ddl_statements:
                try:
                    await db2.execute(text(stmt))
                except Exception as e:
                    print(f"  DDL warning: {str(e)[:80]}")
            await db2.commit()
            print("  V16.4 migration complete: bug fixes + agentic AI tables")

    print("V16.4 migration complete.")


if __name__ == "__main__":
    asyncio.run(migrate())
