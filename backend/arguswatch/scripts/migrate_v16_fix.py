"""V16-fix migration: Add recon_status tracking + exposure_history table."""
import asyncio
from sqlalchemy import text
from arguswatch.database import async_session


async def migrate():
    async with async_session() as db:
        await db.execute(text("ALTER TABLE customers ADD COLUMN IF NOT EXISTS recon_status VARCHAR(20) DEFAULT NULL"))
        await db.execute(text("ALTER TABLE customers ADD COLUMN IF NOT EXISTS recon_error TEXT DEFAULT NULL"))
        await db.execute(text("""
            CREATE TABLE IF NOT EXISTS exposure_history (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE NOT NULL,
                snapshot_date TIMESTAMP NOT NULL,
                overall_score FLOAT DEFAULT 0.0,
                d1_score FLOAT DEFAULT 0.0, d2_score FLOAT DEFAULT 0.0,
                d3_score FLOAT DEFAULT 0.0, d4_score FLOAT DEFAULT 0.0,
                d5_score FLOAT DEFAULT 0.0,
                total_detections INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """))
        await db.execute(text("CREATE INDEX IF NOT EXISTS ix_eh_customer_date ON exposure_history(customer_id, snapshot_date)"))
        await db.commit()
        print("✅ V16-fix migration complete: recon_status, recon_error, exposure_history")


if __name__ == "__main__":
    asyncio.run(migrate())
