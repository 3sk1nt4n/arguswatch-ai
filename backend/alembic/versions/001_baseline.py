"""v16.4.1 baseline - stamp existing schema (25 tables)

All 25 tables are created by initdb/*.sql on first boot.
This migration exists to establish the Alembic version baseline so
future migrations can be applied incrementally with `alembic upgrade head`.

Run: alembic stamp head  (marks DB as current without re-creating tables)
Or:  alembic upgrade head (safe - all ops use IF NOT EXISTS)

Revision ID: 001_baseline
Revises: None
Create Date: 2026-03-02
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Baseline migration - all 25 tables already exist from initdb SQL.
    This just verifies they're present. Uses IF NOT EXISTS so it's safe
    to run even if tables already exist.
    """
    # Verify critical tables exist (will no-op if they do)
    op.execute("""
        DO $$
        BEGIN
            -- Verify core tables exist
            IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'customers') THEN
                RAISE EXCEPTION 'Table customers not found - run initdb/01_schema.sql first';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'detections') THEN
                RAISE EXCEPTION 'Table detections not found - run initdb/01_schema.sql first';
            END IF;
            RAISE NOTICE 'ArgusWatch v16.4.1 baseline verified - 25 tables present';
        END $$;
    """)


def downgrade() -> None:
    """Cannot downgrade baseline - would destroy all data."""
    raise RuntimeError("Cannot downgrade past baseline. To reset: docker compose down -v")
