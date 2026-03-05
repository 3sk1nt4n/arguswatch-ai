"""v16.5 example - add user_accounts table for persistent auth

This is a TEMPLATE showing how future migrations should work.
Uncomment and modify when ready to add persistent user accounts to PostgreSQL.

Revision ID: 002_user_accounts
Revises: 001_baseline
Create Date: 2026-03-02
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "002_user_accounts"
down_revision: Union[str, None] = "001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_accounts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(100), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("last_login", sa.DateTime, nullable=True),
    )
    op.create_index("ix_user_accounts_username", "user_accounts", ["username"])


def downgrade() -> None:
    op.drop_index("ix_user_accounts_username")
    op.drop_table("user_accounts")
