"""Seed customers from CSV - stub module.
Actual seeding handled by SQL safety net in entrypoint.sh.
This module exists to prevent ImportError when entrypoint calls it.
"""

async def seed_from_csv():
    """No-op - SQL safety net in entrypoint.sh handles customer seeding."""
    return {"status": "skipped", "reason": "SQL safety net handles seeding"}
