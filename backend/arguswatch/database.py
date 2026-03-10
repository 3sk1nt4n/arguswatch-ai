from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import text
from arguswatch.config import settings
from arguswatch.models import Base  # noqa: F401 - re-exported for initdb

engine = create_async_engine(settings.DATABASE_URL_ASYNC, echo=False, pool_size=10, max_overflow=20)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
# Alias for backwards compat (some collectors use AsyncSessionLocal)
AsyncSessionLocal = async_session

async def get_db():
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_tenant_db(customer_id: int | None = None):
    """RLS-aware DB session. Sets app.current_customer_id for PostgreSQL RLS policies.
    
    Usage in endpoints:
        @app.get("/api/customers/{cid}/findings")
        async def get_findings(cid: int, db = Depends(get_tenant_db)):
            # DB session automatically scoped to customer_id=cid via RLS
    
    When customer_id is None (admin/analyst), RLS passes all rows.
    When customer_id is set, only that customer's rows are returned.
    """
    async with async_session() as session:
        try:
            if customer_id:
                await session.execute(text("SET LOCAL app.current_customer_id = :cid"), {"cid": str(customer_id)})
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
