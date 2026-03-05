from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
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
