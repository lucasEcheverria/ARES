"""Async SQLAlchemy engines and session factories for both databases."""

from collections.abc import AsyncGenerator

from elasticsearch import AsyncElasticsearch
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from config import settings


def _build_url(database: str) -> str:
    """Build an async MySQL connection URL for the given database name.

    Args:
        database: Name of the target database.

    Returns:
        A `mysql+asyncmy://` connection URL.
    """
    return (
        f"mysql+asyncmy://{settings.db_user}:{settings.db_password}"
        f"@{settings.db_host}:{settings.db_port}/{database}"
    )


engine_config = create_async_engine(_build_url(settings.db_config))
engine_sessions = create_async_engine(_build_url(settings.db_sessions))

AsyncSessionConfig = async_sessionmaker(engine_config, expire_on_commit=False)
AsyncSessionSessions = async_sessionmaker(engine_sessions, expire_on_commit=False)

es_client = AsyncElasticsearch(hosts=[settings.elasticsearch_url])


async def get_config_db() -> AsyncGenerator[AsyncSession]:
    """Yield an async session bound to the `ares_config` database."""
    async with AsyncSessionConfig() as session:
        yield session


async def get_sessions_db() -> AsyncGenerator[AsyncSession]:
    """Yield an async session bound to the `ares_sessions` database."""
    async with AsyncSessionSessions() as session:
        yield session
