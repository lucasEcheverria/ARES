"""Shared pytest fixtures.

DAO-level tests run against an in-memory SQLite database (via `aiosqlite`)
rather than MySQL/MariaDB, so they exercise real SQL without requiring a
live server. This is safe because the ORM models use only generic
SQLAlchemy types (`String`, `Text`, `DateTime`, `Enum`, `Integer`).
"""

from collections.abc import AsyncGenerator

import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from models import event as _event  # noqa: F401  (registers Event on SessionsBase)
from models.session import SessionsBase
from models.user import ConfigBase


def _make_sqlite_engine() -> AsyncEngine:
    """Create an isolated in-memory SQLite async engine backed by a single connection."""
    return create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


@pytest_asyncio.fixture
async def config_db() -> AsyncGenerator[AsyncSession]:
    """Yield an async session against a fresh in-memory `ares_config` schema."""
    engine = _make_sqlite_engine()
    async with engine.begin() as conn:
        await conn.run_sync(ConfigBase.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def sessions_db() -> AsyncGenerator[AsyncSession]:
    """Yield an async session against a fresh in-memory `ares_sessions` schema."""
    engine = _make_sqlite_engine()
    async with engine.begin() as conn:
        await conn.run_sync(SessionsBase.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()
