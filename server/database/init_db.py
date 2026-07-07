"""Auto-create database schemas on server startup."""

import logging

from database.connection import engine_config, engine_sessions

# Importing models.event registers Event on SessionsBase.metadata as a side effect.
from models import event as _event  # noqa: F401
from models.session import SessionsBase
from models.user import ConfigBase

logger = logging.getLogger(__name__)


async def init_db() -> None:
    """Create all tables in both databases if they do not already exist.

    Never drops or truncates existing tables — only issues
    `CREATE TABLE IF NOT EXISTS` statements.
    """
    async with engine_config.begin() as conn:
        await conn.run_sync(ConfigBase.metadata.create_all)
    logger.info(
        "ares_config tables checked/created: %s",
        list(ConfigBase.metadata.tables.keys()),
    )

    async with engine_sessions.begin() as conn:
        await conn.run_sync(SessionsBase.metadata.create_all)
    logger.info(
        "ares_sessions tables checked/created: %s",
        list(SessionsBase.metadata.tables.keys()),
    )
