"""Auto-create database schemas on server startup."""

import logging

from database.connection import engine_config, engine_sessions, es_client

# Importing models.event registers Event on SessionsBase.metadata as a side effect.
from models import event as _event  # noqa: F401
from models.session import SessionsBase
from models.user import ConfigBase

logger = logging.getLogger(__name__)

ARES_LOGS_INDEX = "ares-logs"
ARES_LOGS_MAPPING = {
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "session_id": {"type": "keyword"},
            "sequence": {"type": "integer"},
            "phase": {"type": "keyword"},
            "type": {"type": "keyword"},
            "tool": {"type": "keyword"},
            "content": {"type": "text"},
            "created_at": {"type": "date"},
        }
    }
}


async def init_db() -> None:
    """Create all tables and the Elasticsearch index if they do not already exist.

    Never drops or truncates existing tables/indices — only issues
    `CREATE TABLE IF NOT EXISTS`-equivalent statements.
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

    if not await es_client.indices.exists(index=ARES_LOGS_INDEX):
        await es_client.indices.create(index=ARES_LOGS_INDEX, body=ARES_LOGS_MAPPING)
    logger.info("Elasticsearch index '%s' checked/created", ARES_LOGS_INDEX)
