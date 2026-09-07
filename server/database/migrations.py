"""Idempotent, hand-rolled column/constraint additions for `sessions`.

`init_db()`'s `metadata.create_all()` only creates missing tables — it never
alters an already-existing table's columns. This module covers that gap for
the macrosession feature's new `sessions` columns, using
`information_schema` existence checks rather than `ADD COLUMN IF NOT EXISTS`
syntax (unsupported on MySQL < 8.0.29 and only on MariaDB >= 10.3 — the exact
server version in use is not pinned anywhere in this project, so this
approach is safe regardless of which one is actually running).

Safe to run on every startup: a fresh database (where `create_all()` already
created `sessions` with every column below) makes every check below a no-op.
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

_SESSIONS_COLUMNS_TO_ADD: list[tuple[str, str]] = [
    ("parent_session_id", "VARCHAR(36) NULL"),
    ("host_status", "ENUM('pending','running','complete','failed') NULL"),
    ("failure_reason", "TEXT NULL"),
    ("device_type", "VARCHAR(64) NULL"),
    ("discovery_metadata", "JSON NULL"),
]

_FK_NAME = "fk_sessions_parent_session_id"
_INDEX_NAME = "idx_parent_session_id"


async def _column_exists(conn: AsyncConnection, database: str, table: str, column: str) -> bool:
    result = await conn.execute(
        text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema = :db AND table_name = :table AND column_name = :col"
        ),
        {"db": database, "table": table, "col": column},
    )
    return result.first() is not None


async def _constraint_exists(
    conn: AsyncConnection, database: str, table: str, constraint_name: str
) -> bool:
    result = await conn.execute(
        text(
            "SELECT 1 FROM information_schema.table_constraints "
            "WHERE table_schema = :db AND table_name = :table AND constraint_name = :name"
        ),
        {"db": database, "table": table, "name": constraint_name},
    )
    return result.first() is not None


async def _index_exists(conn: AsyncConnection, database: str, table: str, index_name: str) -> bool:
    result = await conn.execute(
        text(
            "SELECT 1 FROM information_schema.statistics "
            "WHERE table_schema = :db AND table_name = :table AND index_name = :name"
        ),
        {"db": database, "table": table, "name": index_name},
    )
    return result.first() is not None


async def run_sessions_migrations(engine: AsyncEngine, database: str) -> None:
    """Add missing `sessions` columns, its self-referential FK, and its index.

    Args:
        engine: Async engine bound to the `ares_sessions` database.
        database: Name of that database, used to scope `information_schema`
            lookups (all databases share the same server's `information_schema`).
    """
    async with engine.begin() as conn:
        for column_name, ddl_type in _SESSIONS_COLUMNS_TO_ADD:
            if not await _column_exists(conn, database, "sessions", column_name):
                await conn.execute(
                    text(f"ALTER TABLE sessions ADD COLUMN {column_name} {ddl_type}")
                )

        if not await _index_exists(conn, database, "sessions", _INDEX_NAME):
            await conn.execute(
                text(f"CREATE INDEX {_INDEX_NAME} ON sessions (parent_session_id)")
            )

        if not await _constraint_exists(conn, database, "sessions", _FK_NAME):
            await conn.execute(
                text(
                    f"ALTER TABLE sessions ADD CONSTRAINT {_FK_NAME} "
                    "FOREIGN KEY (parent_session_id) REFERENCES sessions(id) ON DELETE CASCADE"
                )
            )
