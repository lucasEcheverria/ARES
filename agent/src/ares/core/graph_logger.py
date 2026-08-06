"""Writes graph events (thought, tool_call, phase_change) to MariaDB.

Encapsulates the pymysql connection and event insertion logic so agent.py
only has to import log_event() and call it. Never raises — any connection
or write failure is logged and swallowed so a missing or unreachable
database never crashes the agent. tool_result events are not written here;
those go to Elasticsearch via es_logger.
"""

import logging
import os
import uuid

import pymysql

logger = logging.getLogger(__name__)

_connection: pymysql.connections.Connection | None = None


def _get_connection() -> pymysql.connections.Connection:
    global _connection
    if _connection is None or not _connection.open:
        _connection = pymysql.connect(
            host=os.environ.get("ARES_DB_HOST", "localhost"),
            port=int(os.environ.get("ARES_DB_PORT", "3306")),
            user=os.environ.get("ARES_DB_USER", ""),
            password=os.environ.get("ARES_DB_PASSWORD", ""),
            database=os.environ.get("ARES_DB_SESSIONS", ""),
            autocommit=True,
        )
    return _connection


def log_event(
    session_id: str,
    sequence: int,
    phase: str,
    event_type: str,
    content: str,
    tool: str | None = None,
) -> None:
    """Insert one row into `ares_sessions.events`.

    Args:
        session_id: Owning session's UUID.
        sequence: Monotonically increasing position within the session,
            tracked by the caller.
        phase: Current phase name, e.g. "RECON".
        event_type: One of "thought", "tool_call", "phase_change".
        content: Full text content of the event.
        tool: Tool name, only set for tool_call events.
    """
    global _connection
    try:
        connection = _get_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO events "
                "(id, session_id, sequence, phase, type, tool, content) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    str(uuid.uuid4()),
                    session_id,
                    sequence,
                    phase,
                    event_type,
                    tool,
                    content,
                ),
            )
    except Exception:
        logger.exception(
            "Failed to write %s event to MariaDB for session '%s'",
            event_type,
            session_id,
        )
        # Drop the cached connection so the next call attempts a fresh one.
        _connection = None
