"""Tests for `EventDAO`."""

import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from dao.event_dao import EventDAO
from models.event import EventType, Phase

pytestmark = pytest.mark.asyncio


def _event_data(session_id: str, sequence: int, **overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "session_id": session_id,
        "sequence": sequence,
        "phase": Phase.RECON,
        "type": EventType.THOUGHT,
        "tool": None,
        "content": "thinking...",
    }
    data.update(overrides)
    return data


async def test_get_next_sequence_starts_at_zero(sessions_db: AsyncSession) -> None:
    dao = EventDAO(sessions_db)

    assert await dao.get_next_sequence(str(uuid.uuid4())) == 0


async def test_get_next_sequence_increments(sessions_db: AsyncSession) -> None:
    dao = EventDAO(sessions_db)
    session_id = str(uuid.uuid4())

    await dao.create(_event_data(session_id, 0))
    await dao.create(_event_data(session_id, 1))

    assert await dao.get_next_sequence(session_id) == 2


async def test_get_next_sequence_is_scoped_per_session(sessions_db: AsyncSession) -> None:
    dao = EventDAO(sessions_db)
    other_session_id = str(uuid.uuid4())
    await dao.create(_event_data(other_session_id, 0))
    await dao.create(_event_data(other_session_id, 1))
    await dao.create(_event_data(other_session_id, 2))

    assert await dao.get_next_sequence(str(uuid.uuid4())) == 0


async def test_get_all_by_session_orders_by_sequence(sessions_db: AsyncSession) -> None:
    dao = EventDAO(sessions_db)
    session_id = str(uuid.uuid4())
    await dao.create(_event_data(session_id, 2, content="third"))
    await dao.create(_event_data(session_id, 0, content="first"))
    await dao.create(_event_data(session_id, 1, content="second"))

    events = await dao.get_all_by_session(session_id)

    assert [e.content for e in events] == ["first", "second", "third"]


async def test_tool_call_event_stores_tool_name(sessions_db: AsyncSession) -> None:
    dao = EventDAO(sessions_db)
    session_id = str(uuid.uuid4())
    await dao.create(
        _event_data(
            session_id, 0, type=EventType.TOOL_CALL, tool="nmap", content="nmap -sV target"
        )
    )

    events = await dao.get_all_by_session(session_id)

    assert events[0].tool == "nmap"
    assert events[0].type == EventType.TOOL_CALL
