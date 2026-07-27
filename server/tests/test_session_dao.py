"""Tests for `SessionDAO`."""

import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from dao.session_dao import SessionDAO
from models.session import SessionStatus

pytestmark = pytest.mark.asyncio


def _session_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "user_id": "user-1",
        "name": "Test session",
        "target": "10.0.0.1",
        "status": SessionStatus.RUNNING,
    }
    data.update(overrides)
    return data


async def test_create_and_get_by_id(sessions_db: AsyncSession) -> None:
    dao = SessionDAO(sessions_db)
    created = await dao.create(_session_data())

    fetched = await dao.get_by_id(created.id)

    assert fetched is not None
    assert fetched.target == "10.0.0.1"
    assert fetched.status == SessionStatus.RUNNING
    assert fetched.report_path is None


async def test_get_by_id_missing_returns_none(sessions_db: AsyncSession) -> None:
    dao = SessionDAO(sessions_db)

    assert await dao.get_by_id(str(uuid.uuid4())) is None


async def test_get_all_by_user_only_returns_owned_sessions(sessions_db: AsyncSession) -> None:
    dao = SessionDAO(sessions_db)
    await dao.create(_session_data(user_id="user-1"))
    await dao.create(_session_data(user_id="user-1"))
    await dao.create(_session_data(user_id="user-2"))

    sessions = await dao.get_all_by_user("user-1")

    assert len(sessions) == 2
    assert all(s.user_id == "user-1" for s in sessions)


async def test_update_status(sessions_db: AsyncSession) -> None:
    dao = SessionDAO(sessions_db)
    created = await dao.create(_session_data())

    await dao.update_status(created.id, SessionStatus.COMPLETED.value)

    updated = await dao.get_by_id(created.id)
    assert updated is not None
    assert updated.status == SessionStatus.COMPLETED


async def test_update_report_path(sessions_db: AsyncSession) -> None:
    dao = SessionDAO(sessions_db)
    created = await dao.create(_session_data())

    await dao.update_report_path(created.id, "/reports/session.md")

    updated = await dao.get_by_id(created.id)
    assert updated is not None
    assert updated.report_path == "/reports/session.md"


async def test_delete_removes_session(sessions_db: AsyncSession) -> None:
    dao = SessionDAO(sessions_db)
    created = await dao.create(_session_data())

    await dao.delete(created.id)

    assert await dao.get_by_id(created.id) is None


async def test_delete_missing_session_is_a_noop(sessions_db: AsyncSession) -> None:
    dao = SessionDAO(sessions_db)

    await dao.delete(str(uuid.uuid4()))  # does not raise
