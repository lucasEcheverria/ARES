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


async def test_get_children_returns_only_that_parents_children_in_creation_order(
    sessions_db: AsyncSession,
) -> None:
    dao = SessionDAO(sessions_db)
    macro = await dao.create(_session_data())
    other_macro = await dao.create(_session_data())
    child1 = await dao.create(_session_data(parent_session_id=macro.id, host_status="pending"))
    child2 = await dao.create(_session_data(parent_session_id=macro.id, host_status="pending"))
    await dao.create(_session_data(parent_session_id=other_macro.id, host_status="pending"))

    children = await dao.get_children(macro.id)

    assert [c.id for c in children] == [child1.id, child2.id]


async def test_update_host_status_sets_status_and_failure_reason(sessions_db: AsyncSession) -> None:
    dao = SessionDAO(sessions_db)
    child = await dao.create(_session_data(host_status="pending"))

    await dao.update_host_status(child.id, "failed", failure_reason="exception: boom")

    updated = await dao.get_by_id(child.id)
    assert updated is not None
    assert updated.host_status == "failed"
    assert updated.failure_reason == "exception: boom"


async def test_get_host_status_summary_counts_by_status(sessions_db: AsyncSession) -> None:
    dao = SessionDAO(sessions_db)
    macro = await dao.create(_session_data())
    await dao.create(_session_data(parent_session_id=macro.id, host_status="complete"))
    await dao.create(_session_data(parent_session_id=macro.id, host_status="complete"))
    await dao.create(_session_data(parent_session_id=macro.id, host_status="failed"))

    summary = await dao.get_host_status_summary(macro.id)

    assert summary == {"complete": 2, "failed": 1}


async def test_get_individual_sessions_excludes_children_and_macrosessions(
    sessions_db: AsyncSession,
) -> None:
    dao = SessionDAO(sessions_db)
    individual = await dao.create(_session_data(user_id="user-1"))
    macro = await dao.create(_session_data(user_id="user-1"))
    await dao.create(
        _session_data(user_id="user-1", parent_session_id=macro.id, host_status="pending")
    )

    individuals = await dao.get_individual_sessions("user-1")

    assert [s.id for s in individuals] == [individual.id]


async def test_get_macrosessions_returns_only_referenced_parents(sessions_db: AsyncSession) -> None:
    dao = SessionDAO(sessions_db)
    await dao.create(_session_data(user_id="user-1"))
    macro = await dao.create(_session_data(user_id="user-1"))
    await dao.create(
        _session_data(user_id="user-1", parent_session_id=macro.id, host_status="pending")
    )

    macrosessions = await dao.get_macrosessions("user-1")

    assert [s.id for s in macrosessions] == [macro.id]
