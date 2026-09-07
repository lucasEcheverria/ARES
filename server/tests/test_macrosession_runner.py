"""Tests for `services.macrosession_runner`.

`run_agent_process` is monkeypatched out entirely — this suite verifies the
sequencing/host_status/failure-isolation logic only, never a real agent
subprocess. `AsyncSessionSessions` is monkeypatched to an in-memory SQLite
sessionmaker (fast unit check only, per the plan's stack note — the real
"forced failure on the home network" scenario is verified manually against
MariaDB, not here).
"""

import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from dao.session_dao import SessionDAO
from models.session import HostStatus, SessionsBase, SessionStatus
from services import macrosession_runner

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


@pytest.fixture
async def macrosession_sessionmaker(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(
        "sqlite+aiosqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    async with engine.begin() as conn:
        await conn.run_sync(SessionsBase.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(macrosession_runner, "AsyncSessionSessions", sessionmaker)

    yield sessionmaker

    await engine.dispose()


async def test_run_macrosession_marks_all_children_complete_on_success(
    macrosession_sessionmaker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with macrosession_sessionmaker() as db:
        dao = SessionDAO(db)
        macro = await dao.create(_session_data())
        child1 = await dao.create(
            _session_data(parent_session_id=macro.id, host_status=HostStatus.PENDING.value)
        )
        child2 = await dao.create(
            _session_data(parent_session_id=macro.id, host_status=HostStatus.PENDING.value)
        )

    async def fake_run_agent_process(session_id: str, target: str) -> None:
        return None

    monkeypatch.setattr(macrosession_runner, "run_agent_process", fake_run_agent_process)

    await macrosession_runner.run_macrosession(macro.id)

    async with macrosession_sessionmaker() as db:
        dao = SessionDAO(db)
        updated_macro = await dao.get_by_id(macro.id)
        updated1 = await dao.get_by_id(child1.id)
        updated2 = await dao.get_by_id(child2.id)

    assert updated_macro is not None
    assert updated_macro.status == SessionStatus.COMPLETED
    assert updated1 is not None and updated1.host_status == HostStatus.COMPLETE
    assert updated2 is not None and updated2.host_status == HostStatus.COMPLETE


async def test_run_macrosession_isolates_a_failing_host_and_continues(
    macrosession_sessionmaker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with macrosession_sessionmaker() as db:
        dao = SessionDAO(db)
        macro = await dao.create(_session_data())
        failing_child = await dao.create(
            _session_data(
                target="10.0.0.99",
                parent_session_id=macro.id,
                host_status=HostStatus.PENDING.value,
            )
        )
        healthy_child = await dao.create(
            _session_data(
                target="10.0.0.2",
                parent_session_id=macro.id,
                host_status=HostStatus.PENDING.value,
            )
        )

    async def flaky_run_agent_process(session_id: str, target: str) -> None:
        if target == "10.0.0.99":
            raise ConnectionError("host unreachable")

    monkeypatch.setattr(macrosession_runner, "run_agent_process", flaky_run_agent_process)

    await macrosession_runner.run_macrosession(macro.id)

    async with macrosession_sessionmaker() as db:
        dao = SessionDAO(db)
        updated_macro = await dao.get_by_id(macro.id)
        updated_failing = await dao.get_by_id(failing_child.id)
        updated_healthy = await dao.get_by_id(healthy_child.id)

    assert updated_failing is not None
    assert updated_failing.host_status == HostStatus.FAILED
    assert updated_failing.failure_reason == "exception: host unreachable"

    # The macrosession must continue to (and complete) the next host.
    assert updated_healthy is not None
    assert updated_healthy.host_status == HostStatus.COMPLETE

    assert updated_macro is not None
    assert updated_macro.status == SessionStatus.COMPLETED
