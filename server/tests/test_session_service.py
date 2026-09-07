"""Tests for `SessionService`."""

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

import services.session_service as session_service_module
from models.session import Session, SessionStatus
from services.session_service import SessionService

pytestmark = pytest.mark.asyncio


@pytest.fixture
def session_dao() -> AsyncMock:
    return AsyncMock()


async def test_create_session_generates_uuid_and_running_status(
    session_dao: AsyncMock,
) -> None:
    session_dao.create.return_value = Session(
        id="generated-id",
        user_id="user-1",
        name="Test session",
        target="10.0.0.1",
        status=SessionStatus.RUNNING,
    )
    service = SessionService(session_dao)

    await service.create_session("user-1", "Test session", "10.0.0.1")

    call_data = session_dao.create.call_args[0][0]
    assert call_data["user_id"] == "user-1"
    assert call_data["name"] == "Test session"
    assert call_data["target"] == "10.0.0.1"
    assert call_data["status"] == SessionStatus.RUNNING
    assert isinstance(call_data["id"], str) and len(call_data["id"]) == 36


async def test_get_user_sessions_delegates_to_dao(session_dao: AsyncMock) -> None:
    session_dao.get_all_by_user.return_value = []
    service = SessionService(session_dao)

    result = await service.get_user_sessions("user-1")

    session_dao.get_all_by_user.assert_awaited_once_with("user-1")
    assert result == []


async def test_get_session_returns_owned_session(session_dao: AsyncMock) -> None:
    owned = Session(id="s-1", user_id="user-1", target="10.0.0.1", status=SessionStatus.RUNNING)
    session_dao.get_by_id.return_value = owned
    service = SessionService(session_dao)

    result = await service.get_session("s-1", "user-1")

    assert result is owned


async def test_get_session_raises_404_when_missing(session_dao: AsyncMock) -> None:
    session_dao.get_by_id.return_value = None
    service = SessionService(session_dao)

    with pytest.raises(HTTPException) as exc_info:
        await service.get_session("missing", "user-1")

    assert exc_info.value.status_code == 404


async def test_get_session_raises_403_for_other_users_session(session_dao: AsyncMock) -> None:
    other_users_session = Session(
        id="s-1", user_id="user-2", target="10.0.0.1", status=SessionStatus.RUNNING
    )
    session_dao.get_by_id.return_value = other_users_session
    service = SessionService(session_dao)

    with pytest.raises(HTTPException) as exc_info:
        await service.get_session("s-1", "user-1")

    assert exc_info.value.status_code == 403


async def test_delete_session_deletes_owned_session(session_dao: AsyncMock) -> None:
    owned = Session(id="s-1", user_id="user-1", target="10.0.0.1", status=SessionStatus.RUNNING)
    session_dao.get_by_id.return_value = owned
    service = SessionService(session_dao)

    await service.delete_session("s-1", "user-1")

    session_dao.delete.assert_awaited_once_with("s-1")


async def test_delete_session_raises_404_when_missing(session_dao: AsyncMock) -> None:
    session_dao.get_by_id.return_value = None
    service = SessionService(session_dao)

    with pytest.raises(HTTPException) as exc_info:
        await service.delete_session("missing", "user-1")

    assert exc_info.value.status_code == 404
    session_dao.delete.assert_not_awaited()


async def test_delete_session_raises_403_for_other_users_session(session_dao: AsyncMock) -> None:
    other_users_session = Session(
        id="s-1", user_id="user-2", target="10.0.0.1", status=SessionStatus.RUNNING
    )
    session_dao.get_by_id.return_value = other_users_session
    service = SessionService(session_dao)

    with pytest.raises(HTTPException) as exc_info:
        await service.delete_session("s-1", "user-1")

    assert exc_info.value.status_code == 403
    session_dao.delete.assert_not_awaited()


async def test_create_subnet_macrosession_delegates_to_discovery_orchestrator(
    session_dao: AsyncMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    macro = Session(
        id="macro-1", user_id="user-1", target="192.168.1.0/24", status=SessionStatus.RUNNING
    )
    fake_orchestrator = AsyncMock(return_value=(macro, []))
    monkeypatch.setattr(
        session_service_module, "discover_and_create_macrosession", fake_orchestrator
    )
    service = SessionService(session_dao)

    result = await service.create_subnet_macrosession("user-1", "Home subnet", "192.168.1.0/24")

    assert result == (macro, [])
    fake_orchestrator.assert_awaited_once_with(
        session_dao, "user-1", "Home subnet", "192.168.1.0/24"
    )


@pytest.mark.parametrize("cidr", ["not-a-cidr", "192.168.0.0/23", "10.0.0.0/16"])
async def test_create_subnet_macrosession_rejects_invalid_or_too_wide_cidr(
    session_dao: AsyncMock, cidr: str
) -> None:
    service = SessionService(session_dao)

    with pytest.raises(HTTPException) as exc_info:
        await service.create_subnet_macrosession("user-1", "Home subnet", cidr)

    assert exc_info.value.status_code == 400


@pytest.mark.parametrize("cidr", ["192.168.1.0/24", "10.0.0.0/28"])
async def test_create_subnet_macrosession_accepts_slash_24_or_narrower(
    session_dao: AsyncMock, monkeypatch: pytest.MonkeyPatch, cidr: str
) -> None:
    macro = Session(id="macro-1", user_id="user-1", target=cidr, status=SessionStatus.RUNNING)
    fake_orchestrator = AsyncMock(return_value=(macro, []))
    monkeypatch.setattr(
        session_service_module, "discover_and_create_macrosession", fake_orchestrator
    )
    service = SessionService(session_dao)

    await service.create_subnet_macrosession("user-1", "Home subnet", cidr)  # does not raise


async def test_get_individual_sessions_delegates_to_dao(session_dao: AsyncMock) -> None:
    session_dao.get_individual_sessions.return_value = []
    service = SessionService(session_dao)

    result = await service.get_individual_sessions("user-1")

    session_dao.get_individual_sessions.assert_awaited_once_with("user-1")
    assert result == []


async def test_get_macrosessions_delegates_to_dao(session_dao: AsyncMock) -> None:
    session_dao.get_macrosessions.return_value = []
    service = SessionService(session_dao)

    result = await service.get_macrosessions("user-1")

    session_dao.get_macrosessions.assert_awaited_once_with("user-1")
    assert result == []


async def test_get_children_delegates_to_dao(session_dao: AsyncMock) -> None:
    session_dao.get_children.return_value = []
    service = SessionService(session_dao)

    result = await service.get_children("macro-1")

    session_dao.get_children.assert_awaited_once_with("macro-1")
    assert result == []


async def test_get_host_status_summary_delegates_to_dao(session_dao: AsyncMock) -> None:
    session_dao.get_host_status_summary.return_value = {"complete": 1}
    service = SessionService(session_dao)

    result = await service.get_host_status_summary("macro-1")

    session_dao.get_host_status_summary.assert_awaited_once_with("macro-1")
    assert result == {"complete": 1}
