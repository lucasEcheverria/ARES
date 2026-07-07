"""Tests for `SessionService`."""

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

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
        id="generated-id", user_id="user-1", target="10.0.0.1", status=SessionStatus.RUNNING
    )
    service = SessionService(session_dao)

    await service.create_session("user-1", "10.0.0.1")

    call_data = session_dao.create.call_args[0][0]
    assert call_data["user_id"] == "user-1"
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
