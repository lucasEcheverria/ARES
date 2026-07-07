"""Tests for the `/sessions` endpoints."""

import datetime
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from main import app
from models.session import Session, SessionStatus
from routers.sessions import get_current_user, get_session_service

client = TestClient(app)


@pytest.fixture(autouse=True)
def _clear_overrides() -> Iterator[None]:
    yield
    app.dependency_overrides.clear()


def _sample_session(**overrides: Any) -> Session:
    data: dict[str, Any] = {
        "id": "s-1",
        "user_id": "user-1",
        "target": "10.0.0.1",
        "status": SessionStatus.RUNNING,
        "report_path": None,
        "created_at": datetime.datetime(2026, 1, 1),
        "updated_at": datetime.datetime(2026, 1, 1),
    }
    data.update(overrides)
    return Session(**data)


def test_create_session_requires_authentication() -> None:
    response = client.post("/sessions", json={"target": "10.0.0.1"})

    assert response.status_code == 401  # HTTPBearer rejects missing credentials


def test_create_session_returns_created_session() -> None:
    mock_service = AsyncMock()
    mock_service.create_session.return_value = _sample_session()
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service

    response = client.post(
        "/sessions",
        json={"target": "10.0.0.1"},
        headers={"Authorization": "Bearer fake-jwt"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "s-1"
    assert body["target"] == "10.0.0.1"
    assert body["status"] == "running"
    mock_service.create_session.assert_awaited_once_with("user-1", "10.0.0.1")


def test_list_sessions_returns_only_current_users_sessions() -> None:
    mock_service = AsyncMock()
    mock_service.get_user_sessions.return_value = [_sample_session()]
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service

    response = client.get("/sessions", headers={"Authorization": "Bearer fake-jwt"})

    assert response.status_code == 200
    assert len(response.json()) == 1
    mock_service.get_user_sessions.assert_awaited_once_with("user-1")


def test_get_session_returns_session() -> None:
    mock_service = AsyncMock()
    mock_service.get_session.return_value = _sample_session()
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service

    response = client.get("/sessions/s-1", headers={"Authorization": "Bearer fake-jwt"})

    assert response.status_code == 200
    mock_service.get_session.assert_awaited_once_with("s-1", "user-1")


def test_get_session_propagates_403_from_service() -> None:
    mock_service = AsyncMock()
    mock_service.get_session.side_effect = HTTPException(status_code=403, detail="forbidden")
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service

    response = client.get("/sessions/s-1", headers={"Authorization": "Bearer fake-jwt"})

    assert response.status_code == 403
