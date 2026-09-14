"""Tests for the `/sessions` endpoints."""

import datetime
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import routers.sessions as sessions_router
from main import app
from models.session import Session, SessionStatus
from routers.sessions import get_current_user, get_log_es_dao, get_session_service

client = TestClient(app)


@pytest.fixture(autouse=True)
def _clear_overrides() -> Iterator[None]:
    yield
    app.dependency_overrides.clear()


def _sample_session(**overrides: Any) -> Session:
    data: dict[str, Any] = {
        "id": "s-1",
        "user_id": "user-1",
        "name": "Test session",
        "target": "10.0.0.1",
        "status": SessionStatus.RUNNING,
        "report_path": None,
        "created_at": datetime.datetime(2026, 1, 1),
        "updated_at": datetime.datetime(2026, 1, 1),
    }
    data.update(overrides)
    return Session(**data)


def test_create_session_requires_authentication() -> None:
    response = client.post(
        "/sessions", json={"mode": "single", "name": "Test session", "target": "10.0.0.1"}
    )

    assert response.status_code == 401  # HTTPBearer rejects missing credentials


def test_create_session_returns_created_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sessions_router, "run_agent_process", AsyncMock())
    mock_service = AsyncMock()
    mock_service.create_session.return_value = _sample_session()
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service

    response = client.post(
        "/sessions",
        json={"mode": "single", "name": "Test session", "target": "10.0.0.1"},
        headers={"Authorization": "Bearer fake-jwt"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "s-1"
    assert body["name"] == "Test session"
    assert body["target"] == "10.0.0.1"
    assert body["status"] == "running"
    mock_service.create_session.assert_awaited_once_with("user-1", "Test session", "10.0.0.1")


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


def test_delete_session_requires_authentication() -> None:
    response = client.delete("/sessions/s-1")

    assert response.status_code == 401


def test_delete_session_returns_204_and_cleans_up_logs() -> None:
    mock_service = AsyncMock()
    mock_log_dao = AsyncMock()
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service
    app.dependency_overrides[get_log_es_dao] = lambda: mock_log_dao

    response = client.delete("/sessions/s-1", headers={"Authorization": "Bearer fake-jwt"})

    assert response.status_code == 204
    mock_service.delete_session.assert_awaited_once_with("s-1", "user-1")
    mock_log_dao.delete_logs_by_session.assert_awaited_once_with("s-1")


def test_delete_session_propagates_404_from_service() -> None:
    mock_service = AsyncMock()
    mock_service.delete_session.side_effect = HTTPException(status_code=404, detail="not found")
    mock_log_dao = AsyncMock()
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service
    app.dependency_overrides[get_log_es_dao] = lambda: mock_log_dao

    response = client.delete("/sessions/s-1", headers={"Authorization": "Bearer fake-jwt"})

    assert response.status_code == 404
    mock_log_dao.delete_logs_by_session.assert_not_awaited()


def test_create_session_subnet_mode_returns_macrosession_with_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sessions_router, "run_macrosession", AsyncMock())
    macro = _sample_session(id="macro-1", target="192.168.1.0/24")
    child = _sample_session(
        id="child-1",
        target="192.168.1.10",
        parent_session_id="macro-1",
        host_status="pending",
        device_type="chromecast",
    )
    mock_service = AsyncMock()
    mock_service.create_subnet_macrosession.return_value = (macro, [child])
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service

    response = client.post(
        "/sessions",
        json={"mode": "subnet", "name": "Home subnet", "cidr": "192.168.1.0/24"},
        headers={"Authorization": "Bearer fake-jwt"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "macro-1"
    assert len(body["children"]) == 1
    assert body["children"][0]["id"] == "child-1"
    assert body["children"][0]["deviceType"] == "chromecast"
    mock_service.create_subnet_macrosession.assert_awaited_once_with(
        "user-1", "Home subnet", "192.168.1.0/24"
    )


def test_list_sessions_individual_type_calls_service_filter() -> None:
    mock_service = AsyncMock()
    mock_service.get_individual_sessions.return_value = [_sample_session()]
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service

    response = client.get(
        "/sessions", params={"type": "individual"}, headers={"Authorization": "Bearer fake-jwt"}
    )

    assert response.status_code == 200
    mock_service.get_individual_sessions.assert_awaited_once_with("user-1")
    mock_service.get_user_sessions.assert_not_awaited()


def test_list_sessions_macro_type_calls_service_filter() -> None:
    mock_service = AsyncMock()
    mock_service.get_macrosessions.return_value = [_sample_session(id="macro-1")]
    mock_service.get_host_status_summary.return_value = {"pending": 1, "complete": 2}
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service

    response = client.get(
        "/sessions", params={"type": "macro"}, headers={"Authorization": "Bearer fake-jwt"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body[0]["hostStatusSummary"] == {"pending": 1, "complete": 2}
    mock_service.get_macrosessions.assert_awaited_once_with("user-1")
    mock_service.get_host_status_summary.assert_awaited_once_with("macro-1")
    mock_service.get_user_sessions.assert_not_awaited()


def test_get_session_with_children_returns_macrosession_response() -> None:
    macro = _sample_session(id="macro-1", target="192.168.1.0/24")
    child = _sample_session(id="child-1", target="192.168.1.10", parent_session_id="macro-1")
    mock_service = AsyncMock()
    mock_service.get_session.return_value = macro
    mock_service.get_children.return_value = [child]
    mock_service.get_host_status_summary.return_value = {"pending": 1}
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service

    response = client.get("/sessions/macro-1", headers={"Authorization": "Bearer fake-jwt"})

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "macro-1"
    assert len(body["children"]) == 1
    assert body["hostStatusSummary"] == {"pending": 1}


def test_get_session_without_children_returns_plain_session_response() -> None:
    mock_service = AsyncMock()
    mock_service.get_session.return_value = _sample_session()
    mock_service.get_children.return_value = []
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_service] = lambda: mock_service

    response = client.get("/sessions/s-1", headers={"Authorization": "Bearer fake-jwt"})

    assert response.status_code == 200
    assert "children" not in response.json()
    mock_service.get_host_status_summary.assert_not_awaited()
