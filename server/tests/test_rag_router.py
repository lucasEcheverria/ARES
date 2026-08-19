"""Tests for the `POST /sessions/{session_id}/query` endpoint."""

import datetime
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from main import app
from models.session import Session, SessionStatus
from routers.rag import get_log_es_dao, get_session_dao
from routers.sessions import get_current_user

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
        "status": SessionStatus.COMPLETED,
        "report_path": None,
        "created_at": datetime.datetime(2026, 1, 1),
        "updated_at": datetime.datetime(2026, 1, 1),
    }
    data.update(overrides)
    return Session(**data)


def _mock_embed_response(vector: list[float]) -> AsyncMock:
    response = AsyncMock()
    response.embeddings = [vector]
    return response


def _mock_chat_response(content: str) -> AsyncMock:
    response = AsyncMock()
    response.message = AsyncMock()
    response.message.content = content
    return response


def test_query_session_requires_authentication() -> None:
    response = client.post("/sessions/s-1/query", json={"question": "what happened?"})

    assert response.status_code == 401


def test_query_session_returns_404_when_session_missing() -> None:
    mock_session_dao = AsyncMock()
    mock_session_dao.get_by_id.return_value = None
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_dao] = lambda: mock_session_dao
    app.dependency_overrides[get_log_es_dao] = lambda: AsyncMock()

    response = client.post(
        "/sessions/s-1/query",
        json={"question": "what happened?"},
        headers={"Authorization": "Bearer fake-jwt"},
    )

    assert response.status_code == 404


def test_query_session_returns_403_for_other_users_session() -> None:
    mock_session_dao = AsyncMock()
    mock_session_dao.get_by_id.return_value = _sample_session(user_id="someone-else")
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_dao] = lambda: mock_session_dao
    app.dependency_overrides[get_log_es_dao] = lambda: AsyncMock()

    response = client.post(
        "/sessions/s-1/query",
        json={"question": "what happened?"},
        headers={"Authorization": "Bearer fake-jwt"},
    )

    assert response.status_code == 403


def test_query_session_returns_answer_and_sources_for_owned_session() -> None:
    mock_session_dao = AsyncMock()
    mock_session_dao.get_by_id.return_value = _sample_session(user_id="user-1")
    mock_log_dao = AsyncMock()
    mock_log_dao.hybrid_search.return_value = [
        {
            "phase": "RECON",
            "sequence": 3,
            "tool": "nmap",
            "lines": ["22/tcp open ssh"],
            "session_id": "s-1",
        }
    ]
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_dao] = lambda: mock_session_dao
    app.dependency_overrides[get_log_es_dao] = lambda: mock_log_dao

    mock_client = AsyncMock()
    mock_client.embed.return_value = _mock_embed_response([0.1, 0.2])
    mock_client.chat.return_value = _mock_chat_response(
        "<think>reasoning...</think>Port 22 is open running SSH."
    )

    with patch("ollama.AsyncClient", return_value=mock_client):
        response = client.post(
            "/sessions/s-1/query",
            json={"question": "which ports are open?"},
            headers={"Authorization": "Bearer fake-jwt"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["answer"] == "Port 22 is open running SSH."
    assert body["sources"] == [
        {"phase": "RECON", "sequence": 3, "tool": "nmap", "snippet": "22/tcp open ssh"}
    ]
    mock_log_dao.hybrid_search.assert_awaited_once_with(
        "s-1", "which ports are open?", [0.1, 0.2], k=8
    )


def test_query_session_scopes_search_to_the_requested_session() -> None:
    mock_session_dao = AsyncMock()
    mock_session_dao.get_by_id.return_value = _sample_session(id="s-1", user_id="user-1")
    mock_log_dao = AsyncMock()
    mock_log_dao.hybrid_search.return_value = []
    app.dependency_overrides[get_current_user] = lambda: "user-1"
    app.dependency_overrides[get_session_dao] = lambda: mock_session_dao
    app.dependency_overrides[get_log_es_dao] = lambda: mock_log_dao

    mock_client = AsyncMock()
    mock_client.embed.return_value = _mock_embed_response([0.5])
    mock_client.chat.return_value = _mock_chat_response("No findings.")

    with patch("ollama.AsyncClient", return_value=mock_client):
        client.post(
            "/sessions/s-1/query",
            json={"question": "anything on port 80?"},
            headers={"Authorization": "Bearer fake-jwt"},
        )

    called_session_id = mock_log_dao.hybrid_search.call_args.args[0]
    assert called_session_id == "s-1"
