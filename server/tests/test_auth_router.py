"""Tests for `POST /auth/google`."""

from collections.abc import Callable
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from main import app
from routers.auth import get_auth_service


def _override_auth_service(mock_service: AsyncMock) -> Callable[[], AsyncMock]:
    def _get() -> AsyncMock:
        return mock_service

    return _get


def test_google_login_returns_bearer_token() -> None:
    mock_service = AsyncMock()
    mock_service.authenticate_with_google.return_value = "signed.jwt.token"
    app.dependency_overrides[get_auth_service] = _override_auth_service(mock_service)

    try:
        client = TestClient(app)
        response = client.post("/auth/google", json={"id_token": "some-google-id-token"})
    finally:
        app.dependency_overrides.pop(get_auth_service, None)

    assert response.status_code == 200
    body = response.json()
    assert body == {"access_token": "signed.jwt.token", "token_type": "bearer"}
    mock_service.authenticate_with_google.assert_awaited_once_with("some-google-id-token")


def test_google_login_missing_id_token_returns_422() -> None:
    client = TestClient(app)

    response = client.post("/auth/google", json={})

    assert response.status_code == 422
