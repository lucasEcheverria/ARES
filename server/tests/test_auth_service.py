"""Tests for `AuthService`."""

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from jose import jwt

from config import settings
from models.user import User
from services.auth_service import AuthService

pytestmark = pytest.mark.asyncio


@pytest.fixture
def user_dao() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def google_payload() -> dict[str, Any]:
    return {
        "sub": "google-sub-123",
        "email": "user@example.com",
        "name": "Test User",
        "picture": "https://example.com/pic.png",
    }


async def test_authenticate_creates_new_user_and_returns_jwt(
    user_dao: AsyncMock, google_payload: dict[str, Any]
) -> None:
    user_dao.get_by_id.return_value = None
    user_dao.create.return_value = User(
        id=google_payload["sub"],
        email=google_payload["email"],
        name=google_payload["name"],
        picture=google_payload["picture"],
    )
    service = AuthService(user_dao)

    with patch(
        "services.auth_service.google_id_token.verify_oauth2_token",
        return_value=google_payload,
    ):
        token = await service.authenticate_with_google("fake-id-token")

    user_dao.create.assert_awaited_once_with(
        {
            "id": "google-sub-123",
            "email": "user@example.com",
            "name": "Test User",
            "picture": "https://example.com/pic.png",
        }
    )
    user_dao.update_last_login.assert_not_awaited()

    claims = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    assert claims["sub"] == "google-sub-123"
    assert claims["email"] == "user@example.com"


async def test_authenticate_updates_last_login_for_existing_user(
    user_dao: AsyncMock, google_payload: dict[str, Any]
) -> None:
    existing_user = User(
        id=google_payload["sub"],
        email=google_payload["email"],
        name=google_payload["name"],
        picture=google_payload["picture"],
    )
    user_dao.get_by_id.return_value = existing_user
    service = AuthService(user_dao)

    with patch(
        "services.auth_service.google_id_token.verify_oauth2_token",
        return_value=google_payload,
    ):
        await service.authenticate_with_google("fake-id-token")

    user_dao.update_last_login.assert_awaited_once_with("google-sub-123")
    user_dao.create.assert_not_awaited()


async def test_authenticate_raises_401_on_invalid_google_token(user_dao: AsyncMock) -> None:
    service = AuthService(user_dao)

    with patch(
        "services.auth_service.google_id_token.verify_oauth2_token",
        side_effect=ValueError("bad token"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await service.authenticate_with_google("invalid-token")

    assert exc_info.value.status_code == 401
