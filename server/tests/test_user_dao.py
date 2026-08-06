"""Tests for `UserDAO`."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from dao.user_dao import UserDAO

pytestmark = pytest.mark.asyncio


async def test_create_and_get_by_id(config_db: AsyncSession) -> None:
    dao = UserDAO(config_db)
    user = await dao.create(
        {"id": "sub-1", "email": "a@example.com", "name": "Alice", "picture": None}
    )

    fetched = await dao.get_by_id("sub-1")

    assert fetched is not None
    assert fetched.id == user.id
    assert fetched.email == "a@example.com"
    assert fetched.name == "Alice"
    assert fetched.picture is None


async def test_get_by_id_missing_returns_none(config_db: AsyncSession) -> None:
    dao = UserDAO(config_db)

    assert await dao.get_by_id("does-not-exist") is None


async def test_get_by_email(config_db: AsyncSession) -> None:
    dao = UserDAO(config_db)
    await dao.create({"id": "sub-2", "email": "b@example.com", "name": "Bob", "picture": None})

    fetched = await dao.get_by_email("b@example.com")

    assert fetched is not None
    assert fetched.id == "sub-2"


async def test_get_by_email_missing_returns_none(config_db: AsyncSession) -> None:
    dao = UserDAO(config_db)

    assert await dao.get_by_email("nobody@example.com") is None


async def test_update_last_login_advances_timestamp(config_db: AsyncSession) -> None:
    dao = UserDAO(config_db)
    user = await dao.create(
        {"id": "sub-3", "email": "c@example.com", "name": "Carol", "picture": None}
    )
    original_last_login = user.last_login

    await dao.update_last_login("sub-3")

    updated = await dao.get_by_id("sub-3")
    assert updated is not None
    assert updated.last_login >= original_last_login
