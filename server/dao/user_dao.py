"""Data Access Object for `ares_config.users`."""

from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models.user import User


class UserDAO:
    """Persistence operations for `User` records."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the DAO.

        Args:
            session: Async SQLAlchemy session bound to `ares_config`.
        """
        self._session = session

    async def get_by_id(self, user_id: str) -> User | None:
        """Fetch a user by their Google `sub` identifier.

        Args:
            user_id: The user's `id` (Google `sub` claim).

        Returns:
            The matching `User`, or `None` if not found.
        """
        return await self._session.get(User, user_id, populate_existing=True)

    async def get_by_email(self, email: str) -> User | None:
        """Fetch a user by email address.

        Args:
            email: The user's email address.

        Returns:
            The matching `User`, or `None` if not found.
        """
        result = await self._session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def create(self, user_data: dict[str, Any]) -> User:
        """Insert a new user.

        Args:
            user_data: Fields for the new `User` (`id`, `email`, `name`, `picture`).

        Returns:
            The newly created `User`.
        """
        user = User(**user_data)
        self._session.add(user)
        await self._session.commit()
        await self._session.refresh(user)
        return user

    async def update_last_login(self, user_id: str) -> None:
        """Set `last_login` to the current time for a user.

        Args:
            user_id: The user's `id`.
        """
        await self._session.execute(
            update(User).where(User.id == user_id).values(last_login=func.now())
        )
        await self._session.commit()
