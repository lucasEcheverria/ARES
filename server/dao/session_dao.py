"""Data Access Object for `ares_sessions.sessions`."""

from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models.session import Session


class SessionDAO:
    """Persistence operations for `Session` records."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the DAO.

        Args:
            session: Async SQLAlchemy session bound to `ares_sessions`.
        """
        self._session = session

    async def get_by_id(self, session_id: str) -> Session | None:
        """Fetch a session by its ID.

        Args:
            session_id: The session's UUID.

        Returns:
            The matching `Session`, or `None` if not found.
        """
        return await self._session.get(Session, session_id, populate_existing=True)

    async def get_all_by_user(self, user_id: str) -> list[Session]:
        """Fetch all sessions belonging to a user.

        Args:
            user_id: The owning user's `id`.

        Returns:
            List of `Session` records, most recently created first.
        """
        result = await self._session.execute(
            select(Session)
            .where(Session.user_id == user_id)
            .order_by(Session.created_at.desc())
        )
        return list(result.scalars().all())

    async def create(self, session_data: dict[str, Any]) -> Session:
        """Insert a new session.

        Args:
            session_data: Fields for the new `Session` (`id`, `user_id`, `target`).

        Returns:
            The newly created `Session`.
        """
        new_session = Session(**session_data)
        self._session.add(new_session)
        await self._session.commit()
        await self._session.refresh(new_session)
        return new_session

    async def update_status(self, session_id: str, status: str) -> None:
        """Update a session's status.

        Args:
            session_id: The session's UUID.
            status: New status value.
        """
        await self._session.execute(
            update(Session).where(Session.id == session_id).values(status=status)
        )
        await self._session.commit()

    async def update_report_path(self, session_id: str, path: str) -> None:
        """Update a session's report path.

        Args:
            session_id: The session's UUID.
            path: Filesystem path to the generated Markdown report.
        """
        await self._session.execute(
            update(Session).where(Session.id == session_id).values(report_path=path)
        )
        await self._session.commit()
