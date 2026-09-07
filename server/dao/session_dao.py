"""Data Access Object for `ares_sessions.sessions`."""

from typing import Any

from sqlalchemy import delete, func, select, update
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

    async def delete(self, session_id: str) -> None:
        """Delete a session by its ID.

        Args:
            session_id: The session's UUID.
        """
        await self._session.execute(delete(Session).where(Session.id == session_id))
        await self._session.commit()

    async def get_children(self, parent_session_id: str) -> list[Session]:
        """Fetch a macrosession's child sessions, in discovery order.

        Args:
            parent_session_id: The macrosession's UUID.

        Returns:
            List of child `Session` records, oldest first.
        """
        result = await self._session.execute(
            select(Session)
            .where(Session.parent_session_id == parent_session_id)
            .order_by(Session.created_at.asc())
        )
        return list(result.scalars().all())

    async def update_host_status(
        self, session_id: str, host_status: str, failure_reason: str | None = None
    ) -> None:
        """Update a child session's host status, and optionally its failure reason.

        Args:
            session_id: The child session's UUID.
            host_status: New `host_status` value.
            failure_reason: Captured exception message, set only when transitioning
                to `failed`.
        """
        values: dict[str, Any] = {"host_status": host_status}
        if failure_reason is not None:
            values["failure_reason"] = failure_reason
        await self._session.execute(
            update(Session).where(Session.id == session_id).values(**values)
        )
        await self._session.commit()

    async def get_host_status_summary(self, parent_session_id: str) -> dict[str, int]:
        """Count a macrosession's children grouped by `host_status`.

        Args:
            parent_session_id: The macrosession's UUID.

        Returns:
            Mapping of `host_status` value to count of children in that status.
        """
        result = await self._session.execute(
            select(Session.host_status, func.count())
            .where(Session.parent_session_id == parent_session_id)
            .group_by(Session.host_status)
        )
        return {status.value: count for status, count in result.all() if status is not None}

    async def get_individual_sessions(self, user_id: str) -> list[Session]:
        """Fetch a user's individual (single-target) sessions.

        A session is individual when it has no parent and is not itself
        referenced as a parent by any other session.

        Args:
            user_id: The owning user's `id`.

        Returns:
            List of individual `Session` records, most recently created first.
        """
        macrosession_ids = select(Session.parent_session_id).where(
            Session.parent_session_id.is_not(None)
        )
        result = await self._session.execute(
            select(Session)
            .where(
                Session.user_id == user_id,
                Session.parent_session_id.is_(None),
                Session.id.not_in(macrosession_ids),
            )
            .order_by(Session.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_macrosessions(self, user_id: str) -> list[Session]:
        """Fetch a user's macrosessions (subnet scans).

        A session is a macrosession when it is referenced as a parent by at
        least one other session.

        Args:
            user_id: The owning user's `id`.

        Returns:
            List of macrosession `Session` records, most recently created first.
        """
        macrosession_ids = select(Session.parent_session_id).where(
            Session.parent_session_id.is_not(None)
        )
        result = await self._session.execute(
            select(Session)
            .where(Session.user_id == user_id, Session.id.in_(macrosession_ids))
            .order_by(Session.created_at.desc())
        )
        return list(result.scalars().all())
