"""Data Access Object for `ares_sessions.events`."""

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.event import Event


class EventDAO:
    """Persistence operations for `Event` records."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the DAO.

        Args:
            session: Async SQLAlchemy session bound to `ares_sessions`.
        """
        self._session = session

    async def get_all_by_session(self, session_id: str) -> list[Event]:
        """Fetch the full ordered execution graph for a session.

        Args:
            session_id: The owning session's UUID.

        Returns:
            List of `Event` records ordered by `sequence`.
        """
        result = await self._session.execute(
            select(Event)
            .where(Event.session_id == session_id)
            .order_by(Event.sequence)
        )
        return list(result.scalars().all())

    async def create(self, event_data: dict[str, Any]) -> Event:
        """Insert a new event.

        Args:
            event_data: Fields for the new `Event`.

        Returns:
            The newly created `Event`.
        """
        event = Event(**event_data)
        self._session.add(event)
        await self._session.commit()
        await self._session.refresh(event)
        return event

    async def get_next_sequence(self, session_id: str) -> int:
        """Compute the next monotonic sequence number for a session.

        Args:
            session_id: The owning session's UUID.

        Returns:
            0 if the session has no events yet, otherwise `max(sequence) + 1`.
        """
        result = await self._session.execute(
            select(func.max(Event.sequence)).where(Event.session_id == session_id)
        )
        max_sequence = result.scalar_one_or_none()
        return 0 if max_sequence is None else max_sequence + 1
