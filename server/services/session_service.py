"""Business logic for session management."""

import uuid

from fastapi import HTTPException, status

from dao.session_dao import SessionDAO
from models.session import Session, SessionStatus


class SessionService:
    """Business logic for creating and retrieving agent sessions."""

    def __init__(self, session_dao: SessionDAO) -> None:
        """Initialize the service.

        Args:
            session_dao: DAO used to persist sessions in `ares_sessions.sessions`.
        """
        self._session_dao = session_dao

    async def create_session(self, user_id: str, target: str) -> Session:
        """Create a new session owned by the given user.

        Args:
            user_id: The owning user's `id`.
            target: The target of the pentest.

        Returns:
            The newly created `Session`, with status `running`.
        """
        return await self._session_dao.create(
            {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "target": target,
                "status": SessionStatus.RUNNING,
            }
        )

    async def get_user_sessions(self, user_id: str) -> list[Session]:
        """List all sessions belonging to a user.

        Args:
            user_id: The owning user's `id`.

        Returns:
            List of `Session` records.
        """
        return await self._session_dao.get_all_by_user(user_id)

    async def get_session(self, session_id: str, user_id: str) -> Session:
        """Fetch a single session, validating ownership.

        Args:
            session_id: The session's UUID.
            user_id: The requesting user's `id`.

        Returns:
            The matching `Session`.

        Raises:
            HTTPException: 404 if the session does not exist, 403 if it belongs
                to a different user.
        """
        session = await self._session_dao.get_by_id(session_id)
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Session not found"
            )
        if session.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session belongs to a different user",
            )
        return session

    async def delete_session(self, session_id: str, user_id: str) -> None:
        """Delete a session, validating ownership.

        Args:
            session_id: The session's UUID.
            user_id: The requesting user's `id`.

        Raises:
            HTTPException: 404 if the session does not exist, 403 if it belongs
                to a different user.
        """
        await self.get_session(session_id, user_id)
        await self._session_dao.delete(session_id)
