"""Business logic for session management."""

import ipaddress
import uuid

from fastapi import HTTPException, status

from dao.session_dao import SessionDAO
from discovery.orchestrator import discover_and_create_macrosession
from models.session import Session, SessionStatus


class SessionService:
    """Business logic for creating and retrieving agent sessions."""

    def __init__(self, session_dao: SessionDAO) -> None:
        """Initialize the service.

        Args:
            session_dao: DAO used to persist sessions in `ares_sessions.sessions`.
        """
        self._session_dao = session_dao

    async def create_session(self, user_id: str, name: str, target: str) -> Session:
        """Create a new session owned by the given user.

        Args:
            user_id: The owning user's `id`.
            name: User-provided name for the session.
            target: The target of the pentest.

        Returns:
            The newly created `Session`, with status `running`.
        """
        return await self._session_dao.create(
            {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "name": name,
                "target": target,
                "status": SessionStatus.RUNNING,
            }
        )

    async def create_subnet_macrosession(
        self, user_id: str, name: str, cidr: str
    ) -> tuple[Session, list[Session]]:
        """Create a macrosession and run phase-1 discovery against a `/24` subnet.

        Args:
            user_id: The owning user's `id`.
            name: User-provided name for the macrosession.
            cidr: Subnet in CIDR notation. Rejected if wider than `/24`.

        Returns:
            The created macrosession and its discovered, classified children
            (each with `host_status="pending"`).

        Raises:
            HTTPException: 400 if `cidr` is not valid or is wider than `/24`.
        """
        self._validate_cidr(cidr)
        return await discover_and_create_macrosession(self._session_dao, user_id, name, cidr)

    @staticmethod
    def _validate_cidr(cidr: str) -> None:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid CIDR: {cidr}"
            ) from exc
        if network.prefixlen < 24:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Subnet mask must be /24 or narrower",
            )

    async def get_user_sessions(self, user_id: str) -> list[Session]:
        """List all sessions belonging to a user.

        Args:
            user_id: The owning user's `id`.

        Returns:
            List of `Session` records.
        """
        return await self._session_dao.get_all_by_user(user_id)

    async def get_individual_sessions(self, user_id: str) -> list[Session]:
        """List a user's individual (single-target) sessions, excluding macrosessions.

        Args:
            user_id: The owning user's `id`.

        Returns:
            List of individual `Session` records, most recently created first.
        """
        return await self._session_dao.get_individual_sessions(user_id)

    async def get_macrosessions(self, user_id: str) -> list[Session]:
        """List a user's macrosessions (subnet scans).

        Args:
            user_id: The owning user's `id`.

        Returns:
            List of macrosession `Session` records, most recently created first.
        """
        return await self._session_dao.get_macrosessions(user_id)

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

    async def get_children(self, macrosession_id: str) -> list[Session]:
        """Fetch a macrosession's discovered children, in discovery order.

        Args:
            macrosession_id: The macrosession's UUID.

        Returns:
            List of child `Session` records, empty if `macrosession_id` is an
            individual session (has no children).
        """
        return await self._session_dao.get_children(macrosession_id)

    async def get_host_status_summary(self, macrosession_id: str) -> dict[str, int]:
        """Count a macrosession's children grouped by `host_status`.

        Args:
            macrosession_id: The macrosession's UUID.

        Returns:
            Mapping of `host_status` value to count of children in that status.
        """
        return await self._session_dao.get_host_status_summary(macrosession_id)

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
