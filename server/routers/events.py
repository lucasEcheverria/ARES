"""Agent execution graph endpoints backed by MariaDB."""

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.ext.asyncio import AsyncSession

from dao.event_dao import EventDAO
from dao.session_dao import SessionDAO
from database.connection import get_sessions_db
from routers.sessions import get_current_user
from schemas.event import EventEntry

router = APIRouter()


def get_event_dao(db: AsyncSession = Depends(get_sessions_db)) -> EventDAO:
    """Build an `EventDAO` wired to the `ares_sessions` database.

    Args:
        db: Async session bound to `ares_sessions`, injected by FastAPI.

    Returns:
        A ready-to-use `EventDAO`.
    """
    return EventDAO(db)


def get_session_dao(db: AsyncSession = Depends(get_sessions_db)) -> SessionDAO:
    """Build a `SessionDAO` wired to the `ares_sessions` database.

    Args:
        db: Async session bound to `ares_sessions`, injected by FastAPI.

    Returns:
        A ready-to-use `SessionDAO`.
    """
    return SessionDAO(db)


@router.get(
    "/{session_id}/events",
    response_model=list[EventEntry],
    summary="List the agent execution graph for a session",
    responses={
        401: {"description": "Missing or invalid bearer token"},
        403: {"description": "Session belongs to a different user"},
        404: {"description": "Session not found"},
    },
)
async def get_session_events(
    session_id: str = Path(..., description="The session's UUID."),
    user_id: str = Depends(get_current_user),
    session_dao: SessionDAO = Depends(get_session_dao),
    event_dao: EventDAO = Depends(get_event_dao),
) -> list[EventEntry]:
    """Fetch the full ordered execution graph for a session owned by the authenticated user.

    Events are sorted by `sequence` ascending.

    Raises:
        HTTPException: 404 if the session does not exist, 403 if it belongs
            to a different user.
    """
    session = await session_dao.get_by_id(session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    if session.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session belongs to a different user",
        )

    events = await event_dao.get_all_by_session(session_id)
    return [EventEntry.model_validate(event) for event in events]
