"""Session management endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, status, BackgroundTasks
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from services.agent_runner import run_agent_process

from config import settings
from dao.log_es_dao import LogEsDAO
from dao.session_dao import SessionDAO
from database.connection import es_client, get_sessions_db
from schemas.session import SessionResponse
from services.session_service import SessionService

router = APIRouter()
_bearer_scheme = HTTPBearer()

_UNAUTHORIZED_RESPONSE: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing or invalid bearer token"}
}
_SESSION_LOOKUP_RESPONSES: dict[int | str, dict[str, Any]] = {
    **_UNAUTHORIZED_RESPONSE,
    403: {"description": "Session belongs to a different user"},
    404: {"description": "Session not found"},
}


class SessionCreateRequest(BaseModel):
    """Request body for `POST /sessions`."""

    name: str = Field(description="User-provided name for the session.")
    target: str = Field(description="Target of the pentest (host, URL, or IP).")


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> str:
    """Resolve the authenticated user's ID from the `Authorization` header.

    Args:
        credentials: Bearer credentials extracted from the request header.

    Returns:
        The `sub` claim (user ID) from the verified JWT.

    Raises:
        HTTPException: 401 if the token is missing, invalid, or expired.
    """
    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc

    user_id = payload.get("sub")
    if not isinstance(user_id, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload"
        )
    return user_id


def get_session_service(db: AsyncSession = Depends(get_sessions_db)) -> SessionService:
    """Build a `SessionService` wired to the `ares_sessions` database.

    Args:
        db: Async session bound to `ares_sessions`, injected by FastAPI.

    Returns:
        A ready-to-use `SessionService`.
    """
    return SessionService(SessionDAO(db))


def get_log_es_dao() -> LogEsDAO:
    """Build a `LogEsDAO` wired to the shared Elasticsearch client.

    Returns:
        A ready-to-use `LogEsDAO`.
    """
    return LogEsDAO(es_client)


@router.post(
    "",
    response_model=SessionResponse,
    summary="Create a session",
    responses=_UNAUTHORIZED_RESPONSE,
)
async def create_session(
    body: SessionCreateRequest,
    background_tasks: BackgroundTasks,
    user_id: str = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> SessionResponse:
    """Create a new agent session and launch the agent in the background."""
    session = await session_service.create_session(user_id, body.name, body.target)
    background_tasks.add_task(run_agent_process, session.id, body.target)
    return SessionResponse.model_validate(session)


@router.get(
    "",
    response_model=list[SessionResponse],
    summary="List sessions",
    responses=_UNAUTHORIZED_RESPONSE,
)
async def list_sessions(
    user_id: str = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> list[SessionResponse]:
    """List all sessions belonging to the authenticated user, most recent first."""
    sessions = await session_service.get_user_sessions(user_id)
    return [SessionResponse.model_validate(s) for s in sessions]


@router.get(
    "/{session_id}",
    response_model=SessionResponse,
    summary="Get a session",
    responses=_SESSION_LOOKUP_RESPONSES,
)
async def get_session(
    session_id: str = Path(..., description="The session's UUID."),
    user_id: str = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> SessionResponse:
    """Fetch a single session owned by the authenticated user."""
    session = await session_service.get_session(session_id, user_id)
    return SessionResponse.model_validate(session)


@router.delete(
    "/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a session",
    responses=_SESSION_LOOKUP_RESPONSES,
)
async def delete_session(
    session_id: str = Path(..., description="The session's UUID."),
    user_id: str = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
    log_dao: LogEsDAO = Depends(get_log_es_dao),
) -> None:
    """Delete a session owned by the authenticated user, and its recorded logs.

    Permanently removes the session row and all associated Elasticsearch log
    documents. This cannot be undone.
    """
    await session_service.delete_session(session_id, user_id)
    await log_dao.delete_logs_by_session(session_id)
