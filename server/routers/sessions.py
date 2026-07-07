"""Session management endpoints."""

import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from dao.session_dao import SessionDAO
from database.connection import get_sessions_db
from models.session import SessionStatus
from services.session_service import SessionService

router = APIRouter()
_bearer_scheme = HTTPBearer()


class SessionCreateRequest(BaseModel):
    """Request body for `POST /sessions`."""

    target: str


class SessionResponse(BaseModel):
    """A session as returned by the API."""

    id: str
    user_id: str
    target: str
    status: SessionStatus
    report_path: str | None
    created_at: datetime.datetime
    updated_at: datetime.datetime

    model_config = {"from_attributes": True}


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


@router.post("", response_model=SessionResponse)
async def create_session(
    body: SessionCreateRequest,
    user_id: str = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> SessionResponse:
    """Create a new agent session for the authenticated user.

    Args:
        body: Request payload containing the pentest target.
        user_id: Authenticated user's ID.
        session_service: Injected `SessionService`.

    Returns:
        The created session.
    """
    session = await session_service.create_session(user_id, body.target)
    return SessionResponse.model_validate(session)


@router.get("", response_model=list[SessionResponse])
async def list_sessions(
    user_id: str = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> list[SessionResponse]:
    """List all sessions belonging to the authenticated user.

    Args:
        user_id: Authenticated user's ID.
        session_service: Injected `SessionService`.

    Returns:
        The user's sessions.
    """
    sessions = await session_service.get_user_sessions(user_id)
    return [SessionResponse.model_validate(s) for s in sessions]


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    user_id: str = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> SessionResponse:
    """Fetch a single session owned by the authenticated user.

    Args:
        session_id: The session's UUID.
        user_id: Authenticated user's ID.
        session_service: Injected `SessionService`.

    Returns:
        The requested session.
    """
    session = await session_service.get_session(session_id, user_id)
    return SessionResponse.model_validate(session)
