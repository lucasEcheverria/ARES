"""Session management endpoints."""

from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from dao.log_es_dao import LogEsDAO
from dao.session_dao import SessionDAO
from database.connection import es_client, get_sessions_db
from schemas.session import MacrosessionResponse, SessionCreateRequest, SessionResponse
from services.agent_runner import run_agent_process
from services.macrosession_runner import run_macrosession
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
    response_model=MacrosessionResponse | SessionResponse,
    summary="Create a session",
    responses=_UNAUTHORIZED_RESPONSE,
)
async def create_session(
    body: SessionCreateRequest,
    background_tasks: BackgroundTasks,
    user_id: str = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> SessionResponse | MacrosessionResponse:
    """Create a new session and launch its agent run(s) in the background.

    `mode="single"` behaves exactly as before. `mode="subnet"` runs phase-1
    discovery synchronously (so the response already includes the discovered
    children), then schedules phase-2 (the sequential agent run against every
    child) as a background task.
    """
    if body.mode == "single":
        session = await session_service.create_session(user_id, body.name, body.target)
        background_tasks.add_task(run_agent_process, session.id, body.target)
        return SessionResponse.model_validate(session)

    macrosession, children = await session_service.create_subnet_macrosession(
        user_id, body.name, body.cidr
    )
    background_tasks.add_task(run_macrosession, macrosession.id)
    return MacrosessionResponse.model_validate(macrosession).model_copy(
        update={"children": [SessionResponse.model_validate(c) for c in children]}
    )


@router.get(
    "",
    response_model=list[MacrosessionResponse | SessionResponse],
    summary="List sessions",
    responses=_UNAUTHORIZED_RESPONSE,
)
async def list_sessions(
    type: Literal["individual", "macro"] | None = Query(
        default=None, description="Filter to individual sessions or macrosessions only."
    ),
    user_id: str = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> list[MacrosessionResponse | SessionResponse]:
    """List sessions belonging to the authenticated user, most recent first.

    Without `type`, returns every session (unchanged behavior). With
    `type=individual`, excludes macrosessions and their children. With
    `type=macro`, returns only macrosessions, each with `host_status_summary`
    inlined for the sidebar's progress display (`children` is left empty here
    — only `GET /sessions/{id}` inlines the full child list).
    """
    if type == "individual":
        sessions = await session_service.get_individual_sessions(user_id)
        return [SessionResponse.model_validate(s) for s in sessions]

    if type == "macro":
        macrosessions = await session_service.get_macrosessions(user_id)
        result: list[MacrosessionResponse | SessionResponse] = []
        for macrosession in macrosessions:
            summary = await session_service.get_host_status_summary(macrosession.id)
            result.append(
                MacrosessionResponse.model_validate(macrosession).model_copy(
                    update={"host_status_summary": summary}
                )
            )
        return result

    sessions = await session_service.get_user_sessions(user_id)
    return [SessionResponse.model_validate(s) for s in sessions]


@router.get(
    "/{session_id}",
    response_model=MacrosessionResponse | SessionResponse,
    summary="Get a session",
    responses=_SESSION_LOOKUP_RESPONSES,
)
async def get_session(
    session_id: str = Path(..., description="The session's UUID."),
    user_id: str = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> SessionResponse | MacrosessionResponse:
    """Fetch a single session owned by the authenticated user.

    If the session has discovered children, it is a macrosession: the
    response inlines `children` and `host_status_summary`. Otherwise it is
    returned exactly as an individual session always has been.
    """
    session = await session_service.get_session(session_id, user_id)
    children = await session_service.get_children(session_id)
    if not children:
        return SessionResponse.model_validate(session)

    summary = await session_service.get_host_status_summary(session_id)
    return MacrosessionResponse.model_validate(session).model_copy(
        update={
            "children": [SessionResponse.model_validate(c) for c in children],
            "host_status_summary": summary,
        }
    )


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
