"""Agent log endpoints backed by Elasticsearch."""

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from dao.log_es_dao import LogEsDAO
from dao.session_dao import SessionDAO
from database.connection import es_client, get_sessions_db
from routers.sessions import get_current_user
from schemas.log import LogsResponse

router = APIRouter()


def get_log_es_dao() -> LogEsDAO:
    """Build a `LogEsDAO` wired to the shared Elasticsearch client.

    Returns:
        A ready-to-use `LogEsDAO`.
    """
    return LogEsDAO(es_client)


def get_session_dao(db: AsyncSession = Depends(get_sessions_db)) -> SessionDAO:
    """Build a `SessionDAO` wired to the `ares_sessions` database.

    Args:
        db: Async session bound to `ares_sessions`, injected by FastAPI.

    Returns:
        A ready-to-use `SessionDAO`.
    """
    return SessionDAO(db)


@router.get(
    "/{session_id}/logs",
    response_model=LogsResponse,
    summary="List agent logs for a session",
    responses={
        401: {"description": "Missing or invalid bearer token"},
        403: {"description": "Session belongs to a different user"},
        404: {"description": "Session not found"},
    },
)
async def get_session_logs(
    session_id: str = Path(..., description="The session's UUID."),
    phase: str | None = Query(
        default=None, description="Filter by phase: RECON, ENUMERATION, VULN_SCAN, or REPORT."
    ),
    type: str | None = Query(
        default=None,
        description="Filter by event type: thought, tool_call, tool_result, or phase_change.",
    ),
    tool: str | None = Query(default=None, description="Filter by tool name, e.g. `nmap`."),
    from_dt: str | None = Query(
        default=None, description="ISO 8601 lower bound (inclusive) on `created_at`."
    ),
    to_dt: str | None = Query(
        default=None, description="ISO 8601 upper bound (inclusive) on `created_at`."
    ),
    limit: int = Query(default=50, description="Maximum number of logs to return."),
    offset: int = Query(default=0, description="Number of matching logs to skip."),
    user_id: str = Depends(get_current_user),
    session_dao: SessionDAO = Depends(get_session_dao),
    log_dao: LogEsDAO = Depends(get_log_es_dao),
) -> LogsResponse:
    """Fetch a page of agent logs for a session owned by the authenticated user.

    Logs are sorted by `sequence` ascending. All filters are optional and are
    combined with AND semantics.

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

    result = await log_dao.get_logs(
        session_id=session_id,
        phase=phase,
        type=type,
        tool=tool,
        from_dt=from_dt,
        to_dt=to_dt,
        limit=limit,
        offset=offset,
    )
    return LogsResponse.model_validate(result)
