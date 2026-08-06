"""Session report endpoint."""

import asyncio
from pathlib import Path as FilePath

from fastapi import APIRouter, Depends, HTTPException, Path, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from dao.session_dao import SessionDAO
from database.connection import get_sessions_db
from routers.sessions import get_current_user

router = APIRouter()


def get_session_dao(db: AsyncSession = Depends(get_sessions_db)) -> SessionDAO:
    """Build a `SessionDAO` wired to the `ares_sessions` database.

    Args:
        db: Async session bound to `ares_sessions`, injected by FastAPI.

    Returns:
        A ready-to-use `SessionDAO`.
    """
    return SessionDAO(db)


@router.get(
    "/{session_id}/report",
    response_class=PlainTextResponse,
    summary="Get a session's generated report",
    responses={
        401: {"description": "Missing or invalid bearer token"},
        403: {"description": "Session belongs to a different user"},
        404: {"description": "Session not found or report not yet available"},
    },
)
async def get_session_report(
    session_id: str = Path(..., description="The session's UUID."),
    user_id: str = Depends(get_current_user),
    session_dao: SessionDAO = Depends(get_session_dao),
) -> PlainTextResponse:
    """Fetch the Markdown report generated for a session owned by the authenticated user.

    Raises:
        HTTPException: 404 if the session does not exist, its report has not
            been generated yet, or the report file is missing on disk. 403 if
            the session belongs to a different user.
    """
    session = await session_dao.get_by_id(session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    if session.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session belongs to a different user",
        )
    if session.report_path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Report not available"
        )

    report_file = FilePath(session.report_path)
    if not await asyncio.to_thread(report_file.is_file):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Report not available"
        )

    content = await asyncio.to_thread(report_file.read_text, encoding="utf-8")
    return PlainTextResponse(content)
