"""Agent runner service for launching ARES agent as a background subprocess."""

import asyncio
import os
import subprocess
from pathlib import Path

from config import settings
from dao.session_dao import SessionDAO
from database.connection import AsyncSessionSessions


def _launch_agent(target: str, session_id: str) -> int:
    """Launch the agent as a subprocess synchronously.

    Args:
        target: Target URL for the agent.
        session_id: Database session ID.

    Returns:
        Process return code.
    """
    env = os.environ.copy()
    env.pop("VIRTUAL_ENV", None)
    env["ARES_REPORTS_DIR"] = settings.reports_dir
    env["ARES_ES_URL"] = settings.ares_es_url
    env["ARES_DB_HOST"] = settings.ares_db_host
    env["ARES_DB_PORT"] = str(settings.ares_db_port)
    env["ARES_DB_USER"] = settings.ares_db_user
    env["ARES_DB_PASSWORD"] = settings.ares_db_password
    env["ARES_DB_SESSIONS"] = settings.ares_db_sessions

    result = subprocess.run(
        ["uv", "run", "python", "-m", "ares.cli",
         "--target", target,
         "--session-id", session_id],
        cwd=settings.agent_path,
        env=env,
    )
    return result.returncode


async def run_agent_process(session_id: str, target: str) -> None:
    """Launch agent in a thread and update session status and report path on completion.

    Args:
        session_id: Database session ID to update on completion.
        target: Target URL, IP or hostname for the agent to scan.
    """
    return_code = await asyncio.to_thread(_launch_agent, target, session_id)

    status = "completed" if return_code == 0 else "failed"
    report_path = (
        str(Path(settings.reports_dir) / f"{session_id}.md")
        if return_code == 0
        else None
    )

    async with AsyncSessionSessions() as db:
        dao = SessionDAO(db)
        await dao.update_status(session_id, status)
        if report_path:
            await dao.update_report_path(session_id, report_path)