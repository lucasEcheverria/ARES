import asyncio
import subprocess
from dao.session_dao import SessionDAO
from database.connection import AsyncSessionSessions
from config import settings

def _launch_agent(target: str, session_id: str) -> int:
    """Launch the agent as a subprocess synchronously.

    Args:
        target: Target URL for the agent.
        session_id: Database session ID.

    Returns:
        Process return code.
    """
    result = subprocess.run(
        ["uv", "run", "python", "-m", "ares.cli",
         "--target", target,
         "--session-id", session_id],
        cwd=settings.agent_path,
    )
    return result.returncode

async def run_agent_process(session_id: str, target: str) -> None:
    """Launch agent in a thread and update session status on completion."""
    return_code = await asyncio.to_thread(_launch_agent, target, session_id)

    status = "completed" if return_code == 0 else "failed"

    async with AsyncSessionSessions() as db:
        dao = SessionDAO(db)
        await dao.update_status(session_id, status)