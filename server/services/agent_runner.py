import asyncio
from dao.session_dao import SessionDAO
from database.connection import AsyncSessionSessions

async def run_agent_process(session_id: str, target: str) -> None:
    # 1. Lanzar el agente como subproceso async
    process = await asyncio.create_subprocess_exec(
        "wsl", "-d", "Ubuntu", "-e",
        "python", "-m", "ares.cli",
        "--target", target,
        "--session-id", session_id,
    )

    # 2. Esperar a que termine sin bloquear el event loop
    return_code = await process.wait()

    # 3. Actualizar status en BD según resultado
    status = "completed" if return_code == 0 else "failed"

    async with AsyncSessionSessions() as db:
        dao = SessionDAO(db)
        await dao.update_status(session_id, status)