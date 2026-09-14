"""Fase 2: ejecución secuencial del agente sobre los hosts de una macrosesión.

Reuses `services.agent_runner.run_agent_process` unmodified per child — this
module only sequences the calls and layers `host_status` transitions on top
(SDD §5.2). A failure on one host never stops the run; the loop always
continues to the next child.
"""

import logging

from dao.session_dao import SessionDAO
from database.connection import AsyncSessionSessions
from models.session import HostStatus
from services.agent_runner import run_agent_process

logger = logging.getLogger(__name__)


async def run_macrosession(macrosession_id: str) -> None:
    """Run the agent pipeline against every child of a macrosession, in order.

    Args:
        macrosession_id: The macrosession's UUID. Its children are fetched
            fresh at the start of the run, in the order they were created
            during discovery.
    """
    async with AsyncSessionSessions() as db:
        children = await SessionDAO(db).get_children(macrosession_id)

    for child in children:
        async with AsyncSessionSessions() as db:
            await SessionDAO(db).update_host_status(child.id, HostStatus.RUNNING.value)

        try:
            await run_agent_process(child.id, child.target)
        except Exception as exc:  # noqa: BLE001 - a per-host failure must not abort the run
            logger.exception("Macrosession %s: host %s failed", macrosession_id, child.target)
            async with AsyncSessionSessions() as db:
                await SessionDAO(db).update_host_status(
                    child.id, HostStatus.FAILED.value, failure_reason=f"exception: {exc}"
                )
            continue

        async with AsyncSessionSessions() as db:
            await SessionDAO(db).update_host_status(child.id, HostStatus.COMPLETE.value)

    async with AsyncSessionSessions() as db:
        await SessionDAO(db).update_status(macrosession_id, "completed")
