"""Seed realistic test data (sessions + agent logs) for local development.

Inserts two sessions for the first user registered via Google OAuth, and
realistic Elasticsearch log documents for each. Safe to re-run: sessions are
matched by (target, user_id) before inserting, and log documents use
deterministic IDs so re-indexing them is a no-op overwrite.

Run with: `uv run python scripts/seed_data.py`
"""

import asyncio
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from database.connection import (  # noqa: E402
    AsyncSessionConfig,
    AsyncSessionSessions,
    es_client,
)
from models.session import Session, SessionStatus  # noqa: E402
from models.user import User  # noqa: E402


async def _get_first_user() -> User | None:
    async with AsyncSessionConfig() as db:
        result = await db.execute(select(User).order_by(User.created_at.asc()).limit(1))
        return result.scalar_one_or_none()


async def _get_or_create_session(user_id: str, target: str) -> tuple[Session, bool]:
    async with AsyncSessionSessions() as db:
        result = await db.execute(
            select(Session).where(Session.user_id == user_id, Session.target == target)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            return existing, False

        new_session = Session(
            id=str(uuid.uuid4()),
            user_id=user_id,
            target=target,
            status=SessionStatus.COMPLETED,
        )
        db.add(new_session)
        await db.commit()
        await db.refresh(new_session)
        return new_session, True


def _log_doc(
    session_id: str,
    sequence: int,
    phase: str,
    type_: str,
    tool: str | None,
    content: str,
    base_time: datetime,
) -> dict[str, Any]:
    return {
        "id": f"{session_id}-{sequence}",
        "session_id": session_id,
        "sequence": sequence,
        "phase": phase,
        "type": type_,
        "tool": tool,
        "content": content,
        "created_at": (base_time + timedelta(seconds=sequence * 30)).isoformat(),
    }


def _session1_logs(session_id: str, base_time: datetime) -> list[dict[str, Any]]:
    return [
        _log_doc(session_id, 0, "RECON", "phase_change", None, "Entering RECON phase", base_time),
        _log_doc(
            session_id,
            1,
            "RECON",
            "tool_call",
            "nmap",
            "Running nmap -sV -p- localhost:8080",
            base_time,
        ),
        _log_doc(
            session_id,
            2,
            "RECON",
            "tool_result",
            "nmap",
            "8080/tcp open  http    nginx 1.25.3",
            base_time,
        ),
        _log_doc(
            session_id,
            3,
            "RECON",
            "thought",
            None,
            "HTTP service detected on 8080. Moving to enumeration to map exposed endpoints.",
            base_time,
        ),
        _log_doc(
            session_id,
            4,
            "ENUMERATION",
            "phase_change",
            None,
            "Entering ENUMERATION phase",
            base_time,
        ),
        _log_doc(
            session_id,
            5,
            "ENUMERATION",
            "tool_call",
            "gobuster",
            "Running gobuster dir -u http://localhost:8080 -w common.txt",
            base_time,
        ),
        _log_doc(
            session_id,
            6,
            "ENUMERATION",
            "tool_result",
            "gobuster",
            "/admin (Status: 200)\n/api (Status: 200)\n/login (Status: 200)",
            base_time,
        ),
        _log_doc(
            session_id,
            7,
            "ENUMERATION",
            "tool_call",
            "curl",
            "curl -s http://localhost:8080/api",
            base_time,
        ),
    ]


def _session2_logs(session_id: str, base_time: datetime) -> list[dict[str, Any]]:
    return [
        _log_doc(session_id, 0, "RECON", "phase_change", None, "Entering RECON phase", base_time),
        _log_doc(
            session_id,
            1,
            "RECON",
            "tool_call",
            "nmap",
            "Running nmap -sV -p443,80 alud.es",
            base_time,
        ),
        _log_doc(
            session_id,
            2,
            "RECON",
            "tool_result",
            "nmap",
            "80/tcp  open  http   nginx\n443/tcp open  https  nginx",
            base_time,
        ),
        _log_doc(
            session_id,
            3,
            "RECON",
            "thought",
            None,
            "TLS enabled on 443. No obvious vulnerable services found. Proceeding to report.",
            base_time,
        ),
        _log_doc(
            session_id,
            4,
            "REPORT",
            "phase_change",
            None,
            "Entering REPORT phase",
            base_time,
        ),
    ]


async def seed() -> None:
    """Insert sessions and agent logs for the first registered user."""
    user = await _get_first_user()
    if user is None:
        print("No users found in ares_config.users. Log in via Google OAuth first, then re-run.")
        return

    print(f"Seeding data for user: {user.email} ({user.id})")

    base_time = datetime.now(UTC) - timedelta(hours=1)

    session1, created1 = await _get_or_create_session(user.id, "localhost:8080")
    session2, created2 = await _get_or_create_session(user.id, "alud.es")

    logs1 = _session1_logs(session1.id, base_time)
    logs2 = _session2_logs(session2.id, base_time + timedelta(minutes=30))

    for log in [*logs1, *logs2]:
        await es_client.index(index="ares-logs", id=log["id"], document=log)
    await es_client.indices.refresh(index="ares-logs")

    print(
        f"Session 1 ({'created' if created1 else 'already existed'}): "
        f"{session1.id} -> target={session1.target}, {len(logs1)} logs indexed"
    )
    print(
        f"Session 2 ({'created' if created2 else 'already existed'}): "
        f"{session2.id} -> target={session2.target}, {len(logs2)} logs indexed"
    )


async def main() -> None:
    """Entry point."""
    try:
        await seed()
    finally:
        await es_client.close()


if __name__ == "__main__":
    asyncio.run(main())
