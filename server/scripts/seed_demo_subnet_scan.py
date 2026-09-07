"""Seed a demo subnet-scan macrosession for local development.

Inserts one macrosession (a plausible but unambiguously fake CIDR) with 6
child sessions covering a mix of `device_type` and `host_status`, for the
first user registered via Google OAuth. Safe to re-run: the macrosession is
matched by (target=cidr, user_id) before inserting anything. For `complete`
children, also seeds a few fake `Event` rows so the split-screen view isn't
empty when testing.

Never touches `agent/` or `server/discovery/` — this is demo data, not a
real discovery run.

Refuses to run when `ENV=production`.

Run with: `uv run python scripts/seed_demo_subnet_scan.py`
"""

import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from database.connection import AsyncSessionConfig, AsyncSessionSessions, es_client  # noqa: E402
from models.event import Event  # noqa: E402
from models.session import HostStatus, Session, SessionStatus  # noqa: E402
from models.user import User  # noqa: E402

DEMO_CIDR = "192.168.56.0/24"  # VirtualBox host-only range: private, unambiguously fake.

_CHILD_SPECS: list[dict[str, Any]] = [
    {"ip": "192.168.56.1", "device_type": "router", "host_status": HostStatus.COMPLETE},
    {"ip": "192.168.56.10", "device_type": "chromecast", "host_status": HostStatus.COMPLETE},
    {"ip": "192.168.56.11", "device_type": "printer", "host_status": HostStatus.COMPLETE},
    {
        "ip": "192.168.56.20",
        "device_type": "unknown",
        "host_status": HostStatus.FAILED,
        "failure_reason": "exception: Connection timed out after 30s",
    },
    {"ip": "192.168.56.21", "device_type": "chromecast", "host_status": HostStatus.PENDING},
    {"ip": "192.168.56.22", "device_type": "apple_tv", "host_status": HostStatus.RUNNING},
]


async def _get_first_user() -> User | None:
    async with AsyncSessionConfig() as db:
        result = await db.execute(select(User).order_by(User.created_at.asc()).limit(1))
        return result.scalar_one_or_none()


async def _get_or_create_macrosession(user_id: str) -> tuple[Session, bool]:
    async with AsyncSessionSessions() as db:
        result = await db.execute(
            select(Session).where(Session.user_id == user_id, Session.target == DEMO_CIDR)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            return existing, False

        macrosession = Session(
            id=str(uuid.uuid4()),
            user_id=user_id,
            name="Demo home subnet",
            target=DEMO_CIDR,
            status=SessionStatus.COMPLETED,
        )
        db.add(macrosession)
        await db.commit()
        await db.refresh(macrosession)
        return macrosession, True


async def _create_child_session(
    user_id: str, macrosession_id: str, spec: dict[str, Any]
) -> Session:
    async with AsyncSessionSessions() as db:
        child = Session(
            id=str(uuid.uuid4()),
            user_id=user_id,
            name=spec["ip"],
            target=spec["ip"],
            status=SessionStatus.COMPLETED
            if spec["host_status"] == HostStatus.COMPLETE
            else SessionStatus.RUNNING,
            parent_session_id=macrosession_id,
            host_status=spec["host_status"],
            failure_reason=spec.get("failure_reason"),
            device_type=spec["device_type"],
            discovery_metadata={
                "ip": spec["ip"],
                "mac": None,
                "service_types": [],
                "response_port": None,
            },
        )
        db.add(child)
        await db.commit()
        await db.refresh(child)
        return child


async def _seed_fake_events(session_id: str, base_time: datetime) -> None:
    events = [
        Event(
            id=str(uuid.uuid4()),
            session_id=session_id,
            sequence=0,
            phase="RECON",
            type="phase_change",
            tool=None,
            content="Entering RECON phase",
            created_at=base_time,
        ),
        Event(
            id=str(uuid.uuid4()),
            session_id=session_id,
            sequence=1,
            phase="RECON",
            type="tool_call",
            tool="nmap",
            content="Running nmap -sV -p- against the host",
            created_at=base_time + timedelta(seconds=30),
        ),
        Event(
            id=str(uuid.uuid4()),
            session_id=session_id,
            sequence=2,
            phase="RECON",
            type="tool_result",
            tool="nmap",
            content="80/tcp open  http",
            created_at=base_time + timedelta(seconds=60),
        ),
    ]
    async with AsyncSessionSessions() as db:
        for event in events:
            db.add(event)
        await db.commit()


async def seed() -> None:
    """Insert a demo macrosession and its children for the first registered user."""
    if os.getenv("ENV", "development") == "production":
        print("Refusing to seed demo subnet scan data in production (ENV=production).")
        return

    user = await _get_first_user()
    if user is None:
        print("No users found in ares_config.users. Log in via Google OAuth first, then re-run.")
        return

    print(f"Seeding demo subnet scan for user: {user.email} ({user.id})")

    macrosession, created = await _get_or_create_macrosession(user.id)
    print(
        f"Macrosession ({'created' if created else 'already existed'}): "
        f"{macrosession.id} -> target={macrosession.target}"
    )

    if not created:
        print("Macrosession already seeded; skipping child creation.")
        return

    base_time = datetime.now(UTC) - timedelta(hours=1)
    for spec in _CHILD_SPECS:
        child = await _create_child_session(user.id, macrosession.id, spec)
        print(
            f"  Child: {child.target} -> "
            f"device_type={child.device_type}, host_status={child.host_status}"
        )
        if spec["host_status"] == HostStatus.COMPLETE:
            await _seed_fake_events(child.id, base_time)


async def main() -> None:
    """Entry point."""
    try:
        await seed()
    finally:
        await es_client.close()


if __name__ == "__main__":
    asyncio.run(main())
