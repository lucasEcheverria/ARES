"""ORM model for `ares_sessions.events`."""

import datetime
import enum

from sqlalchemy import DateTime, Enum, Index, Integer, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from models.session import SessionsBase


class Phase(enum.StrEnum):
    """Phase of the agent's execution graph an event belongs to."""

    RECON = "RECON"
    ENUMERATION = "ENUMERATION"
    VULN_SCAN = "VULN_SCAN"
    REPORT = "REPORT"


class EventType(enum.StrEnum):
    """Kind of event recorded in the agent's execution graph."""

    THOUGHT = "thought"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    PHASE_CHANGE = "phase_change"


class Event(SessionsBase):
    """A single step in an agent session's execution graph.

    Attributes:
        id: UUID v4.
        session_id: References `ares_sessions.sessions.id` (application-level FK only).
        sequence: Monotonically increasing integer per session, guarantees ordering.
        phase: Agent phase the event occurred in.
        type: Kind of event.
        tool: Name of the tool invoked; NULL for `thought` and `phase_change` events.
        content: Event payload/body.
        created_at: Timestamp of event creation.
    """

    __tablename__ = "events"
    __table_args__ = (
        Index("idx_session_id", "session_id"),
        Index("idx_session_sequence", "session_id", "sequence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[Phase] = mapped_column(
        Enum(Phase, values_callable=lambda e: [m.value for m in e]), nullable=False
    )
    type: Mapped[EventType] = mapped_column(
        Enum(EventType, values_callable=lambda e: [m.value for m in e]), nullable=False
    )
    tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
