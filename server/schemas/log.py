"""Pydantic response schemas for log endpoints."""

import datetime

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class LogEntry(BaseModel):
    """A single agent log document as returned by the API."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: str = Field(description="Unique ID of the log document.")
    session_id: str = Field(description="The session this log belongs to.")
    sequence: int = Field(description="Monotonically increasing order within the session.")
    phase: str = Field(description="Agent phase: RECON, ENUMERATION, VULN_SCAN, or REPORT.")
    type: str = Field(
        description="Event type: thought, tool_call, tool_result, or phase_change."
    )
    tool: str | None = Field(
        default=None, description="Tool name, when `type` is tool_call or tool_result."
    )
    content: str = Field(description="Log payload/body.")
    created_at: datetime.datetime = Field(description="Timestamp the log was recorded.")


class LogsResponse(BaseModel):
    """A page of agent logs for a session, with the total match count."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    total: int = Field(description="Total number of logs matching the filters.")
    logs: list[LogEntry] = Field(description="The page of logs, sorted by sequence ascending.")
