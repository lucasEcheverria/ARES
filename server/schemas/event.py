"""Pydantic response schemas for the agent execution graph (events) endpoint."""

import datetime

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class EventEntry(BaseModel):
    """A single graph event (thought, tool_call, or phase_change) as returned by the API."""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, from_attributes=True
    )

    id: str = Field(description="Unique ID of the event.")
    session_id: str = Field(description="The session this event belongs to.")
    sequence: int = Field(description="Monotonically increasing order within the session.")
    phase: str = Field(description="Agent phase: RECON, ENUMERATION, VULN_SCAN, or REPORT.")
    type: str = Field(description="Event type: thought, tool_call, or phase_change.")
    tool: str | None = Field(
        default=None, description="Tool name, present only for tool_call events."
    )
    content: str = Field(description="Full text content of the event.")
    created_at: datetime.datetime = Field(description="Timestamp the event was recorded.")
