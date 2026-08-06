"""Pydantic response schemas for log endpoints."""

import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class LogEntry(BaseModel):
    """A single tool_result log document as returned by the API."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: str = Field(description="Unique ID of the log document.")
    session_id: str = Field(description="The session this log belongs to.")
    phase: str = Field(description="Agent phase: RECON, ENUMERATION, VULN_SCAN, or REPORT.")
    tool: str = Field(description="Name of the tool that produced this result.")
    created_at: datetime.datetime = Field(description="Timestamp the log was recorded.")
    exit_code: int = Field(description="Exit code of the tool execution.")
    lines: list[str] = Field(description="Raw tool output, split into non-empty lines.")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool-specific structured fields extracted from the output.",
    )


class LogsResponse(BaseModel):
    """A page of agent logs for a session, with the total match count."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    total: int = Field(description="Total number of logs matching the filters.")
    logs: list[LogEntry] = Field(
        description="The page of logs, sorted by created_at ascending."
    )
