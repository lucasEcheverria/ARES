"""Pydantic request/response schemas for the RAG query endpoint."""

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class RagQueryRequest(BaseModel):
    """Request body for `POST /sessions/{session_id}/query`."""

    question: str = Field(description="Natural-language question about the session.")


class RagSource(BaseModel):
    """A single retrieved fragment used to ground the LLM's answer."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    phase: str = Field(description="Agent phase the source fragment was recorded in.")
    sequence: int = Field(description="Ordering sequence of the source fragment.")
    tool: str | None = Field(
        default=None, description="Tool name, if the source is a tool_call or tool_result."
    )
    snippet: str = Field(description="Short excerpt of the retrieved source text.")


class RagQueryResponse(BaseModel):
    """Response body for `POST /sessions/{session_id}/query`."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    answer: str = Field(description="LLM-generated answer grounded in the retrieved sources.")
    sources: list[RagSource] = Field(description="Source fragments used to ground the answer.")
