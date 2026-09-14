"""RAG query endpoint for asking natural-language questions about a session."""

import re
from typing import Any

import ollama
from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.ext.asyncio import AsyncSession

from dao.log_es_dao import LogEsDAO
from dao.session_dao import SessionDAO
from database.connection import es_client, get_sessions_db
from routers.sessions import get_current_user
from schemas.rag import RagQueryRequest, RagQueryResponse, RagSource

router = APIRouter()

EMBED_MODEL = "nomic-embed-text"
CHAT_MODEL = "deepseek-r1:32b"

_SNIPPET_MAX_CHARS = 400
_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL)

_SYSTEM_PROMPT = (
    "You are assisting a security analyst reviewing an autonomous penetration "
    "testing session. Answer the question using ONLY the context fragments "
    "below, drawn from the agent's recorded reasoning and tool output. Never "
    "invent findings that are not present in the context. If the context does "
    "not contain enough information to answer, say so explicitly."
)


def get_log_es_dao() -> LogEsDAO:
    """Build a `LogEsDAO` wired to the shared Elasticsearch client.

    Returns:
        A ready-to-use `LogEsDAO`.
    """
    return LogEsDAO(es_client)


def get_session_dao(db: AsyncSession = Depends(get_sessions_db)) -> SessionDAO:
    """Build a `SessionDAO` wired to the `ares_sessions` database.

    Args:
        db: Async session bound to `ares_sessions`, injected by FastAPI.

    Returns:
        A ready-to-use `SessionDAO`.
    """
    return SessionDAO(db)


def _source_text(source: dict[str, Any]) -> str:
    """Extract the embeddable/displayable text of a retrieved source document.

    Args:
        source: A document returned by `LogEsDAO.hybrid_search`.

    Returns:
        `lines` joined with newlines for ES-native tool_result documents,
        `content` for MariaDB-sourced graph events.
    """
    lines = source.get("lines")
    if lines:
        return "\n".join(lines)
    return str(source.get("content", ""))


def _snippet(source: dict[str, Any]) -> str:
    """Truncate a source's text to a short display snippet.

    Args:
        source: A document returned by `LogEsDAO.hybrid_search`.

    Returns:
        The source text, truncated to `_SNIPPET_MAX_CHARS` with an ellipsis.
    """
    text = _source_text(source)
    if len(text) <= _SNIPPET_MAX_CHARS:
        return text
    return f"{text[:_SNIPPET_MAX_CHARS]}..."


def _build_prompt(question: str, sources: list[dict[str, Any]]) -> str:
    """Assemble the grounded prompt sent to the chat model.

    Args:
        question: The user's natural-language question.
        sources: Retrieved context documents, most relevant first.

    Returns:
        Full prompt string, with each source labeled by phase and tool.
    """
    context_blocks = []
    for i, source in enumerate(sources, start=1):
        label = source.get("phase", "?")
        tool = source.get("tool")
        if tool:
            label = f"{label} / {tool}"
        context_blocks.append(f"[{i}] ({label}): {_source_text(source)}")
    context = "\n\n".join(context_blocks) or "No relevant context was found."

    return f"{_SYSTEM_PROMPT}\n\n## Context\n{context}\n\n## Question\n{question}"


def _strip_reasoning(text: str) -> str:
    """Remove deepseek-r1's internal `<think>` reasoning block, if present.

    Args:
        text: Raw LLM response.

    Returns:
        Text with any `<think>...</think>` block removed, stripped.
    """
    return _THINK_BLOCK.sub("", text).strip()


@router.post(
    "/{session_id}/query",
    response_model=RagQueryResponse,
    summary="Ask a natural-language question about a session's exploration",
    responses={
        401: {"description": "Missing or invalid bearer token"},
        403: {"description": "Session belongs to a different user"},
        404: {"description": "Session not found"},
    },
)
async def query_session(
    body: RagQueryRequest,
    session_id: str = Path(..., description="The session's UUID."),
    user_id: str = Depends(get_current_user),
    session_dao: SessionDAO = Depends(get_session_dao),
    log_dao: LogEsDAO = Depends(get_log_es_dao),
) -> RagQueryResponse:
    """Answer a question about a session by retrieving and grounding on its logs.

    Embeds the question, retrieves the most relevant fragments from both the
    agent's reasoning and its tool output via `LogEsDAO.hybrid_search`, and
    asks the chat model to answer using only that retrieved context.

    Raises:
        HTTPException: 404 if the session does not exist, 403 if it belongs
            to a different user.
    """
    session = await session_dao.get_by_id(session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    if session.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session belongs to a different user",
        )

    client = ollama.AsyncClient()
    embed_response = await client.embed(model=EMBED_MODEL, input=body.question)
    query_vector = list(embed_response.embeddings[0])

    sources = await log_dao.hybrid_search(session_id, body.question, query_vector, k=8)

    chat_response = await client.chat(
        model=CHAT_MODEL,
        messages=[{"role": "user", "content": _build_prompt(body.question, sources)}],
        options={"num_ctx": 32768},
    )
    answer = _strip_reasoning(chat_response.message.content or "")

    return RagQueryResponse(
        answer=answer,
        sources=[
            RagSource(
                phase=source.get("phase", ""),
                sequence=source.get("sequence", 0),
                tool=source.get("tool"),
                snippet=_snippet(source),
            )
            for source in sources
        ],
    )
