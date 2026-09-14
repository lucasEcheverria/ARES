"""Tests for `rag_indexing_service.index_session_embeddings`.

Elasticsearch (`LogEsDAO`) and Ollama are mocked; MariaDB access goes through
the real in-memory SQLite fixture via `EventDAO`, following the same pattern
as `test_event_dao.py`.
"""

import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from dao.event_dao import EventDAO
from models.event import EventType, Phase
from services import rag_indexing_service

pytestmark = pytest.mark.asyncio


def _event_data(session_id: str, sequence: int, **overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "session_id": session_id,
        "sequence": sequence,
        "phase": Phase.RECON,
        "type": EventType.THOUGHT,
        "tool": None,
        "content": f"thought number {sequence}",
    }
    data.update(overrides)
    return data


def _make_embed_response(vectors: list[list[float]]) -> AsyncMock:
    response = AsyncMock()
    response.embeddings = vectors
    return response


@pytest.fixture
def patched_session_sessions(sessions_db: AsyncSession) -> Iterator[None]:
    @asynccontextmanager
    async def _fake() -> AsyncIterator[AsyncSession]:
        yield sessions_db

    with patch.object(rag_indexing_service, "AsyncSessionSessions", lambda: _fake()):
        yield


async def test_indexes_mariadb_events_into_es(
    sessions_db: AsyncSession, patched_session_sessions: None
) -> None:
    session_id = str(uuid.uuid4())
    await EventDAO(sessions_db).create(_event_data(session_id, 0, content="found port 80 open"))

    mock_log_dao = AsyncMock()
    mock_log_dao.get_all_by_session.return_value = []
    mock_client = AsyncMock()
    mock_client.embed.return_value = _make_embed_response([[0.1, 0.2]])

    with (
        patch.object(rag_indexing_service, "LogEsDAO", return_value=mock_log_dao),
        patch("ollama.AsyncClient", return_value=mock_client),
    ):
        await rag_indexing_service.index_session_embeddings(session_id)

    mock_log_dao.insert_log.assert_awaited_once()
    document = mock_log_dao.insert_log.call_args.args[0]
    assert document["session_id"] == session_id
    assert document["phase"] == "RECON"
    assert document["type"] == "thought"
    assert document["content"] == "found port 80 open"
    assert document["embedding"] == [0.1, 0.2]


async def test_updates_embedding_for_existing_tool_result_documents(
    sessions_db: AsyncSession, patched_session_sessions: None
) -> None:
    session_id = str(uuid.uuid4())
    mock_log_dao = AsyncMock()
    mock_log_dao.get_all_by_session.return_value = [
        {"id": "doc-1", "session_id": session_id, "lines": ["open port 80"]},
    ]
    mock_client = AsyncMock()
    mock_client.embed.return_value = _make_embed_response([[0.3, 0.4]])

    with (
        patch.object(rag_indexing_service, "LogEsDAO", return_value=mock_log_dao),
        patch("ollama.AsyncClient", return_value=mock_client),
    ):
        await rag_indexing_service.index_session_embeddings(session_id)

    mock_log_dao.update_embedding.assert_awaited_once_with("doc-1", [0.3, 0.4])


async def test_failing_document_does_not_stop_the_rest(
    sessions_db: AsyncSession, patched_session_sessions: None
) -> None:
    session_id = str(uuid.uuid4())
    mock_log_dao = AsyncMock()
    mock_log_dao.get_all_by_session.return_value = [
        {"id": "doc-1", "session_id": session_id, "lines": ["result one"]},
        {"id": "doc-2", "session_id": session_id, "lines": ["result two"]},
    ]
    mock_log_dao.update_embedding.side_effect = [Exception("ES write failed"), None]
    mock_client = AsyncMock()
    mock_client.embed.return_value = _make_embed_response([[0.1], [0.2]])

    with (
        patch.object(rag_indexing_service, "LogEsDAO", return_value=mock_log_dao),
        patch("ollama.AsyncClient", return_value=mock_client),
    ):
        await rag_indexing_service.index_session_embeddings(session_id)  # does not raise

    assert mock_log_dao.update_embedding.await_count == 2


async def test_never_raises_when_es_fetch_fails(
    sessions_db: AsyncSession, patched_session_sessions: None
) -> None:
    session_id = str(uuid.uuid4())
    mock_log_dao = AsyncMock()
    mock_log_dao.get_all_by_session.side_effect = Exception("ES unreachable")
    mock_client = AsyncMock()

    with (
        patch.object(rag_indexing_service, "LogEsDAO", return_value=mock_log_dao),
        patch("ollama.AsyncClient", return_value=mock_client),
    ):
        await rag_indexing_service.index_session_embeddings(session_id)  # does not raise

    mock_log_dao.update_embedding.assert_not_awaited()


async def test_never_raises_when_embedding_call_fails(
    sessions_db: AsyncSession, patched_session_sessions: None
) -> None:
    session_id = str(uuid.uuid4())
    mock_log_dao = AsyncMock()
    mock_log_dao.get_all_by_session.return_value = [
        {"id": "doc-1", "session_id": session_id, "lines": ["result one"]},
    ]
    mock_client = AsyncMock()
    mock_client.embed.side_effect = Exception("Ollama unreachable")

    with (
        patch.object(rag_indexing_service, "LogEsDAO", return_value=mock_log_dao),
        patch("ollama.AsyncClient", return_value=mock_client),
    ):
        await rag_indexing_service.index_session_embeddings(session_id)  # does not raise

    mock_log_dao.update_embedding.assert_not_awaited()
