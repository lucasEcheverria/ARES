"""Background embedding indexing for a session's RAG corpus.

Embeds both sources of a session's execution trail so they become jointly
searchable through `LogEsDAO.hybrid_search`:

- MariaDB graph events (`thought`, `tool_call`, `phase_change`), fetched via
  `EventDAO`, mirrored into the `ares-logs` Elasticsearch index as new
  documents (they don't exist there yet — `ares-logs`'s base mapping already
  carries the `type`/`sequence`/`content` fields needed to hold them).
- Elasticsearch `tool_result` documents, already written by the agent's
  `es_logger`; only their `embedding` field is updated in place.
"""

import logging

import ollama

from dao.event_dao import EventDAO
from dao.log_es_dao import LogEsDAO
from database.connection import AsyncSessionSessions, es_client
from models.event import Event

logger = logging.getLogger(__name__)

EMBED_MODEL = "nomic-embed-text"


async def index_session_embeddings(session_id: str) -> None:
    """Embed and index every event/log of a session for retrieval-augmented queries.

    Never raises: any failure fetching a source, embedding a batch, or
    writing a single document is logged and the rest of the work continues,
    so a missing or unreachable Ollama/Elasticsearch never breaks the
    calling background task.

    Args:
        session_id: The session whose events/logs should be indexed.
    """
    log_dao = LogEsDAO(es_client)
    client = ollama.AsyncClient()

    await _index_tool_results(log_dao, client, session_id)
    await _index_events(log_dao, client, session_id)


async def _index_tool_results(
    log_dao: LogEsDAO, client: ollama.AsyncClient, session_id: str
) -> None:
    """Embed existing ES `tool_result` documents and update their `embedding` field."""
    try:
        documents = await log_dao.get_all_by_session(session_id)
    except Exception:
        logger.exception("Failed to fetch ES documents for session '%s'", session_id)
        return

    texts = ["\n".join(document.get("lines", [])) for document in documents]
    vectors = await _embed_batch(client, texts, session_id)
    if vectors is None:
        return

    for document, vector in zip(documents, vectors, strict=True):
        if vector is None:
            continue
        try:
            await log_dao.update_embedding(document["id"], vector)
        except Exception:
            logger.exception(
                "Failed to update embedding for tool_result document '%s' (session '%s')",
                document.get("id"),
                session_id,
            )


async def _index_events(log_dao: LogEsDAO, client: ollama.AsyncClient, session_id: str) -> None:
    """Embed MariaDB graph events and index them into ES as new documents."""
    try:
        async with AsyncSessionSessions() as db:
            events = await EventDAO(db).get_all_by_session(session_id)
    except Exception:
        logger.exception("Failed to fetch MariaDB events for session '%s'", session_id)
        return

    texts = [event.content for event in events]
    vectors = await _embed_batch(client, texts, session_id)
    if vectors is None:
        return

    for event, vector in zip(events, vectors, strict=True):
        if vector is None:
            continue
        try:
            await log_dao.insert_log(_event_to_document(event, vector))
        except Exception:
            logger.exception(
                "Failed to index event '%s' for session '%s'", event.id, session_id
            )


def _event_to_document(event: Event, vector: list[float]) -> dict[str, object]:
    """Build the ES document for a MariaDB graph event.

    Args:
        event: The source `Event` record.
        vector: Its embedding vector.

    Returns:
        Document ready to pass to `LogEsDAO.insert_log`.
    """
    return {
        "id": event.id,
        "session_id": event.session_id,
        "sequence": event.sequence,
        "phase": event.phase.value,
        "type": event.type.value,
        "tool": event.tool,
        "content": event.content,
        "created_at": event.created_at.isoformat(),
        "embedding": vector,
    }


async def _embed_batch(
    client: ollama.AsyncClient, texts: list[str], session_id: str
) -> list[list[float] | None] | None:
    """Embed a batch of texts in a single Ollama call, skipping blank entries.

    Args:
        client: Ollama async client.
        texts: Texts to embed, one per source item (may include blanks).
        session_id: Session ID, used only for logging context.

    Returns:
        One vector per input text (`None` where the input was blank), in the
        same order as `texts`. `None` (the whole batch, not a single vector)
        if the embedding call itself failed.
    """
    non_blank = [(i, text) for i, text in enumerate(texts) if text.strip()]
    if not non_blank:
        return [None] * len(texts)

    try:
        response = await client.embed(model=EMBED_MODEL, input=[text for _, text in non_blank])
    except Exception:
        logger.exception(
            "Failed to embed batch of %d texts for session '%s'", len(non_blank), session_id
        )
        return None

    vectors: list[list[float] | None] = [None] * len(texts)
    for (i, _), embedding in zip(non_blank, response.embeddings, strict=True):
        vectors[i] = list(embedding)
    return vectors
