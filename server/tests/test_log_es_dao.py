"""Tests for `LogEsDAO`, including its RAG-related methods."""

from typing import Any
from unittest.mock import AsyncMock

import pytest

from dao.log_es_dao import LogEsDAO

pytestmark = pytest.mark.asyncio


def _hit(doc_id: str, source: dict[str, Any]) -> dict[str, Any]:
    return {"_id": doc_id, "_source": source}


async def test_get_logs_excludes_mirrored_graph_events() -> None:
    client = AsyncMock()
    client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
    dao = LogEsDAO(client)

    await dao.get_logs(session_id="s-1")

    call_kwargs = client.search.call_args.kwargs
    assert call_kwargs["query"]["bool"]["must_not"] == [
        {"terms": {"type": ["thought", "tool_call", "phase_change"]}}
    ]


async def test_get_all_by_session_returns_documents_with_id() -> None:
    client = AsyncMock()
    client.search.return_value = {
        "hits": {
            "hits": [
                _hit("doc-1", {"session_id": "s-1", "lines": ["a"]}),
                _hit("doc-2", {"session_id": "s-1", "lines": ["b"]}),
            ]
        }
    }
    dao = LogEsDAO(client)

    documents = await dao.get_all_by_session("s-1")

    assert [d["id"] for d in documents] == ["doc-1", "doc-2"]
    client.search.assert_awaited_once()
    call_kwargs = client.search.call_args.kwargs
    assert call_kwargs["query"] == {"term": {"session_id": "s-1"}}


async def test_get_all_by_session_paginates_past_page_size() -> None:
    client = AsyncMock()
    first_page = {"hits": {"hits": [_hit(f"doc-{i}", {}) for i in range(500)]}}
    second_page = {"hits": {"hits": [_hit("doc-500", {})]}}
    client.search.side_effect = [first_page, second_page]
    dao = LogEsDAO(client)

    documents = await dao.get_all_by_session("s-1")

    assert len(documents) == 501
    assert client.search.await_count == 2


async def test_update_embedding_calls_partial_update() -> None:
    client = AsyncMock()
    dao = LogEsDAO(client)

    await dao.update_embedding("doc-1", [0.1, 0.2, 0.3])

    client.update.assert_awaited_once_with(
        index="ares-logs", id="doc-1", doc={"embedding": [0.1, 0.2, 0.3]}
    )


def _knn_call(client: AsyncMock) -> Any:
    return next(c for c in client.search.call_args_list if "knn" in c.kwargs)


def _lexical_call(client: AsyncMock) -> Any:
    return next(c for c in client.search.call_args_list if "query" in c.kwargs)


async def test_hybrid_search_scopes_both_legs_to_session() -> None:
    client = AsyncMock()
    client.search.return_value = {"hits": {"hits": []}}
    dao = LogEsDAO(client)

    await dao.hybrid_search("s-1", "what ports were open", [0.1, 0.2], k=8)

    assert client.search.await_count == 2
    knn_kwargs = _knn_call(client).kwargs["knn"]
    bm25_query = _lexical_call(client).kwargs["query"]["bool"]

    assert knn_kwargs["filter"] == {"term": {"session_id": "s-1"}}
    assert knn_kwargs["query_vector"] == [0.1, 0.2]
    assert bm25_query["filter"] == [{"term": {"session_id": "s-1"}}]
    assert bm25_query["must"][0]["multi_match"]["query"] == "what ports were open"


async def test_hybrid_search_does_not_leak_other_sessions() -> None:
    client = AsyncMock()
    client.search.return_value = {
        "hits": {"hits": [_hit("doc-1", {"session_id": "s-1", "content": "match"})]}
    }
    dao = LogEsDAO(client)

    documents = await dao.hybrid_search("s-1", "question", [0.1], k=8)

    assert len(documents) == 1
    assert documents[0]["session_id"] == "s-1"
    knn_filter = _knn_call(client).kwargs["knn"]["filter"]
    bm25_filter = _lexical_call(client).kwargs["query"]["bool"]["filter"]
    assert "s-2" not in str(knn_filter)
    assert "s-2" not in str(bm25_filter)


async def test_hybrid_search_fuses_and_deduplicates_across_legs() -> None:
    client = AsyncMock()
    client.search.side_effect = [
        {  # kNN leg
            "hits": {
                "hits": [
                    _hit("doc-A", {"session_id": "s-1", "content": "a"}),
                    _hit("doc-B", {"session_id": "s-1", "content": "b"}),
                ]
            }
        },
        {  # BM25 leg
            "hits": {
                "hits": [
                    _hit("doc-B", {"session_id": "s-1", "content": "b"}),
                    _hit("doc-C", {"session_id": "s-1", "content": "c"}),
                ]
            }
        },
    ]
    dao = LogEsDAO(client)

    documents = await dao.hybrid_search("s-1", "question", [0.1], k=8)

    ids = [d["id"] for d in documents]
    assert set(ids) == {"doc-A", "doc-B", "doc-C"}
    assert ids[0] == "doc-B"  # ranked in both legs, so it gets the highest fused score


async def test_hybrid_search_truncates_to_k() -> None:
    client = AsyncMock()
    client.search.side_effect = [
        {"hits": {"hits": [_hit(f"doc-{i}", {"session_id": "s-1"}) for i in range(5)]}},
        {"hits": {"hits": []}},
    ]
    dao = LogEsDAO(client)

    documents = await dao.hybrid_search("s-1", "question", [0.1], k=2)

    assert len(documents) == 2
